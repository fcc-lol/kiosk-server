import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import cors from "cors";
import { promises as fs } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { randomUUID } from "crypto";
import { z } from "zod";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Security constants
const MAX_ID_LENGTH = 50;
const MAX_TITLE_LENGTH = 100;
const MAX_URL_LENGTH = 2000;
const MAX_REQUEST_BODY_SIZE = "1mb";
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_REQUESTS = 100; // Max requests per window

// Rate limiting storage
const rateLimit = {};

const checkRateLimit = (ip) => {
  const now = Date.now();
  if (!rateLimit[ip]) {
    rateLimit[ip] = { count: 1, timestamp: now };
    return true;
  }

  if (now - rateLimit[ip].timestamp > RATE_LIMIT_WINDOW) {
    rateLimit[ip] = { count: 1, timestamp: now };
    return true;
  }

  if (rateLimit[ip].count >= MAX_REQUESTS) {
    return false;
  }

  rateLimit[ip].count++;
  return true;
};

// Input validation functions
const validateId = (id) => {
  if (typeof id !== "string") return false;
  // Only allow alphanumeric characters, hyphens, and underscores
  // Prevent directory traversal attempts
  return (
    /^[a-zA-Z0-9-_]+$/.test(id) &&
    id.length <= MAX_ID_LENGTH &&
    !id.includes("..") &&
    !id.includes("/") &&
    !id.includes("\\")
  );
};

const validateTitle = (title) => {
  if (typeof title !== "string") return false;
  // Allow letters, numbers, spaces, common punctuation, and emojis
  // Prevent XSS attempts
  return (
    title.length <= MAX_TITLE_LENGTH &&
    !title.includes("<script") &&
    !title.includes("javascript:") &&
    !title.includes("onerror=") &&
    !title.includes("onload=")
  );
};

const processUrlTemplates = (url) => {
  if (typeof url !== "string") return url;

  // Find all environment variable templates in the URL
  const envVarRegex = /\{([A-Z0-9_]+)\}/g;
  let processedUrl = url;
  let match;

  while ((match = envVarRegex.exec(url)) !== null) {
    const envVarName = match[1];
    const envVarValue = process.env[envVarName] || "";
    processedUrl = processedUrl.replace(`{${envVarName}}`, envVarValue);
  }

  return processedUrl;
};

const validateUrl = (url) => {
  if (typeof url !== "string" || url.length > MAX_URL_LENGTH) return false;

  try {
    // Process any environment variable templates before validation
    const processedUrl = processUrlTemplates(url);
    const urlObj = new URL(processedUrl);
    // Allow both http and https protocols
    if (!["http:", "https:"].includes(urlObj.protocol)) {
      return false;
    }

    // Prevent potential XSS through URL
    if (
      urlObj.search.includes("<script") ||
      urlObj.search.includes("javascript:") ||
      urlObj.hash.includes("<script") ||
      urlObj.hash.includes("javascript:")
    ) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
};

const sanitizeInput = (input) => {
  if (typeof input !== "string") return input;

  // Remove any potential script tags and HTML
  let sanitized = input.replace(/<[^>]*>/g, "");

  // Remove potential XSS vectors
  sanitized = sanitized
    .replace(/javascript:/gi, "")
    .replace(/onerror=/gi, "")
    .replace(/onload=/gi, "")
    .replace(/eval\(/gi, "")
    .replace(/document\.cookie/gi, "")
    .replace(/document\.location/gi, "");

  // Prevent directory traversal
  sanitized = sanitized.replace(/\.\./g, "").replace(/\\/g, "");

  return sanitized;
};

const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = ["https://kiosk.fcc.lol"];

    // Only allow localhost in development
    if (process.env.NODE_ENV !== "production") {
      allowedOrigins.push("http://localhost:3000");
    }

    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "DELETE", "PUT"],
  credentials: true
};

const app = express();
const port = 3105;
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: corsOptions
});

// Security middleware
app.use(express.json({ limit: MAX_REQUEST_BODY_SIZE }));
app.use((req, res, next) => {
  // Rate limiting
  const ip = req.ip;
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: "Too many requests" });
  }

  // Security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains"
  );
  next();
});

app.use(cors(corsOptions));

// Store current URL for each screen
const currentScreens = {};
const configPath = path.join(__dirname, "config.json");

async function loadConfig() {
  try {
    const data = await fs.readFile(configPath, "utf8");
    const config = JSON.parse(data);

    // Handle migration from old format to new format
    if (config.urls && !config.screens) {
      // Old format - migrate to new format
      config.screens = {
        A: {
          urls: config.urls,
          currentId: null
        }
      };
      delete config.urls;
      await fs.writeFile(configPath, JSON.stringify(config, null, 2));
    }

    // Ensure screens object exists
    if (!config.screens) {
      config.screens = {
        A: { urls: [], currentId: null }
      };
    }

    // Initialize currentScreens if not already initialized
    Object.keys(config.screens).forEach((screen) => {
      if (currentScreens[screen] === undefined) {
        const screenConfig = config.screens[screen];
        if (screenConfig.urls && screenConfig.urls.length > 0) {
          const firstEnabledUrl = screenConfig.urls.find(
            (entry) => entry.enabled !== false
          );
          currentScreens[screen] = firstEnabledUrl ? firstEnabledUrl.id : null;
        } else {
          currentScreens[screen] = null;
        }
      }
    });

    return config;
  } catch (error) {
    console.error("Error loading config:", error);
    return { screens: { A: { urls: [], currentId: null } } };
  }
}

async function getUrlEntryById(id, screen = "A") {
  const config = await loadConfig();
  if (!config.screens || !config.screens[screen]) return null;

  const entry = config.screens[screen].urls.find((entry) => entry.id === id);
  if (!entry) return null;

  // Process any environment variable templates in the URL
  return {
    ...entry,
    url: processUrlTemplates(entry.url)
  };
}

io.on("connection", (socket) => {
  // Send current state for all screens
  socket.emit("currentUrlStates", currentScreens);

  socket.on("changeUrl", async ({ id, screen = "A" }) => {
    try {
      if (!id) {
        socket.emit("error", "ID cannot be empty");
        return;
      }

      const urlEntry = await getUrlEntryById(id, screen);
      if (!urlEntry) {
        socket.emit("error", "Invalid ID");
        return;
      }

      // Check if the URL is enabled
      if (urlEntry.enabled === false) {
        socket.emit("error", "Cannot change to a disabled URL");
        return;
      }

      currentScreens[screen] = id;
      io.emit("currentUrlState", { screen, id });
    } catch (error) {
      socket.emit("error", "Failed to process URL change");
    }
  });

  socket.on("requestCurrentUrl", ({ screen = "A" } = {}) => {
    socket.emit("currentUrlState", { screen, id: currentScreens[screen] });
  });
});

app.get("/urls", async (req, res) => {
  const apiKey = req.query["fccApiKey"];
  if (!apiKey || apiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  try {
    const config = await loadConfig();
    const processTemplates = req.query.processTemplates !== "false";
    const includeDisabled = req.query.includeDisabled === "true";
    const screen = req.query.screen || "A";

    // Auto-create screen if it doesn't exist
    if (!config.screens[screen]) {
      config.screens[screen] = { urls: [] };
      await fs.writeFile(configPath, JSON.stringify(config, null, 2));
      // Initialize current screen state
      if (currentScreens[screen] === undefined) {
        currentScreens[screen] = null;
      }
    }

    // Filter URLs based on includeDisabled parameter
    // If includeDisabled is true, return all URLs; otherwise only return enabled URLs
    const filteredUrls = includeDisabled
      ? config.screens[screen].urls
      : config.screens[screen].urls.filter((entry) => entry.enabled !== false);

    // Process URLs to replace template variables if processTemplates is not false
    const processedUrls = filteredUrls.map((entry) => ({
      ...entry,
      url: processTemplates ? processUrlTemplates(entry.url) : entry.url
    }));
    res.json(processedUrls);
  } catch (error) {
    console.error("Error fetching URLs:", error);
    res.status(500).json({ error: "Failed to fetch URLs" });
  }
});

app.get("/current-url", async (req, res) => {
  const { fccApiKey, screen = "A" } = req.query;

  if (!fccApiKey || fccApiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  try {
    const config = await loadConfig();

    // Auto-create screen if it doesn't exist
    if (!config.screens[screen]) {
      config.screens[screen] = { urls: [] };
      await fs.writeFile(configPath, JSON.stringify(config, null, 2));
      // Initialize current screen state
      if (currentScreens[screen] === undefined) {
        currentScreens[screen] = null;
      }
    }

    const currentId = currentScreens[screen];
    if (!currentId) {
      return res.json({ id: null, url: null });
    }

    const urlEntry = await getUrlEntryById(currentId, screen);
    if (!urlEntry) {
      return res.status(404).json({ error: "Current URL not found" });
    }
    res.json({ id: currentId, url: urlEntry.url });
  } catch (error) {
    console.error("Error getting current URL:", error);
    res.status(500).json({ error: "Failed to get current URL" });
  }
});

app.post("/change-url", async (req, res) => {
  const { id, fccApiKey, screen = "A" } = req.body;

  if (!fccApiKey || fccApiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  if (!id) {
    return res.status(400).json({ error: "ID is required" });
  }

  try {
    const config = await loadConfig();

    // Auto-create screen if it doesn't exist
    if (!config.screens[screen]) {
      config.screens[screen] = { urls: [] };
      await fs.writeFile(configPath, JSON.stringify(config, null, 2));
      // Initialize current screen state
      if (currentScreens[screen] === undefined) {
        currentScreens[screen] = null;
      }
    }

    const urlEntry = await getUrlEntryById(id, screen);
    if (!urlEntry) {
      return res.status(400).json({ error: "Invalid ID" });
    }

    // Check if the URL is enabled
    if (urlEntry.enabled === false) {
      return res.status(400).json({ error: "Cannot change to a disabled URL" });
    }

    currentScreens[screen] = id;
    io.emit("currentUrlState", { screen, id });
    res.json({
      success: true,
      message: "URL changed successfully",
      id,
      screen
    });
  } catch (error) {
    console.error("Error changing URL:", error);
    res.status(500).json({ error: "Failed to change URL" });
  }
});

app.post("/add-url", async (req, res) => {
  const { id, title, url, enabled, fccApiKey, screen = "A" } = req.body;

  if (!fccApiKey || fccApiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  // Validate required fields
  if (!id || !title || !url) {
    return res.status(400).json({ error: "ID, title, and URL are required" });
  }

  // Validate and sanitize inputs
  if (!validateId(id)) {
    return res.status(400).json({ error: "Invalid ID format" });
  }
  if (!validateTitle(title)) {
    return res.status(400).json({ error: "Invalid title format" });
  }
  if (!validateUrl(url)) {
    return res.status(400).json({ error: "Invalid URL format" });
  }

  try {
    const config = await loadConfig();

    if (!config.screens[screen]) {
      config.screens[screen] = { urls: [], currentId: null };
    }

    // Check if ID already exists
    if (config.screens[screen].urls.some((entry) => entry.id === id)) {
      return res.status(400).json({ error: "ID already exists" });
    }

    // Add new URL entry with sanitized data
    config.screens[screen].urls.push({
      id: sanitizeInput(id),
      title: sanitizeInput(title),
      url: sanitizeInput(url),
      enabled: enabled !== undefined ? Boolean(enabled) : true
    });

    // Save updated config
    await fs.writeFile(configPath, JSON.stringify(config, null, 2));

    res.json({ success: true, message: "URL added successfully" });
  } catch (error) {
    console.error("Error adding URL:", error);
    res.status(500).json({ error: "Failed to add URL" });
  }
});

app.delete("/remove-url", async (req, res) => {
  const { id, fccApiKey, screen = "A" } = req.body;

  if (!fccApiKey || fccApiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  if (!id) {
    return res.status(400).json({ error: "ID is required" });
  }

  try {
    const config = await loadConfig();

    if (!config.screens[screen]) {
      return res.status(404).json({ error: "Screen not found" });
    }

    // Check if URL exists
    const urlIndex = config.screens[screen].urls.findIndex(
      (entry) => entry.id === id
    );
    if (urlIndex === -1) {
      return res.status(404).json({ error: "URL not found" });
    }

    // Remove URL entry
    config.screens[screen].urls.splice(urlIndex, 1);

    // Save updated config
    await fs.writeFile(configPath, JSON.stringify(config, null, 2));

    // If the removed URL was the current one, set currentScreens[screen] to the first enabled URL or null
    if (currentScreens[screen] === id) {
      const firstEnabledUrl = config.screens[screen].urls.find(
        (entry) => entry.enabled !== false
      );
      currentScreens[screen] = firstEnabledUrl ? firstEnabledUrl.id : null;
      io.emit("currentUrlState", { screen, id: currentScreens[screen] });
    }

    res.json({ success: true, message: "URL removed successfully" });
  } catch (error) {
    console.error("Error removing URL:", error);
    res.status(500).json({ error: "Failed to remove URL" });
  }
});

app.put("/edit-url", async (req, res) => {
  const { id, newId, title, url, enabled, fccApiKey, screen = "A" } = req.body;

  if (!fccApiKey || fccApiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  if (!id) {
    return res.status(400).json({ error: "ID is required" });
  }

  // Validate inputs if provided
  if (newId && !validateId(newId)) {
    return res.status(400).json({ error: "Invalid new ID format" });
  }
  if (title && !validateTitle(title)) {
    return res.status(400).json({ error: "Invalid title format" });
  }
  if (url && !validateUrl(url)) {
    return res.status(400).json({ error: "Invalid URL format" });
  }

  try {
    const config = await loadConfig();

    if (!config.screens[screen]) {
      return res.status(404).json({ error: "Screen not found" });
    }

    // Find the URL entry to edit
    const urlIndex = config.screens[screen].urls.findIndex(
      (entry) => entry.id === id
    );
    if (urlIndex === -1) {
      return res.status(404).json({ error: "URL not found" });
    }

    // Check if newId already exists (if it's different from current id)
    if (
      newId &&
      newId !== id &&
      config.screens[screen].urls.some((entry) => entry.id === newId)
    ) {
      return res
        .status(400)
        .json({ error: `ID '${newId}' is already in use by another URL` });
    }

    // Update the URL entry with sanitized values
    const currentEntry = config.screens[screen].urls[urlIndex];
    config.screens[screen].urls[urlIndex] = {
      id: newId !== undefined ? sanitizeInput(newId) : currentEntry.id,
      title: title !== undefined ? sanitizeInput(title) : currentEntry.title,
      url: url !== undefined ? sanitizeInput(url) : currentEntry.url,
      enabled:
        enabled !== undefined
          ? Boolean(enabled)
          : currentEntry.enabled !== undefined
          ? currentEntry.enabled
          : true
    };

    // If the ID was changed and this was the current URL, update currentScreens[screen]
    if (newId && newId !== id && currentScreens[screen] === id) {
      currentScreens[screen] = newId;
      io.emit("currentUrlState", { screen, id: currentScreens[screen] });
    }

    // Save updated config
    await fs.writeFile(configPath, JSON.stringify(config, null, 2));

    res.json({ success: true, message: "URL updated successfully" });
  } catch (error) {
    console.error("Error updating URL:", error);
    res.status(500).json({ error: "Failed to update URL" });
  }
});

app.put("/toggle-url-enabled", async (req, res) => {
  const { id, enabled, fccApiKey, screen = "A" } = req.body;

  if (!fccApiKey || fccApiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  if (!id) {
    return res.status(400).json({ error: "ID is required" });
  }

  if (enabled === undefined) {
    return res.status(400).json({ error: "enabled field is required" });
  }

  try {
    const config = await loadConfig();

    if (!config.screens[screen]) {
      return res.status(404).json({ error: "Screen not found" });
    }

    // Find the URL entry
    const urlIndex = config.screens[screen].urls.findIndex(
      (entry) => entry.id === id
    );
    if (urlIndex === -1) {
      return res.status(404).json({ error: "URL not found" });
    }

    // Update the enabled field
    config.screens[screen].urls[urlIndex].enabled = Boolean(enabled);

    // Save updated config
    await fs.writeFile(configPath, JSON.stringify(config, null, 2));

    // If the current URL was disabled, switch to the first enabled URL
    if (
      currentScreens[screen] === id &&
      !config.screens[screen].urls[urlIndex].enabled
    ) {
      const firstEnabledUrl = config.screens[screen].urls.find(
        (entry) => entry.enabled !== false
      );
      currentScreens[screen] = firstEnabledUrl ? firstEnabledUrl.id : null;
      io.emit("currentUrlState", { screen, id: currentScreens[screen] });
    }

    // Return the updated URL data
    res.json({
      success: true,
      message: "URL enabled status updated successfully",
      url: config.screens[screen].urls[urlIndex]
    });
  } catch (error) {
    console.error("Error toggling URL enabled status:", error);
    res.status(500).json({ error: "Failed to update URL enabled status" });
  }
});

app.put("/update-order", async (req, res) => {
  const { orderedIds, fccApiKey, screen = "A" } = req.body;

  if (!fccApiKey || fccApiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  if (!Array.isArray(orderedIds)) {
    return res.status(400).json({ error: "orderedIds must be an array" });
  }

  try {
    const config = await loadConfig();

    if (!config.screens[screen]) {
      return res.status(404).json({ error: "Screen not found" });
    }

    // Validate that all IDs exist and are unique
    const uniqueIds = new Set(orderedIds);
    if (uniqueIds.size !== orderedIds.length) {
      return res.status(400).json({ error: "IDs must be unique" });
    }

    const existingIds = new Set(
      config.screens[screen].urls.map((url) => url.id)
    );
    const missingIds = orderedIds.filter((id) => !existingIds.has(id));
    if (missingIds.length > 0) {
      return res.status(400).json({
        error: `The following IDs do not exist: ${missingIds.join(", ")}`
      });
    }

    // Create a map of URLs by ID for quick lookup
    const urlMap = new Map(
      config.screens[screen].urls.map((url) => [url.id, url])
    );

    // Reorder the URLs based on the provided order
    const reorderedUrls = orderedIds.map((id) => urlMap.get(id));

    // Update the config with the new order
    config.screens[screen].urls = reorderedUrls;

    // Save the updated config
    await fs.writeFile(configPath, JSON.stringify(config, null, 2));

    res.json({ success: true, message: "URL order updated successfully" });
  } catch (error) {
    console.error("Error updating URL order:", error);
    res.status(500).json({ error: "Failed to update URL order" });
  }
});

// ---------------------------------------------------------------------------
// MCP endpoint (Streamable HTTP) for switching what the kiosk shows from
// MCP clients like Claude Desktop. Auth reuses FCC_API_KEY. Because the
// custom-connector UI has no API-key field, the key is accepted in the URL
// path (/mcp/:key) as well as via query/header for other clients.
// ---------------------------------------------------------------------------
const mcpText = (value) => ({
  content: [{ type: "text", text: JSON.stringify(value, null, 2) }]
});

function buildKioskMcpServer() {
  const mcp = new McpServer({ name: "fcc-kiosk", version: "1.0.0" });

  mcp.registerTool(
    "list_kiosk_apps",
    {
      title: "List kiosk apps",
      description:
        "List the apps/URLs available to show on a kiosk screen. Returns each entry's id, title, and enabled state. Use the id with switch_kiosk_app. Screens default to 'A'.",
      inputSchema: {
        screen: z
          .string()
          .optional()
          .describe("Screen to list (e.g. 'A', 'B', 'C'). Defaults to 'A'."),
        includeDisabled: z
          .boolean()
          .optional()
          .describe("Include disabled apps in the list. Defaults to false.")
      }
    },
    async ({ screen = "A", includeDisabled = false }) => {
      const config = await loadConfig();
      const urls = config.screens[screen] ? config.screens[screen].urls : [];
      const filtered = includeDisabled
        ? urls
        : urls.filter((entry) => entry.enabled !== false);
      const apps = filtered.map(({ id, title, enabled }) => ({
        id,
        title,
        enabled: enabled !== false
      }));
      return mcpText({ screen, count: apps.length, apps });
    }
  );

  mcp.registerTool(
    "get_current_kiosk_app",
    {
      title: "Get current kiosk app",
      description:
        "Get what a kiosk screen is currently showing (its id and resolved URL). Screens default to 'A'.",
      inputSchema: {
        screen: z
          .string()
          .optional()
          .describe("Screen to check (e.g. 'A', 'B', 'C'). Defaults to 'A'.")
      }
    },
    async ({ screen = "A" }) => {
      await loadConfig(); // initializes currentScreens after a fresh restart
      const currentId = currentScreens[screen] ?? null;
      let url = null;
      if (currentId) {
        const entry = await getUrlEntryById(currentId, screen);
        url = entry ? entry.url : null;
      }
      return mcpText({ screen, id: currentId, url });
    }
  );

  mcp.registerTool(
    "switch_kiosk_app",
    {
      title: "Switch kiosk app",
      description:
        "Switch what a kiosk screen is currently showing. Pass the id of an enabled app (see list_kiosk_apps). Screens default to 'A'.",
      inputSchema: {
        id: z.string().describe("The id of the app/URL to switch to."),
        screen: z
          .string()
          .optional()
          .describe("Screen to switch (e.g. 'A', 'B', 'C'). Defaults to 'A'.")
      }
    },
    async ({ id, screen = "A" }) => {
      const entry = await getUrlEntryById(id, screen);
      if (!entry) throw new Error("Invalid ID");
      if (entry.enabled === false) {
        throw new Error("Cannot change to a disabled URL");
      }
      currentScreens[screen] = id;
      io.emit("currentUrlState", { screen, id });
      return mcpText({ success: true, id, screen });
    }
  );

  return mcp;
}

const mcpAuth = (req, res, next) => {
  const bearer = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const key =
    req.params.key || req.query.fccApiKey || req.headers["x-api-key"] || bearer;
  if (!key || key !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }
  next();
};

// Active Streamable HTTP sessions, keyed by mcp-session-id.
const mcpTransports = {};

app.post(["/mcp", "/mcp/:key"], mcpAuth, async (req, res) => {
  try {
    const sessionId = req.headers["mcp-session-id"];
    let transport;

    if (sessionId && mcpTransports[sessionId]) {
      transport = mcpTransports[sessionId];
    } else if (!sessionId && isInitializeRequest(req.body)) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          mcpTransports[id] = transport;
        }
      });
      transport.onclose = () => {
        if (transport.sessionId) delete mcpTransports[transport.sessionId];
      };
      const mcp = buildKioskMcpServer();
      await mcp.connect(transport);
    } else {
      return res.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: No valid session ID" },
        id: null
      });
    }

    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("MCP request error:", error);
    if (!res.headersSent) {
      res.status(500).json({ error: "MCP request failed" });
    }
  }
});

// GET (server-sent stream) and DELETE (session teardown) reuse the session.
const handleMcpSession = async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  if (!sessionId || !mcpTransports[sessionId]) {
    return res.status(400).json({ error: "Invalid or missing session ID" });
  }
  await mcpTransports[sessionId].handleRequest(req, res);
};

app.get(["/mcp", "/mcp/:key"], mcpAuth, handleMcpSession);
app.delete(["/mcp", "/mcp/:key"], mcpAuth, handleMcpSession);

app.get("/health", (req, res) => {
  res.json({ status: "ok", connections: io.engine.clientsCount });
});

httpServer.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
