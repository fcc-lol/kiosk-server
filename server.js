import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import cors from "cors";
import { promises as fs } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

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

const validateUrl = (url) => {
  if (typeof url !== "string" || url.length > MAX_URL_LENGTH) return false;

  try {
    // Replace template variables before validation
    const processedUrl = url
      .replace("{STUDIO_LAT}", process.env.STUDIO_LAT || "")
      .replace("{STUDIO_LNG}", process.env.STUDIO_LNG || "");

    const urlObj = new URL(processedUrl);
    // Allow both http and https protocols
    if (!["http:", "https:"].includes(urlObj.protocol)) {
      return false;
    }

    // Prevent potential SSRF attacks
    const hostname = urlObj.hostname.toLowerCase();
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname.startsWith("192.168.") ||
      hostname.startsWith("10.") ||
      hostname.startsWith("172.16.")
    ) {
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
    const allowedOrigins = ["https://fcc-kiosk-client.leo.gd"];

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
const port = 3111;
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

let currentId = null;
const configPath = path.join(__dirname, "config.json");

async function loadConfig() {
  try {
    const data = await fs.readFile(configPath, "utf8");
    const config = JSON.parse(data);
    if (currentId === null && config.urls.length > 0) {
      currentId = config.urls[0].id;
    }
    return config;
  } catch (error) {
    console.error("Error loading config:", error);
    return { urls: [] };
  }
}

async function getUrlEntryById(id) {
  const config = await loadConfig();
  const entry = config.urls.find((entry) => entry.id === id);
  if (!entry) return null;

  // Replace template variables in the URL
  const processedUrl = entry.url
    .replace("{STUDIO_LAT}", process.env.STUDIO_LAT || "")
    .replace("{STUDIO_LNG}", process.env.STUDIO_LNG || "");

  return {
    ...entry,
    url: processedUrl
  };
}

io.on("connection", (socket) => {
  if (currentId) {
    socket.emit("currentUrlState", currentId);
  }

  socket.on("changeUrl", async (id) => {
    try {
      if (!id) {
        socket.emit("error", "ID cannot be empty");
        return;
      }

      const urlEntry = await getUrlEntryById(id);
      if (!urlEntry) {
        socket.emit("error", "Invalid ID");
        return;
      }

      currentId = id;
      io.emit("currentUrlState", id);
    } catch (error) {
      socket.emit("error", "Failed to process URL change");
    }
  });

  socket.on("requestCurrentUrl", () => {
    socket.emit("currentUrlState", currentId);
  });
});

app.get("/urls", async (req, res) => {
  const apiKey = req.query["fccApiKey"];
  if (!apiKey || apiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  try {
    const config = await loadConfig();
    // Process URLs to replace template variables
    const processedUrls = config.urls.map((entry) => ({
      ...entry,
      url: entry.url
        .replace("{STUDIO_LAT}", process.env.STUDIO_LAT || "")
        .replace("{STUDIO_LNG}", process.env.STUDIO_LNG || "")
    }));
    res.json(processedUrls);
  } catch (error) {
    console.error("Error fetching URLs:", error);
    res.status(500).json({ error: "Failed to fetch URLs" });
  }
});

app.get("/current-url", async (req, res) => {
  const { fccApiKey } = req.query;

  if (!fccApiKey || fccApiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  if (!currentId) {
    return res.json({ id: null, url: null });
  }

  try {
    const urlEntry = await getUrlEntryById(currentId);
    res.json({ id: currentId, url: urlEntry.url });
  } catch (error) {
    res.status(500).json({ error: "Failed to get current URL" });
  }
});

app.post("/change-url", async (req, res) => {
  const { id, fccApiKey } = req.body;

  if (!fccApiKey || fccApiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  if (!id) {
    return res.status(400).json({ error: "ID is required" });
  }

  try {
    const urlEntry = await getUrlEntryById(id);
    if (!urlEntry) {
      return res.status(400).json({ error: "Invalid ID" });
    }

    currentId = id;
    io.emit("currentUrlState", id);
    res.json({ success: true, message: "URL changed successfully", id });
  } catch (error) {
    console.error("Error changing URL:", error);
    res.status(500).json({ error: "Failed to change URL" });
  }
});

app.post("/add-url", async (req, res) => {
  const { id, title, url, fccApiKey } = req.body;

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

    // Check if ID already exists
    if (config.urls.some((entry) => entry.id === id)) {
      return res.status(400).json({ error: "ID already exists" });
    }

    // Add new URL entry with sanitized data
    config.urls.push({
      id: sanitizeInput(id),
      title: sanitizeInput(title),
      url: sanitizeInput(url)
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
  const { id, fccApiKey } = req.body;

  if (!fccApiKey || fccApiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  if (!id) {
    return res.status(400).json({ error: "ID is required" });
  }

  try {
    const config = await loadConfig();

    // Check if URL exists
    const urlIndex = config.urls.findIndex((entry) => entry.id === id);
    if (urlIndex === -1) {
      return res.status(404).json({ error: "URL not found" });
    }

    // Remove URL entry
    config.urls.splice(urlIndex, 1);

    // Save updated config
    await fs.writeFile(configPath, JSON.stringify(config, null, 2));

    // If the removed URL was the current one, set currentId to the first available URL or null
    if (currentId === id) {
      currentId = config.urls.length > 0 ? config.urls[0].id : null;
      io.emit("currentUrlState", currentId);
    }

    res.json({ success: true, message: "URL removed successfully" });
  } catch (error) {
    console.error("Error removing URL:", error);
    res.status(500).json({ error: "Failed to remove URL" });
  }
});

app.put("/edit-url", async (req, res) => {
  const { id, newId, title, url, fccApiKey } = req.body;

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

    // Find the URL entry to edit
    const urlIndex = config.urls.findIndex((entry) => entry.id === id);
    if (urlIndex === -1) {
      return res.status(404).json({ error: "URL not found" });
    }

    // Check if newId already exists (if it's different from current id)
    if (
      newId &&
      newId !== id &&
      config.urls.some((entry) => entry.id === newId)
    ) {
      return res
        .status(400)
        .json({ error: `ID '${newId}' is already in use by another URL` });
    }

    // Update the URL entry with sanitized values
    const currentEntry = config.urls[urlIndex];
    config.urls[urlIndex] = {
      id: newId !== undefined ? sanitizeInput(newId) : currentEntry.id,
      title: title !== undefined ? sanitizeInput(title) : currentEntry.title,
      url: url !== undefined ? sanitizeInput(url) : currentEntry.url
    };

    // If the ID was changed and this was the current URL, update currentId
    if (newId && newId !== id && currentId === id) {
      currentId = newId;
      io.emit("currentUrlState", currentId);
    }

    // Save updated config
    await fs.writeFile(configPath, JSON.stringify(config, null, 2));

    res.json({ success: true, message: "URL updated successfully" });
  } catch (error) {
    console.error("Error updating URL:", error);
    res.status(500).json({ error: "Failed to update URL" });
  }
});

app.put("/update-order", async (req, res) => {
  const { orderedIds, fccApiKey } = req.body;

  if (!fccApiKey || fccApiKey !== process.env.FCC_API_KEY) {
    return res.status(401).json({ error: "Unauthorized - Invalid API key" });
  }

  if (!Array.isArray(orderedIds)) {
    return res.status(400).json({ error: "orderedIds must be an array" });
  }

  try {
    const config = await loadConfig();

    // Validate that all IDs exist and are unique
    const uniqueIds = new Set(orderedIds);
    if (uniqueIds.size !== orderedIds.length) {
      return res.status(400).json({ error: "IDs must be unique" });
    }

    const existingIds = new Set(config.urls.map((url) => url.id));
    const missingIds = orderedIds.filter((id) => !existingIds.has(id));
    if (missingIds.length > 0) {
      return res.status(400).json({
        error: `The following IDs do not exist: ${missingIds.join(", ")}`
      });
    }

    // Create a map of URLs by ID for quick lookup
    const urlMap = new Map(config.urls.map((url) => [url.id, url]));

    // Reorder the URLs based on the provided order
    const reorderedUrls = orderedIds.map((id) => urlMap.get(id));

    // Update the config with the new order
    config.urls = reorderedUrls;

    // Save the updated config
    await fs.writeFile(configPath, JSON.stringify(config, null, 2));

    res.json({ success: true, message: "URL order updated successfully" });
  } catch (error) {
    console.error("Error updating URL order:", error);
    res.status(500).json({ error: "Failed to update URL order" });
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", connections: io.engine.clientsCount });
});

httpServer.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
