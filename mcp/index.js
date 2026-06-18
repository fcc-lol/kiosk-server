#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// Talks to the deployed kiosk-server HTTP API, authenticating with the same
// FCC_API_KEY that the server itself uses for auth.
const BASE_URL = (process.env.KIOSK_SERVER_URL || "https://kiosk-server.fcc.lol").replace(
  /\/$/,
  ""
);
const API_KEY = process.env.FCC_API_KEY;

if (!API_KEY) {
  console.error(
    "fcc-kiosk-mcp: FCC_API_KEY is not set. Set it in the MCP server's env config."
  );
  process.exit(1);
}

async function api(pathname, { method = "GET", query = {}, body } = {}) {
  const url = new URL(BASE_URL + pathname);
  url.searchParams.set("fccApiKey", API_KEY);
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  }

  const res = await fetch(url, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify({ ...body, fccApiKey: API_KEY }) : undefined
  });

  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!res.ok) {
    const message =
      data && typeof data === "object" && data.error ? data.error : `HTTP ${res.status}`;
    throw new Error(message);
  }
  return data;
}

const json = (value) => ({
  content: [{ type: "text", text: JSON.stringify(value, null, 2) }]
});

const server = new McpServer({
  name: "fcc-kiosk",
  version: "1.0.0"
});

server.registerTool(
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
    const urls = await api("/urls", {
      query: { screen, includeDisabled: includeDisabled ? "true" : "false" }
    });
    const apps = (Array.isArray(urls) ? urls : []).map(({ id, title, enabled }) => ({
      id,
      title,
      enabled: enabled !== false
    }));
    return json({ screen, count: apps.length, apps });
  }
);

server.registerTool(
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
    const current = await api("/current-url", { query: { screen } });
    return json({ screen, ...current });
  }
);

server.registerTool(
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
    const result = await api("/change-url", {
      method: "POST",
      body: { id, screen }
    });
    return json(result);
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error(`fcc-kiosk-mcp connected (base: ${BASE_URL})`);
