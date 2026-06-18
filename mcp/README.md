# FCC Kiosk MCP

An MCP server for switching what the FCC kiosk is currently showing. It's a thin
client over the deployed kiosk-server HTTP API (`https://kiosk-server.fcc.lol`),
authenticating with the same `FCC_API_KEY` the server uses for auth.

## Tools

- **`list_kiosk_apps`** — list the apps/URLs available on a screen (`id`, `title`,
  `enabled`). Params: `screen` (default `"A"`), `includeDisabled` (default `false`).
- **`get_current_kiosk_app`** — what a screen is currently showing (`id` + resolved
  `url`). Params: `screen` (default `"A"`).
- **`switch_kiosk_app`** — switch a screen to a given app `id`. Params: `id`
  (required), `screen` (default `"A"`).

Screens are `A`, `B`, `C`, … (the kiosk auto-creates a screen on first use).

## Configuration

Set via environment variables:

- `FCC_API_KEY` (required) — same key as the kiosk-server's `.env`.
- `KIOSK_SERVER_URL` (optional) — defaults to `https://kiosk-server.fcc.lol`.

## Install & register

```sh
cd mcp
npm install

claude mcp add fcc-kiosk -s local \
  -e FCC_API_KEY=<the-key> \
  -e KIOSK_SERVER_URL=https://kiosk-server.fcc.lol \
  -- node "$PWD/index.js"
```

Local scope keeps the API key out of git (it's stored in `~/.claude.json`, not in
the repo). Once registered, ask Claude things like "what's the kiosk showing?" or
"switch the kiosk to the moon dashboard".
