# FCC Kiosk MCP

An MCP server for switching what the FCC kiosk is currently showing. Same three
tools, exposed two ways, both authenticating with the kiosk-server's `FCC_API_KEY`:

- **Remote (HTTP)** — built into the kiosk-server itself at
  `https://kiosk-server.fcc.lol/mcp/<FCC_API_KEY>`. Use this for Claude Desktop /
  claude.ai **custom connectors** (see "Remote endpoint" below).
- **Local (stdio)** — the standalone server in this folder (`index.js`). Use this
  for the Claude Code CLI (see "Local stdio" below).

Both expose the same tools and talk to the same underlying config.

## Tools

- **`list_kiosk_apps`** — list the apps/URLs available on a screen (`id`, `title`,
  `enabled`). Params: `screen` (default `"A"`), `includeDisabled` (default `false`).
- **`get_current_kiosk_app`** — what a screen is currently showing (`id` + resolved
  `url`). Params: `screen` (default `"A"`).
- **`switch_kiosk_app`** — switch a screen to a given app `id`. Params: `id`
  (required), `screen` (default `"A"`).

Screens are `A`, `B`, `C`, … (the kiosk auto-creates a screen on first use).

## Remote endpoint (Claude Desktop / claude.ai)

The kiosk-server exposes a Streamable HTTP MCP endpoint (see `../server.js`). Add
it as a custom connector with:

```
https://kiosk-server.fcc.lol/mcp/<FCC_API_KEY>
```

The API key lives in the URL path because the connector dialog has no API-key
field (it only offers OAuth, which is not needed here — leave those blank). The
endpoint also accepts the key via `?fccApiKey=`, an `x-api-key` header, or a
`Bearer` token.

## Configuration (local stdio)

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
