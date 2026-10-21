# volvo-mcp

MCP server (streamable-http) for Volvo EVs (tested target: EX30 2024) using the
Volvo Cars connected-vehicle API with the app-style OAuth login (same approach as
Dielee/volvo2mqtt).

## Tools
volvo_auth_status, volvo_auth_start, volvo_auth_otp, volvo_status, volvo_location,
volvo_lock, volvo_unlock, volvo_climate_start, volvo_climate_stop,
volvo_charge_start, volvo_charge_stop, volvo_statistics

## Config (env)
- VOLVO_USERNAME / VOLVO_PASSWORD — Volvo ID login (or files in VOLVO_SECRET_DIR, default /run/secrets/volvo)
- VOLVO_VCC_API_KEY — free API key from https://developer.volvocars.com/account/
- VOLVO_VIN — optional, else first vehicle on account
- VOLVO_UNIT — 1=km (default), 2/mi=miles
- VOLVO_TOKEN_PATH — writable path for OAuth tokens (default /data/volvo-token.json)
- MCP_HOST / MCP_PORT — default 0.0.0.0:8090, endpoint /mcp

## First login
1. Start server, call volvo_auth_start -> otp_required (code sent to Volvo app/email)
2. Call volvo_auth_otp with the code. Token is persisted and auto-refreshed.
