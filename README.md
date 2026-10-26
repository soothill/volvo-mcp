# volvo-mcp

MCP server (streamable-http) for Volvo EVs (tested target: EX30 2024) using the
Volvo Cars connected-vehicle API.

Auth uses the **public PKCE client from the current Volvo Cars Android app**
(`mo2qy9h_10`, extracted from `se.volvo.vcc` 7.4/7.5 `AuthenticationConfig`).
The old shared client `h4Yf0b` (used by volvo2mqtt/evcc/Domoticz for years) was
revoked Volvo-wide on 2026-10-26 — see Dielee/volvo2mqtt#337. Volvo also refuses
`response_mode=pi.flow` for the new client, so login is a browser redirect flow,
not a scriptable username/password + OTP exchange.

## Tools
volvo_auth_status, volvo_auth_start, volvo_auth_finish, volvo_auth_otp (alias),
volvo_status, volvo_location, volvo_lock, volvo_unlock, volvo_climate_start,
volvo_climate_stop, volvo_charge_start, volvo_charge_stop, volvo_statistics

## Config (env)
- VOLVO_VCC_API_KEY — free API key from https://developer.volvocars.com/account/
- VOLVO_CLIENT_ID — OAuth client (default `mo2qy9h_10`, the app's public client)
- VOLVO_REDIRECT_URI — must be registered for the client (default the app's
  `vca://www.volvocars.com/l/vca/oauth/callback`)
- VOLVO_CLIENT_SECRET — optional; only needed for a confidential client (the
  public PKCE flow sends no secret)
- VOLVO_USERNAME / VOLVO_PASSWORD — **no longer used** (browser login)
- VOLVO_VIN — optional, else first vehicle on account
- VOLVO_UNIT — 1=km (default), 2/mi=miles
- VOLVO_TOKEN_PATH — writable path for OAuth tokens (default /data/volvo-token.json)
- MCP_HOST / MCP_PORT — default 0.0.0.0:8090, endpoint /mcp

## First login
1. Call `volvo_auth_start` → returns `auth_url` (PKCE challenge + state).
2. Open `auth_url` in any browser; sign in with your Volvo ID and enter the OTP
   **in the browser**. The browser ends on a `vca://…?code=…` URL that fails to
   open on a desktop — expected.
3. Copy the FULL final address-bar URL and call `volvo_auth_finish` with it.
   The code is exchanged with the stored PKCE verifier; the token is persisted
   and auto-refreshed thereafter.
