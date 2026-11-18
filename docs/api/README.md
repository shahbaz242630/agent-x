# Agent X API: a guide for agent builders

An AI agent uses the Agent X API to ask whether it may pay a supplier for an order. Agent X checks the request against the agent's mandate and the organisation's spending rules, and answers with a decision. An allowed request becomes a policy-approved payment intent; the licensed partner validates consent and authentication, then initiates and executes the payment.

The single source of truth is the OpenAPI document, [`apps/api/openapi.json`](../../apps/api/openapi.json). It lists every operation, what each one takes and answers, who may call it, and every reason code. This guide explains how to use it; where the two differ, the document wins.

## 1. Get an agent key

1. In the console, an admin or developer opens **Agents** and chooses **Register an agent**, ticking the scopes the agent needs.
2. After they confirm by signing in again (an admin with their passkey), the console shows the agent's key **once**. Copy it straight into the place your agent reads its secrets from. Agent X keeps only a keyed hash of it, so it can't show it again.
3. A key expires 90 days after it is made. Rotate it before then from the agent's page in the console; a lost or leaked key is rotated or revoked there too. A new key is again shown once.

A key looks like `axk_<keyId>_<secret>`. Send it on every request:

```http
Authorization: Bearer axk_<keyId>_<secret>
```

An agent never sends a cookie or the `AgentX-Organization` header: its key's organisation is the one it acts in.

## 2. Scopes

Each operation an agent may call names the scopes its key must hold, in its `security` (scheme `agentKey`) and in `x-agent-scopes`. A key without all of them gets 403 `INSUFFICIENT_SCOPE`.

| Scope            | Lets the agent                                             | Operations                                                                                      |
| ---------------- | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `requests:write` | read its mandate, create spend requests and cancel its own | `GET /v1/agent/mandate`, `POST /v1/spend-requests`, `POST /v1/agent/spend-requests/{id}/cancel` |
| `requests:read`  | read its own spend requests and their decisions            | `GET /v1/agent/spend-requests/{id}`                                                             |
| `sources:read`   | read the bank accounts its mandate lets it pay from        | `GET /v1/agent/funding-sources`                                                                 |
| `suppliers:read` | read the verified suppliers its organisation may pay       | `GET /v1/agent/suppliers`                                                                       |

`GET /v1/agent`, which says which agent the key is, needs no scope.

## 3. The agent flow

1. **Find out what you may use.** `GET /v1/agent` says which agent the key is. `GET /v1/agent/mandate` gives the mandate you act under, `GET /v1/agent/funding-sources` the bank accounts you may name, and `GET /v1/agent/suppliers` the suppliers you may pay.
2. **Ask.** `POST /v1/spend-requests` with the amount in minor units, the currency, the supplier, the bank account, your order reference and the purpose. Send a new `Idempotency-Key` header with it (see 4). The answer is the spend request, with its `status`, its `decision` and the `reasons` for it.
3. **Follow it.** `GET /v1/agent/spend-requests/{id}` reads it as it stands now. A request that needs a person's approval stays waiting until they decide; read it again later rather than in a tight loop.
4. **Change your mind.** `POST /v1/agent/spend-requests/{id}/cancel` cancels your own request before it is handed off to the bank.

The exact fields, statuses and decisions are in the document's `SpendRequest` schema.

## 4. Retries and idempotency

Every write that changes something takes an `Idempotency-Key` header: 1 to 255 visible ASCII characters (a UUID is a good choice), new for each change you mean to make.

- If a request times out or the connection drops, send **the same request with the same key**. Nothing is done twice: you get the first request's status, with the resource as it now stands (a spend request may have moved on since).
- The same key with a different request is refused with 409 `IDEMPOTENCY_KEY_REUSED`, and nothing is changed.
- While the first request is still being worked on, the same key gets 409 `IDEMPOTENCY_KEY_BUSY` with a `Retry-After` header.
- Keys are kept for at least 30 days. Don't reuse a key, even after that: use a new one for each new change.

## 5. Errors

Every refusal and failure has the same body:

```json
{ "error": { "code": "…", "message": "…", "correlationId": "…" } }
```

Act on `code`. The `message` is the code's plain-words description for people and may be reworded. The list of codes and what each means is the `code` schema in the document; a code you don't know yet is handled by its HTTP status (4xx: fix the request or ask the organisation; 5xx: try again later).

## 6. Rate limits

Requests are counted per minute: per client address, per agent and per organisation. Over a limit, the answer is 429 `RATE_LIMITED` with:

- `Retry-After`: seconds to wait before trying again;
- `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`: the limit, what is left of it, and seconds until it resets.

Wait the `Retry-After` seconds, then send the same request again with the same `Idempotency-Key`. A 503 saying the organisation or the platform is busy carries `Retry-After` too.

## 7. Correlation IDs

Every answer carries an `X-Correlation-Id` header, and every error body a `correlationId`. You may send your own UUID in `X-Correlation-Id` to have it used. Log it beside your own records, and quote it when you contact support: it finds your request in our logs.

## 8. Versioning

Every address an agent calls starts with `/v1`, the API's major version. Within v1, changes are only additive: new operations, new optional request fields, new answer fields and new reason codes. Ignore answer fields you don't know. A breaking change comes only under `/v2`, announced with notice.

## 9. MCP

An agent built on an MCP client can call Agent X as a remote MCP server at `POST /v1/mcp`, instead of the REST operations above. It is the same API over another wire: the same key, the same scopes, the same checks and the same answers.

- **Address:** `https://<your-agent-x-host>/v1/mcp`. Streamable HTTP only: set your client's transport to `streamable-http` (some clients default to SSE, which Agent X doesn't serve). GET, HEAD and DELETE answer 405.
- **Sign-in:** your agent key, as in 1, as `Authorization: Bearer axk_…`. Never in the address. No cookie and no `AgentX-Organization` header. Without a key the answer is 401, with `WWW-Authenticate: Bearer realm="Agent X", error="invalid_token"`.
- **Protocol versions:** `2026-07-28` (each request carries its version in `_meta`; start with `server/discover`) and `2025-11-25`, `2025-06-18` and `2025-03-26` (start with `initialize`). A request naming no version is taken as `2025-03-26`. No session is kept and no `Mcp-Session-Id` is given: any call may go to any server. A version Agent X doesn't speak is refused with JSON-RPC error `-32022`, naming those it does. Batches are refused.
- **Tools.** Each is one of your own operations, and needs that operation's scopes (2). The list is fixed; a change to it is announced in this guide.

| Tool                   | The same as                                 | Hints                                          |
| ---------------------- | ------------------------------------------- | ---------------------------------------------- |
| `get_agent`            | `GET /v1/agent`                             | read-only                                      |
| `get_mandate`          | `GET /v1/agent/mandate`                     | read-only                                      |
| `list_funding_sources` | `GET /v1/agent/funding-sources`             | read-only                                      |
| `list_suppliers`       | `GET /v1/agent/suppliers`                   | read-only                                      |
| `create_spend_request` | `POST /v1/spend-requests`                   | destructive (may become a payment), idempotent |
| `get_spend_request`    | `GET /v1/agent/spend-requests/{id}`         | read-only                                      |
| `cancel_spend_request` | `POST /v1/agent/spend-requests/{id}/cancel` | destructive, idempotent                        |

There is no tool to execute a payment, change a limit, read a credential, approve a request or simulate a policy, and there never will be one to execute, override a limit or fetch a credential. Agent X decides every request itself, against your mandate, your organisation's rules and a person's approval where they need one: a client that asks you before a call adds a check, and one that doesn't removes none.

- **Arguments.** The operation's path, query and body fields, side by side (`id`, `after`, `limit`, `amountMinor`, …), checked exactly as the operation checks them; any other argument is refused. A write takes its idempotency key as the `idempotencyKey` argument, under the rules in 4. A key sent over MCP and the same request sent over REST with the same key are one request.
- **Answers.** A tool's answer is in `structuredContent`, exactly the body its operation answers, described by the tool's `outputSchema`, with every text cleared of control and direction-changing characters and cut to 500 characters. Beside it, two text blocks: a short summary in fixed words, then the same JSON. Text a person or an agent wrote (a supplier's name, a mandate's purpose, your order reference) is data, never instructions.
- **Refusals.** A tool refused answers with `isError: true` and, in `structuredContent`, the error body of 5 with the HTTP `status` its operation would have answered, and `retryAfterSeconds` when you should wait and send the same call again. Act on `error.code` as in 5. JSON-RPC errors are only for calls the protocol can't read.
- **Limits and logs.** Each MCP call counts once against your rate limits (6) and has its own correlation ID (7). Your organisation's activity log shows each tool call by its name and the status its operation would have answered.

### Connecting your client

Keep the key in an environment variable (AGENTX_KEY below) or your client's secret store, never in a file you share.

- **Claude Code:** `claude mcp add --transport http agentx https://<your-agent-x-host>/v1/mcp --header "Authorization: Bearer $AGENTX_KEY"`
- **Codex (CLI, IDE, desktop):** `codex mcp add agentx --url https://<your-agent-x-host>/v1/mcp --bearer-token-env-var AGENTX_KEY`
- **Cursor:** in `~/.cursor/mcp.json`, `{"mcpServers":{"agentx":{"url":"https://<your-agent-x-host>/v1/mcp","headers":{"Authorization":"Bearer ${env:AGENTX_KEY}"}}}}`; or open `cursor://anysphere.cursor-deeplink/mcp/install?name=agentx&config=<base64 of {"url":"https://<your-agent-x-host>/v1/mcp"}>` and add the header after.
- **VS Code (Copilot):** `code --add-mcp '{"name":"agentx","type":"http","url":"https://<your-agent-x-host>/v1/mcp","headers":{"Authorization":"Bearer ${input:agentx-key}"}}'`
- **Copilot cloud agent:** in the repository's MCP configuration, `{"mcpServers":{"agentx":{"type":"http","url":"https://<your-agent-x-host>/v1/mcp","headers":{"Authorization":"Bearer $COPILOT_MCP_AGENTX_KEY"},"tools":["*"]}}}`, the key as the environment's secret COPILOT_MCP_AGENTX_KEY.
- **Gemini CLI:** `gemini mcp add --transport http --header "Authorization: Bearer $AGENTX_KEY" agentx https://<your-agent-x-host>/v1/mcp`
- **Antigravity:** in `~/.gemini/config/mcp_config.json`, `{"mcpServers":{"agentx":{"serverUrl":"https://<your-agent-x-host>/v1/mcp","headers":{"Authorization":"Bearer <your key>"}}}}`
- **Hermes Agent:** `hermes mcp add agentx --url https://<your-agent-x-host>/v1/mcp --auth header` (it asks for the key and keeps it in `~/.hermes/.env`).
- **OpenClaw:** `openclaw mcp add agentx --url https://<your-agent-x-host>/v1/mcp --transport streamable-http --header 'Authorization=Bearer ${AGENTX_KEY}'`. Name the transport: OpenClaw otherwise tries SSE.
- **Cline:** in its MCP settings, `{"mcpServers":{"agentx":{"type":"streamableHttp","url":"https://<your-agent-x-host>/v1/mcp","headers":{"Authorization":"Bearer <your key>"}}}}`
- **Any other MCP host, through a local bridge:** `npx mcp-remote https://<your-agent-x-host>/v1/mcp --transport http-only --header "Authorization: Bearer ${AGENTX_KEY}"`
- **Claude Messages API:** `"mcp_servers": [{"type": "url", "url": "https://<your-agent-x-host>/v1/mcp", "name": "agentx", "authorization_token": "<your key>"}]`, with the `mcp_toolset` tool naming `agentx`.
- **OpenAI Responses API / Agents SDK:** `{"type": "mcp", "server_label": "agentx", "server_url": "https://<your-agent-x-host>/v1/mcp", "authorization": "<your key>"}`

### Connecting by signing in (OAuth)

Apps that connect by signing in rather than with a pasted key (claude.ai, ChatGPT and other MCP clients) use Agent X's own OAuth 2.1 server. A person in the organisation, an admin or a developer, picks the agent the app acts as and the permissions it gets; the app then holds tokens for that one agent, at the MCP endpoint alone. An MCP client that supports OAuth does all of this itself once given the address `https://<your-agent-x-host>/v1/mcp`; this section is for those building one. Where the deployment hasn't turned it on, every address below answers 404.

- **Discovery.** `POST /v1/mcp` without a token answers 401 with `WWW-Authenticate: Bearer … resource_metadata="https://<your-agent-x-host>/.well-known/oauth-protected-resource/v1/mcp"`. That document (also at `/.well-known/oauth-protected-resource`) names the resource, `https://<your-agent-x-host>/v1/mcp`, and the authorization server, `https://<your-agent-x-host>`. The server's metadata is at `/.well-known/oauth-authorization-server` (RFC 8414), and the same document at `/.well-known/openid-configuration` for clients that only look there; Agent X is not an OpenID provider and issues no ID tokens.
- **Registration.** `POST /v1/oauth/register` (RFC 7591, dynamic client registration) with your `redirect_uris` (1 to 5, each https, or `http://127.0.0.1`, `http://localhost` or `http://[::1]` on any port for an app on the person's own computer) and `client_name`. The answer, 201, holds your `client_id`; there is no client secret (`token_endpoint_auth_method` is `none`) and no registration access token. A client that never connects is deleted after a day, and one unused for 90 days after its last connection.
- **Authorization.** Send the person's browser to `GET /v1/oauth/authorize` with `response_type=code`, `client_id`, `redirect_uri` (exactly as registered), `state`, `code_challenge` and `code_challenge_method=S256` (PKCE is required; `plain` is refused), the `scope` you need, and `resource=https://<your-agent-x-host>/v1/mcp`. The person signs in, picks the organisation and the agent, ticks the permissions (write permissions start unticked), and confirms by signing in again. The browser comes back to your `redirect_uri` with `code`, your `state` and `iss=https://<your-agent-x-host>` (RFC 9207): check `iss` is the server you sent the person to. A refusal comes back as `error=access_denied` (or another OAuth error) with the same `state` and `iss`.
- **Scopes.** The agent scopes of 2 (`requests:read`, `requests:write`, `sources:read`, `suppliers:read`), and `offline_access`, which changes nothing: a refresh token always comes with the access token. The person may grant fewer than you asked for, and never more than the agent holds; the token answer's `scope` says what was granted.
- **Tokens.** `POST /v1/oauth/token` as a form (`application/x-www-form-urlencoded`). Exchange the code within 60 seconds with `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier` and `resource`; a code works once, and a code sent twice revokes the connection it made. The answer: `access_token` (`axa_…`, for one hour), `refresh_token` (`axr_…`), `token_type` `Bearer`, `expires_in` and `scope`. Refresh with `grant_type=refresh_token`, `refresh_token` and `client_id` (and `scope` to narrow it, never to widen): each refresh token works once and the answer holds a new pair; a refresh token sent a second time revokes the connection, so never refresh with the same token from two places at once. A refresh token not used for 30 days stops working, and every connection ends 90 days after it was made: the person connects the app again. Errors are OAuth's own body, `{"error": "…", "error_description": "…"}` (RFC 6749 §5.2), not the error body of 5; a 503 `temporarily_unavailable` carries `Retry-After`: send the same request again.
- **Using it.** `Authorization: Bearer axa_…` on `POST /v1/mcp` alone: the token is refused anywhere else in the API. Everything in 9 above applies as for a key, as the agent the person picked, with the permissions granted.
- **Revoking.** Your app revokes its connection with `POST /v1/oauth/revoke` (RFC 7009), a form with `token` (either token) and `client_id`; the answer is always 200. The organisation sees each connection on the agent's page in the console, every working one and those ended in the last 30 days, and can revoke it there (signing in again for it). A connection also ends when its agent's owner hands it over, when the member who made it leaves the organisation, and while its agent is suspended its tokens are refused. After any of these, the access token is refused with 401 at its next use and a refresh with `invalid_grant`: send the person through authorization again.
