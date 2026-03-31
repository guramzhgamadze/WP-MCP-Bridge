# WordPress MCP Bridge

> Connect your WordPress site to Claude.ai via the Model Context Protocol (MCP) — giving Claude read-only access to your plugins, themes, post types, custom fields, database, source files, logs, hooks, and more.

![Version](https://img.shields.io/badge/version-2.6.0-blue)
![WordPress](https://img.shields.io/badge/WordPress-5.8%2B-21759b)
![PHP](https://img.shields.io/badge/PHP-8.0%2B-777bb3)
![License](https://img.shields.io/badge/license-GPL--2.0-green)

---

## What It Does

WordPress MCP Bridge turns your WordPress site into an MCP server that Claude.ai can connect to. Once connected, Claude can inspect your site's architecture in real time — plugins, database schema, source code, ACF fields, REST routes, cron jobs, and more — so it can write plugins, debug issues, and answer questions that are **perfectly tailored to your exact setup**.

**Claude gets read-only access. It cannot write, delete, or modify anything.**

---

## Features

- **Full OAuth 2.1 authorization server** with PKCE (S256), dynamic client registration (RFC 7591), and auto-discovery endpoints (RFC 8414 + RFC 9728)
- **Bearer Token auth** as a simpler alternative to OAuth
- **19 MCP tools** covering every major aspect of a WordPress site
- **Rate limiting** — 120 tool calls per minute per IP
- **Security hardened** — path traversal guards, credential redaction, single-use auth codes, clickjacking protection, and more
- **Apache + FastCGI compatible** — Authorization header normalization built in
- **Zero dependencies** — pure WordPress, no Composer required

---

## Requirements

| Requirement | Version |
|---|---|
| WordPress | 5.8 or higher |
| PHP | **8.0 or higher** (uses union types and `str_starts_with`) |
| MySQL / MariaDB | Any version supported by your WordPress install |

---

## Installation

1. Download or clone this repository into your `wp-content/plugins/` directory:
   ```bash
   cd wp-content/plugins
   git clone https://github.com/your-repo/wp-mcp-bridge.git wp-mcp-bridge
   ```
2. Activate the plugin from **WordPress Admin → Plugins**.
3. Go to **Settings → MCP Bridge** to find your endpoint URL and Bearer Token.
4. Flush rewrite rules: **Settings → Permalinks → Save Changes**.

---

## Connecting to Claude.ai

There are two connection methods. Option A is the fastest.

### Option A — Bearer Token (Simplest)

1. In Claude.ai, go to **Profile → Settings → Connectors → Add custom connector**.
2. Paste your **MCP Endpoint URL** (found in Settings → MCP Bridge):
   ```
   https://your-site.com/wp-json/mcp/v1/bridge
   ```
3. Set auth type to **Bearer Token** (or **API Key**).
4. Paste the token from the settings page.
5. Save — Claude.ai connects immediately.

### Option B — OAuth 2.1 (Browser Login Flow)

Claude.ai will automatically discover the OAuth server via the `.well-known/` endpoints. If asked for OAuth details manually, use:

| Field | Value |
|---|---|
| Authorization URL | `https://your-site.com/wp-json/mcp/v1/oauth/authorize` |
| Token URL | `https://your-site.com/wp-json/mcp/v1/oauth/token` |
| Client ID | `claude.ai` (any value except literally "Bearer Token") |
| Scopes | `claudeai` |

Claude.ai will open a browser window to your WordPress site, where you log in as an administrator and click **Allow Access**.

---

## Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /wp-json/mcp/v1/bridge` | Main MCP JSON-RPC endpoint |
| `GET/POST /wp-json/mcp/v1/oauth/authorize` | OAuth 2.1 authorization |
| `POST /wp-json/mcp/v1/oauth/token` | OAuth 2.1 token exchange |
| `POST /wp-json/mcp/v1/oauth/register` | Dynamic client registration (RFC 7591) |
| `GET /.well-known/oauth-authorization-server` | OAuth discovery (RFC 8414) |
| `GET /.well-known/oauth-protected-resource` | Protected resource metadata (RFC 9728) |
| `GET /authorize` | Old-spec fallback (auto-proxied) |
| `POST /token` | Old-spec fallback (auto-proxied) |

---

## Available MCP Tools

| Tool | Description |
|---|---|
| `wp_get_site_info` | WP/PHP/MySQL versions, active theme, plugins, debug settings, upload dirs |
| `wp_get_plugins` | All installed plugins — name, version, author, status (`active`/`inactive`/`all`) |
| `wp_get_themes` | All themes — version, author, parent theme, active state |
| `wp_get_post_types` | All post types — labels, supports, taxonomies, REST base, post count |
| `wp_get_taxonomies` | All taxonomies — object types, REST settings, term counts |
| `wp_get_options` | WordPress options (credentials always redacted) |
| `wp_query_posts` | Query any post type via WP_Query — returns post data, meta, and terms |
| `wp_get_db_schema` | All database tables — columns, types, row counts |
| `wp_db_query` | Run a `SELECT` query (credential columns and `SELECT * on wp_users` blocked) |
| `wp_list_files` | List files in any `wp-content` subdirectory, filtered by extension |
| `wp_read_file` | Read any source file in `wp-content` (max 512 KB) |
| `wp_get_logs` | Read `debug.log` or PHP error log (last N lines) |
| `wp_get_hooks` | Inspect `$wp_filter` — all registered actions and filters with priorities |
| `wp_get_acf_fields` | All ACF field groups and fields (requires ACF plugin) |
| `wp_get_users` | List users with roles (passwords never returned) |
| `wp_get_menus` | Navigation menus, assigned locations, and menu items with hierarchy |
| `wp_get_cron_jobs` | All scheduled WP cron events — next run times, schedules, and args |
| `wp_get_active_widgets` | Active widget areas and widgets with their settings |
| `wp_get_rest_routes` | All registered REST API routes with methods and namespaces |

---

## Security

### Authentication
- Bearer tokens are stored with `autoload = false` — never loaded on regular page requests
- Tokens are validated with `hash_equals()` to prevent timing attacks
- OAuth access tokens expire after **1 hour**; authorization codes expire after **10 minutes**
- Authorization codes are **single-use** — deleted immediately on redemption

### Authorization
- Only WordPress administrators (`manage_options`) can grant OAuth consent
- The OAuth consent page is protected against clickjacking via `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`
- PKCE S256 is **mandatory** — plain code challenges are rejected

### File & Database Access
- All file operations are contained within `wp-content` using `realpath()` + separator-aware path checks (OWASP path traversal prevention)
- Log file paths are validated against an allowlist of roots (`WP_CONTENT_DIR`, `ABSPATH`, `sys_get_temp_dir()`)
- Database queries are restricted to `SELECT` only; `user_pass`, `user_activation_key`, and `SELECT * on wp_users` are blocked
- The plugin's own API key and OAuth redirect URIs are blocked from the `wp_get_options` tool

### CORS & Network
- CORS headers are scoped to `claude.ai`, `app.claude.ai`, and `www.claude.ai` only
- DNS rebinding protection via per-request origin check
- `WWW-Authenticate` on 401 responses points Claude.ai to the OAuth discovery endpoint
- Apache + FastCGI Authorization header normalization — no `.htaccess` workaround needed

---

## OAuth Flow Diagram

```
Claude.ai                     Your WordPress Site
    │                               │
    │──GET /.well-known/oauth-protected-resource──▶│
    │◀─── { authorization_servers: [...] } ────────│
    │                               │
    │──GET /.well-known/oauth-authorization-server─▶│
    │◀─── { authorization_endpoint, token_endpoint, registration_endpoint } ──│
    │                               │
    │──POST /mcp/v1/oauth/register──▶│  (RFC 7591 Dynamic Client Registration)
    │◀─── { client_id } ────────────│
    │                               │
    │──GET /mcp/v1/oauth/authorize──▶│  (PKCE code_challenge S256)
    │◀─── redirect to WP login ─────│
    │                               │
    [User logs in as WP admin, clicks "Allow Access"]
    │                               │
    │◀─── redirect with ?code= ─────│
    │                               │
    │──POST /mcp/v1/oauth/token─────▶│  (code + code_verifier)
    │◀─── { access_token, expires_in } ───────────│
    │                               │
    │──POST /mcp/v1/bridge──────────▶│  (Authorization: Bearer <token>)
    │◀─── MCP JSON-RPC response ────│
```

---

## Troubleshooting

### 404 / `rest_no_route`
1. Go to **Settings → Permalinks** and click **Save Changes** to flush rewrite rules.
2. Confirm the plugin is active.
3. Test the endpoint manually:
   ```bash
   curl -s -X POST https://your-site.com/wp-json/mcp/v1/bridge \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}'
   ```
   A working response starts with: `{"jsonrpc":"2.0","id":1,"result":{...`

### OAuth `rest_cookie_invalid_nonce` (403)
Fixed in v2.6.0 (BUG-35). Update to the latest version. The consent form now sends two separate nonces: one for WordPress REST cookie auth (`_wpnonce`) and one for CSRF protection (`_mcp_nonce`).

### Authorization header always empty (Apache + FastCGI)
Fixed automatically in v2.4.0+ via the `wp_mcp_bridge_fix_auth_header()` function hooked to `init` priority 1. If you still see issues, add this to your `.htaccess`:
```apache
RewriteRule ^ - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
```

### Bearer Token via `wp_get_options`
Fixed in v2.6.0 (BUG-31). The plugin's own `wp_mcp_bridge_api_key` option is now permanently blocked from the `wp_get_options` tool.

### Enable Debug Logging
Add to `wp-config.php`:
```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);
```
Then check `wp-content/debug.log` or use the `wp_get_logs` MCP tool.

---

## Changelog

### v2.6.0
- **Fix [CRITICAL]** BUG-35: `rest_cookie_invalid_nonce` 403 on "Allow Access" — two-nonce form approach
- **Fix [CRITICAL]** BUG-31: `wp_get_options` could expose the plugin's own Bearer token
- **Fix [HIGH]** BUG-32: `_get_cron_array()` returning `false` crashes cron tool on PHP 8.2+
- **Fix [MEDIUM]** BUG-33: Unused `$resp_types` variable causing PHP notice
- **Fix [LOW]** BUG-34: Transients not cleaned up on plugin deactivation

### v2.5.0
- **Fix [CRITICAL]** BUG-26: Missing `registration_endpoint` — Claude Code could not connect
- **Fix [CRITICAL]** BUG-27: Plugin declared `Requires PHP: 7.4` but used PHP 8.0+ syntax
- **Fix [HIGH]** BUG-28: `realpath()` returning `false` bypassed path containment guard
- **Fix [MEDIUM]** BUG-29: `register_setting()` not hooked to `rest_api_init`
- **Fix [MEDIUM]** BUG-30: `array_filter()` stripping valid empty-string OAuth params

### v2.4.0
- **Fix [CRITICAL]** BUG-20: `do_action('rest_api_init')` inside tool callback double-fired all hooks
- **Fix [HIGH]** BUG-21: `strncmp` path prefix check bypassed by sibling directories
- **Fix [HIGH]** BUG-22: N+1 DB queries in `wp_get_users` tool
- **Fix [HIGH]** BUG-23: Unescaped output of `$client_display` variable (XSS risk)
- **Fix [MEDIUM]** BUG-24: OAuth consent page missing `X-Frame-Options` — clickjacking
- **Fix [MEDIUM]** BUG-25: Authorization header stripped on Apache/FastCGI — auth always failed

### v2.3.0
- **Fix [CRITICAL]** BUG-12: `wp_safe_redirect()` blocked OAuth code delivery to `claude.ai`
- **Fix [CRITICAL]** BUG-13: `get_json_params()` returning `null` caused PHP 8 TypeError
- **Fix [HIGH]** BUG-14: `wp_enqueue_script('', '')` didn't queue inline JS handle
- **Fix [HIGH]** BUG-15: `ini_get('error_log')` bypassed safe path — log traversal vulnerability
- **Fix [HIGH]** BUG-16: Token fallback path always emitted HTTP 200 even on errors
- **Fix [MEDIUM]** BUG-17: `strtok()` global state corrupted path parsing
- **Fix [MEDIUM]** BUG-18: Cache-Control/Pragma headers missing on token fallback responses
- **Fix [LOW]** BUG-19: Missing `rel="noopener noreferrer"` on `target="_blank"` links

### v2.2.0
- Full OAuth 2.1 PKCE authorization server implemented (BUG-11)
- Added `/.well-known/oauth-authorization-server` (RFC 8414)
- Added `/.well-known/oauth-protected-resource` (RFC 9728)
- Added `/authorize` and `/token` fallback paths for old MCP spec compatibility

### v2.1.0
- **Fix [CRITICAL]** BUG-01: Missing GET handler caused generic 404
- **Fix [CRITICAL]** BUG-02: OPTIONS preflight blocked by auth callback
- **Fix [CRITICAL]** BUG-03: Missing CORS headers blocked all Claude.ai responses
- **Fix [HIGH]** BUG-04: `post_count` always cast to `1` via stdClass
- **Fix [HIGH]** BUG-05: Missing `wp_reset_postdata()` after WP_Query loop
- **Fix [MEDIUM]** BUG-06: API key stored with `autoload = true`
- **Fix [MEDIUM]** BUG-07: `date()` used instead of `gmdate()` for timestamps
- **Fix [MEDIUM]** BUG-08: `MCP-Protocol-Version` header only on initialize response
- **Fix [LOW]** BUG-09: Rate-limit key used spoofable `HTTP_X_FORWARDED_FOR`
- **Fix [LOW]** BUG-10: Inline `onclick` JS on "Regenerate Key" button

---

## Contributing

Pull requests are welcome. For significant changes, please open an issue first.

When reporting a bug, please include:
- WordPress version
- PHP version
- The exact error message or HTTP response
- Output of `curl` against the MCP endpoint (with token redacted)

---

## License

[GPL v2 or later](https://www.gnu.org/licenses/gpl-2.0.html)
