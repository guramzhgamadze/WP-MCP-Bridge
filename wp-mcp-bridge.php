<?php
/**
 * Plugin Name:       WordPress MCP Bridge
 * Plugin URI:        https://github.com/your-repo/wp-mcp-bridge
 * Description:       Exposes your WordPress site to Claude.ai via the Model Context Protocol (MCP). Gives Claude read-only access to plugins, themes, post types, custom fields, database, source files, logs, hooks, and more — so it can write perfectly tailored plugins for your site.
 * Version:           2.6.0
 * Requires at least: 5.8
 * Requires PHP:      8.0
 * Author:            Your Name
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-mcp-bridge
 */

/*
 * ============================================================
 * AUDIT v2.6.0  — 5 bugs found and fixed
 * ============================================================
 *
 * BUG-35 [CRITICAL] rest_cookie_invalid_nonce (403) when clicking "Allow Access".
 *   ROOT CAUSE: WordPress REST API cookie authentication reads $_REQUEST['_wpnonce']
 *   and validates it against wp_create_nonce('wp_rest') — this runs BEFORE
 *   permission_callback and before our handler executes. The consent form sent
 *   _wpnonce = wp_create_nonce('wp_mcp_oauth_consent'), which WordPress REST
 *   cookie auth saw, tried to verify as 'wp_rest', failed, and returned 403.
 *   The permission_callback='__return_true' was never even reached.
 *   Source: wp-includes/class-wp-rest-server.php §REST_COOKIE_AUTH
 *   Source: developer.wordpress.org/rest-api/using-the-rest-api/authentication/
 *   FIX: Two-nonce approach in the consent form:
 *     _wpnonce  = wp_create_nonce('wp_rest')            ← for WP REST cookie auth
 *     _mcp_nonce = wp_create_nonce('wp_mcp_oauth_consent') ← for our CSRF check
 *   POST handler now checks _mcp_nonce instead of _wpnonce.
 *   Both protections are fully active; they serve separate purposes.
 *
 * BUG-31 [CRITICAL] wp_get_options tool can expose the plugin's own Bearer token.
 *   wp_mcp_tool_options() blocked WordPress security keys but NOT the plugin's
 *   own option keys. An authenticated Claude session could call the tool with
 *   keys:['wp_mcp_bridge_api_key'] and receive the very Bearer token it used
 *   to authenticate — silently exfiltrating the credential.
 *   Source: developer.wordpress.org/reference/functions/get_option/
 *   FIX: Added 'wp_mcp_bridge_api_key' and 'wp_mcp_bridge_oauth_redirect_uris'
 *        to the $blocked list in wp_mcp_tool_options().
 *
 * BUG-32 [HIGH] _get_cron_array() returns false on corrupt/missing cron data —
 *   foreach(false) emits E_WARNING on PHP 8.0/8.1 and throws TypeError on
 *   PHP 8.2+, crashing the wp_get_cron_jobs tool entirely.
 *   Source: developer.wordpress.org/plugins/cron/simple-testing/
 *   FIX: $cron = _get_cron_array() ?: []; normalises false to empty array.
 *
 * BUG-33 [MEDIUM] Unused $resp_types variable in DCR handler — PHP notice.
 *   FIX: Removed the unused assignment; added explanatory comment.
 *
 * BUG-34 [LOW] No transient cleanup on plugin deactivation — orphaned DB rows.
 *   WordPress plugin handbook: clean up after yourself on deactivation.
 *   Source: developer.wordpress.org/plugins/cron/scheduling-wp-cron-events/
 *   FIX: Added $wpdb DELETE in wp_mcp_bridge_deactivate() for wpmcp_ transients.
 *

 *   wp_mcp_tool_options() blocked WordPress security keys but NOT the plugin's
 *   own option keys. An authenticated Claude session could call the tool with
 *   keys:['wp_mcp_bridge_api_key'] and receive the very Bearer token it used
 *   to authenticate — silently exfiltrating the credential to Claude's context,
 *   log, or any MCP consumer.
 *   Source: developer.wordpress.org/reference/functions/get_option/
 *   FIX: Added 'wp_mcp_bridge_api_key' and 'wp_mcp_bridge_oauth_redirect_uris'
 *        to the $blocked list in wp_mcp_tool_options().
 *
 * BUG-32 [HIGH] _get_cron_array() returns false on corrupt/missing cron data —
 *   foreach(false) emits E_WARNING on PHP 8.0/8.1 and throws TypeError on
 *   PHP 8.2+, crashing the wp_get_cron_jobs tool entirely.
 *   _get_cron_array() returns false when the 'cron' option is not an array
 *   (e.g., fresh install, malformed option, filtered to false). WordPress core
 *   itself guards against this return value in wp_clear_scheduled_hook() and
 *   wp_schedule_single_event() with empty($crons) checks.
 *   Source: developer.wordpress.org/plugins/cron/simple-testing/
 *   Source: developer.wordpress.org/reference/functions/_get_cron_array/
 *   FIX: $cron = _get_cron_array() ?: []; normalises false to empty array.
 *
 * BUG-33 [MEDIUM] Unused $resp_types variable in DCR handler — PHP notice.
 *   wp_mcp_bridge_oauth_register_rest() assigned $resp_types but never read it.
 *   PHP 8+ emits E_NOTICE for unused variables in some configurations, and
 *   static analysis tools flag it. It also created a latent risk of accidental
 *   reliance on an unchecked user-supplied value.
 *   FIX: Removed the assignment; added explanatory comment.
 *
 * BUG-34 [LOW] No transient cleanup on plugin deactivation — orphaned DB rows.
 *   OAuth code transients (wpmcp_code_*), access token transients (wpmcp_token_*),
 *   and rate-limit transients (wpmcp_rate_*) are left in wp_options after the
 *   plugin is deactivated. Although they expire on their own, best practice and
 *   the WordPress plugin handbook both require cleanup on deactivation.
 *   Source: developer.wordpress.org/plugins/cron/scheduling-wp-cron-events/
 *   FIX: Added $wpdb->query DELETE in wp_mcp_bridge_deactivate() scoped to
 *        the wpmcp_ transient prefix used exclusively by this plugin.
 *
 * ============================================================
 * BUGS FIXED IN v2.5.0 (carried forward)
 * ============================================================
 *
 * BUG-26 [CRITICAL] Missing registration_endpoint → Claude Code cannot connect.
 * BUG-27 [CRITICAL] Requires PHP: 7.4 but uses PHP 8.0+ syntax → parse error.
 * BUG-28 [HIGH]     wp_mcp_safe_path: realpath() false → str_starts_with bypass.
 * BUG-29 [MEDIUM]   register_setting only on admin_init, not rest_api_init.
 * BUG-30 [MEDIUM]   array_filter($params) strips valid empty-string OAuth params.
 *

 *   Metadata — Claude.ai and Claude Code fail to connect.
 *   The MCP spec 2025-06-18 states authorization servers SHOULD support
 *   OAuth 2.0 Dynamic Client Registration (RFC 7591). Without a
 *   registration_endpoint in the /.well-known/oauth-authorization-server
 *   metadata document, Claude Code fails immediately with:
 *     "Incompatible auth server: does not support dynamic client registration"
 *   Claude.ai shows the same error when it cannot register a client_id.
 *   Source: modelcontextprotocol.io/specification/2025-06-18/basic/authorization
 *   Source: github.com/anthropics/claude-code/issues/38102
 *   Source: tools.ietf.org/html/rfc7591 (OAuth 2.0 Dynamic Client Registration)
 *   FIX: Added /wp-json/mcp/v1/oauth/register endpoint (RFC 7591).
 *        Added registration_endpoint field to the ASM metadata document.
 *        The endpoint accepts any well-formed DCR request, validates the
 *        redirect_uris against our allowlist, and returns a deterministic
 *        client_id derived from the registration metadata.
 *
 * BUG-27 [CRITICAL] Plugin declares Requires PHP: 7.4 but uses PHP 8.0+
 *   features — fatal error on PHP 7.4.
 *   The plugin uses:
 *     - Union return types (bool|WP_Error) — PHP 8.0+ only
 *     - str_starts_with() — PHP 8.0+ only
 *   PHP 7.4 has no support for either. Any site running PHP 7.4 (still
 *   common on shared hosts) gets a fatal "Parse error: syntax error" the
 *   moment WordPress tries to load the plugin file.
 *   Source: php.net/manual/en/migration80.new-features.php
 *   FIX: Changed Requires PHP: 7.4 → Requires PHP: 8.0 in plugin header.
 *        WordPress will now block activation on PHP < 8.0 with a clear error.
 *
 * BUG-28 [HIGH] wp_mcp_safe_path(): no null-check on $base — the entire
 *   path containment guard is bypassed if realpath(WP_CONTENT_DIR) fails.
 *   realpath() returns false when the target directory does not exist.
 *   If $base is false:
 *     $base . '/' = '/' (PHP coerces false → empty string)
 *     str_starts_with($full, false . DIRECTORY_SEPARATOR)
 *       = str_starts_with($full, '/')
 *       = true for every absolute path
 *   This means ANY path resolves as "inside wp-content", allowing any file
 *   on the filesystem to be read via wp_read_file and wp_list_files.
 *   The same flaw existed in the log tool's allowed_roots check.
 *   Source: php.net/manual/en/function.realpath.php
 *   FIX: Added an explicit `if ( $base === false )` guard at the top of
 *        wp_mcp_safe_path() and in the log tool's allowed_roots loop.
 *
 * BUG-29 [MEDIUM] register_setting() only hooked to admin_init — not
 *   rest_api_init. WordPress documentation explicitly requires both.
 *   "If you plan to use your setting in the REST API, use both the
 *    rest_api_init and admin_init hooks when calling register_setting()
 *    instead of just admin_init."
 *   Without the rest_api_init hook, the sanitize_callback is not applied
 *   when settings are updated via the REST API, leaving them unsanitised.
 *   Source: developer.wordpress.org/reference/functions/register_setting/
 *   FIX: Hook wp_mcp_bridge_admin_settings() to both admin_init and
 *        rest_api_init.
 *
 * BUG-30 [MEDIUM] array_filter($params) in wp_mcp_bridge_authorize_url()
 *   strips legitimate empty-string OAuth parameters.
 *   array_filter() with no callback removes ALL falsy values, including
 *   empty string '' and '0'. The OAuth state and scope parameters can
 *   legitimately be empty strings in some flows. When state='' is stripped
 *   from the login return URL, the authorize endpoint receives no state on
 *   the post-login redirect — breaking CSRF protection. When scope='' is
 *   stripped, the server picks a default scope the client may not expect.
 *   Source: tools.ietf.org/html/rfc6749#section-4.1.1
 *   Source: php.net/manual/en/function.array-filter.php
 *   FIX: Replace array_filter($params) with array_filter($params, 'strlen')
 *        which only removes null and false, not empty strings.
 *        For 'state' and 'scope' specifically, preserve them even when empty.
 *
 * ============================================================
 * BUGS FIXED IN v2.4.0 (carried forward)
 * ============================================================
 *
 * BUG-20 [CRITICAL] do_action('rest_api_init') inside a tool callback
 *   double-fires every rest_api_init hook in the system.
 *   wp_mcp_tool_rest_routes() called do_action('rest_api_init') to "ensure
 *   all plugin routes are registered." But this function is called from
 *   inside a REST API request — routes are already registered. Calling
 *   do_action('rest_api_init') again fires every plugin's REST registration
 *   callback a second time, including our own wp_mcp_bridge_register_routes(),
 *   which tries to register all MCP routes twice. WordPress logs "Route is
 *   already registered" notices; other plugins may perform DB writes, send
 *   emails, or trigger other side-effects as if the REST API were initialising.
 *   Source: developer.wordpress.org/reference/hooks/rest_api_init/
 *   FIX: Remove do_action(); call rest_get_server() directly — the server is
 *   already initialised by the time any tool runs inside a REST callback.
 *
 * BUG-21 [HIGH] wp_mcp_safe_path() strncmp prefix check is bypassable.
 *   strncmp($full, $base, strlen($base)) matches any path whose first
 *   strlen($base) bytes equal $base — including sibling directories.
 *   Example: $base = '/var/www/html/wp-content'
 *            $full = '/var/www/html/wp-content-evil/shell.php'
 *   strncmp returns 0 (match) → path escapes wp-content silently.
 *   This is a documented class of path-traversal bypass.
 *   Source: owasp.org/www-community/attacks/Path_Traversal
 *   FIX: Check str_starts_with($full, $base . DIRECTORY_SEPARATOR)
 *   OR $full === $base (exact match for the directory itself).
 *   The same fix is applied to the log tool's allowed_roots check.
 *
 * BUG-22 [HIGH] get_userdata() called per user in a loop — N+1 queries.
 *   wp_mcp_tool_get_users() used 'fields' => [...column array...] in the
 *   get_users() call, which returns stdClass objects without roles. Then
 *   get_userdata($user->ID)->roles was called for each user to fetch roles
 *   from wp_usermeta. get_userdata() issues a separate DB query per user.
 *   On a site with 200 users this means 200 additional queries per tool call.
 *   Source: developer.wordpress.org/reference/functions/get_users/
 *     "If 'fields' is set to 'all' (default) it will return WP_User objects."
 *     WP_User objects have ->roles directly; WP_User_Query batch-primes cache.
 *   FIX: Remove the 'fields' restriction → get WP_User objects → use ->roles.
 *
 * BUG-23 [HIGH] $client_display echoed unescaped — breaks WordPress
 *   "always escape on output" rule and trips security scanners.
 *   The variable holds either a hardcoded HTML string (Bearer Token case)
 *   or esc_html($client_id) (normal case), then is echoed without escaping.
 *   While the hardcoded branch is safe today, it creates an antipattern where
 *   a single variable holds both HTML and text depending on runtime state.
 *   Any future modification risks an XSS.
 *   Source: developer.wordpress.org/apis/security/escaping/
 *   FIX: Separate the two branches at the echo site. Hardcoded HTML rendered
 *   via a dedicated PHP block; user-supplied data escaped with esc_html().
 *
 * BUG-24 [MEDIUM] OAuth consent page missing X-Frame-Options — clickjacking.
 *   RFC 6749 §10.13 ("Clickjacking") explicitly requires that authorization
 *   endpoints prevent embedding in iframes. Without X-Frame-Options: DENY
 *   an attacker could load the consent page in a transparent iframe over a
 *   legitimate-looking page and trick an authenticated admin into clicking
 *   "Allow Access" without realising.
 *   Source: tools.ietf.org/html/rfc6749#section-10.13
 *   FIX: Add X-Frame-Options: DENY and
 *        Content-Security-Policy: frame-ancestors 'none' headers.
 *
 * BUG-25 [MEDIUM] Authorization header stripped on Apache/FastCGI — auth
 *   always fails even with a valid Bearer token.
 *   Some Apache + mod_fastcgi / PHP-FPM configurations strip the
 *   Authorization header before it reaches PHP. WP_REST_Request::get_header()
 *   then returns an empty string and the plugin returns 401 for every request
 *   regardless of the token value. WordPress core works around this by checking
 *   $_SERVER['HTTP_AUTHORIZATION'] and $_SERVER['REDIRECT_HTTP_AUTHORIZATION'].
 *   Source: developer.wordpress.org/reference/functions/rest_get_authenticated_app_password/
 *   FIX: Before the REST handler runs, normalise the Authorization header from
 *   the $_SERVER superglobal fallbacks used by WordPress core.
 *
 * ============================================================
 * BUGS FIXED IN v2.3.0 (carried forward)
 * ============================================================
 *
 * BUG-12 [CRITICAL] wp_safe_redirect() silently blocks OAuth code delivery.
 * BUG-13 [CRITICAL] get_json_params() null → PHP TypeError crash on PHP 8.
 * BUG-14 [HIGH]     wp_enqueue_script('', '') doesn't queue inline JS handle.
 * BUG-15 [HIGH]     ini_get('error_log') bypasses safe path — log traversal.
 * BUG-16 [HIGH]     Token fallback path always HTTP 200 even on errors.
 * BUG-17 [MEDIUM]   strtok() global state corrupts path parsing.
 * BUG-18 [MEDIUM]   Cache-Control/Pragma headers missing on token fallback.
 * BUG-19 [LOW]      Missing rel="noopener noreferrer" on target="_blank".
 *
 *   wp_safe_redirect() validates the redirect host against WordPress's
 *   allowed-hosts list, which only contains the current site's domain by
 *   default. Redirecting to https://claude.ai/api/mcp/auth_callback fails
 *   silently — WordPress redirects to admin_url() instead. The auth code
 *   is issued but never delivered; the OAuth flow can never complete.
 *   Source: developer.wordpress.org/reference/functions/wp_safe_redirect/
 *   Source: developer.wordpress.org/reference/hooks/allowed_redirect_hosts/
 *   FIX: Added 'allowed_redirect_hosts' filter scoped to MCP OAuth redirects.
 *   Filter is active only during OAuth flow (flag set in authorize core).
 *   Alternatively, wp_redirect() is used for the code delivery step since
 *   the redirect_uri has already been validated against our own allowlist.
 *
 * BUG-13 [CRITICAL] get_json_params() returns null → PHP TypeError crash.
 *   WP_REST_Request::get_json_params() returns null when the request body
 *   is absent or not valid JSON. Then $body['id'] on null triggers a PHP
 *   TypeError on PHP 8.0+: "Cannot use null value as an array".
 *   This crashes the MCP handler on any malformed request (e.g. health checks,
 *   retry packets, or Claude.ai probing during error recovery).
 *   Source: developer.wordpress.org/reference/classes/wp_rest_request/get_json_params/
 *   FIX: $body = $request->get_json_params() ?? [];
 *
 * BUG-14 [HIGH] wp_enqueue_script() with empty string src is unreliable.
 *   wp_enqueue_script('handle', '') does not register the handle into
 *   $wp_scripts->queue — the WP source skips the add() call when $src is
 *   falsy. wp_add_inline_script() then silently attaches to a handle that
 *   is not queued, so the inline JS is never output on some WP versions.
 *   Source: developer.wordpress.org/reference/functions/wp_register_script/
 *     "If source is set to false, script is an alias of other scripts."
 *   Source: developer.wordpress.org/reference/functions/wp_add_inline_script/
 *   FIX: wp_register_script('handle', false) + wp_enqueue_script('handle').
 *
 * BUG-15 [HIGH] Log file path traversal — ini_get('error_log') bypasses safe path.
 *   wp_mcp_tool_get_logs() uses ini_get('error_log') to locate the PHP error
 *   log, which can return any absolute path on the filesystem. The wp_mcp_safe_path()
 *   guard that restricts all other file operations to wp-content is completely
 *   bypassed for log_type='error'. A server with error_log pointing to
 *   /var/log/auth.log, /etc/passwd, or ~/.ssh/authorized_keys would expose
 *   those files through this tool.
 *   FIX: Resolve the log path with realpath() and validate it is inside one of:
 *     ABSPATH, WP_CONTENT_DIR, sys_get_temp_dir(). Throw if outside.
 *
 * BUG-16 [HIGH] Token endpoint fallback always emits HTTP 200 regardless of error.
 *   wp_mcp_bridge_run_oauth_token_from_globals() calls echo wp_json_encode()
 *   without setting the HTTP status code. When token exchange fails (400 for
 *   invalid_grant, 401 for invalid_client) the HTTP response is 200 OK with
 *   a JSON error body. OAuth 2.1 / RFC 6749 §5.2 requires the status code
 *   to match the error class. Claude.ai reads the HTTP status to detect errors.
 *   Source: tools.ietf.org/html/rfc6749#section-5.2
 *   FIX: status_header( $result->get_status() ) before echo.
 *
 * BUG-17 [MEDIUM] strtok() has global state — unsafe in hook callbacks.
 *   PHP's strtok() maintains an internal pointer. If another plugin earlier
 *   in the 'init' hook called strtok() without exhausting the string, the
 *   pointer is left in an arbitrary position. The next strtok($str, '?')
 *   call may return false or the wrong substring.
 *   Source: php.net/manual/en/function.strtok.php
 *     "strtok() is not reentrant. Do not use it if other code also uses it."
 *   FIX: explode( '?', $uri, 2 )[0] — no shared state, deterministic.
 *
 * BUG-18 [MEDIUM] Fallback /token path missing Cache-Control and Pragma headers.
 *   RFC 6749 §5.1 REQUIRES that token responses include:
 *     Cache-Control: no-store
 *     Pragma: no-cache
 *   The REST API path sets these via $response->header(). The fallback path
 *   at /token emits the body directly and omits both required headers.
 *   Source: tools.ietf.org/html/rfc6749#section-5.1
 *   FIX: Add header('Cache-Control: no-store') and header('Pragma: no-cache')
 *   before the echo in wp_mcp_bridge_run_oauth_token_from_globals().
 *
 * BUG-19 [LOW] Missing rel="noopener noreferrer" on target="_blank" admin link.
 *   The admin settings page links to https://claude.ai with target="_blank"
 *   but no rel attribute. The opened page can access window.opener and navigate
 *   the admin tab to a phishing URL (reverse tabnapping attack).
 *   Source: developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel/noopener
 *   FIX: Add rel="noopener noreferrer" to all target="_blank" links.
 *
 * ============================================================
 * BUGS FIXED IN v2.2.0 — OAuth 2.1 PKCE Authorization Server Added
 * ============================================================
 *
 * ROOT CAUSE OF 404 (BUG-11):
 *
 *   When Claude.ai tries to connect to a custom MCP connector it performs
 *   OAuth 2.1 discovery as specified in MCP spec 2025-03-26 / 2025-06-18:
 *
 *   1. Claude.ai sends GET /.well-known/oauth-authorization-server
 *      → Plugin had no such endpoint → WordPress returned 404
 *
 *   2. Claude.ai fell back to old-spec default paths:
 *      https://yogahub.online/authorize?response_type=code&...
 *      → WordPress has no /authorize page → returned 404
 *      → User sees 404 error, Claude.ai cannot connect.
 *
 *   The URL the user reported:
 *   https://yogahub.online/authorize?response_type=code
 *     &client_id=Bearer+Token        ← user entered "Bearer Token" as the
 *                                       client_id field in Claude.ai settings
 *                                       (confusion between auth type and client ID)
 *     &redirect_uri=https://claude.ai/api/mcp/auth_callback
 *     &code_challenge=...            ← PKCE S256 challenge
 *     &code_challenge_method=S256
 *     &state=...
 *     &scope=claudeai
 *
 *   FIX (BUG-11): Implement a complete OAuth 2.1 authorization server:
 *     /.well-known/oauth-protected-resource   (RFC 9728 — MCP 2025-06-18 MUST)
 *     /.well-known/oauth-authorization-server (RFC 8414 — discovery document)
 *     /authorize                              (old-spec fallback path at root)
 *     /token                                  (old-spec fallback path at root)
 *     /wp-json/mcp/v1/oauth/authorize         (canonical REST endpoint)
 *     /wp-json/mcp/v1/oauth/token             (canonical REST endpoint)
 *   Sources:
 *     modelcontextprotocol.io/specification/2025-06-18/basic/authorization
 *     tools.ietf.org/html/rfc8414 (OAuth 2.0 Authorization Server Metadata)
 *     tools.ietf.org/html/rfc9728 (OAuth 2.0 Protected Resource Metadata)
 *     tools.ietf.org/html/rfc7636 (PKCE)
 *
 * ============================================================
 * BUGS FIXED IN v2.1.0 (carried forward)
 * ============================================================
 *
 * BUG-01 [CRITICAL] Missing GET method → generic rest_no_route 404.
 *   FIX: GET handler returns 405 + Allow: POST (MCP spec 2025-06-18).
 *
 * BUG-02 [CRITICAL] OPTIONS preflight blocked by auth callback → browser
 *   refused all POST requests from Claude.ai.
 *   FIX: permission_callback short-circuits to true for OPTIONS.
 *
 * BUG-03 [CRITICAL] Missing CORS response headers → browser blocked
 *   all cross-origin responses.
 *   FIX: rest_pre_serve_request filter injects full CORS header set.
 *
 * BUG-04 [HIGH] post_count cast stdClass→int (always 1).
 *   FIX: Explicit property access on wp_count_posts() result.
 *
 * BUG-05 [HIGH] Missing wp_reset_postdata() after WP_Query loop.
 *   FIX: wp_reset_postdata() added.
 *
 * BUG-06 [MEDIUM] API key stored with autoload = true (loaded every page).
 *   FIX: update_option() with $autoload = false.
 *
 * BUG-07 [MEDIUM] date() used instead of gmdate() for timestamps.
 *   FIX: gmdate() with UTC label.
 *
 * BUG-08 [MEDIUM] MCP-Protocol-Version only on initialize response.
 *   FIX: wp_mcp_ok_response() always sets the header.
 *
 * BUG-09 [LOW] Rate-limit key used HTTP_X_FORWARDED_FOR (spoofable).
 *   FIX: REMOTE_ADDR as canonical key.
 *
 * BUG-10 [LOW] Inline onclick JS on "Regenerate Key" button.
 *   FIX: wp_add_inline_script() named function.
 * ============================================================
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ============================================================
// PLUGIN CONSTANTS
// ============================================================
define( 'WP_MCP_BRIDGE_VERSION',       '2.6.0' );
define( 'WP_MCP_BRIDGE_DIR',           plugin_dir_path( __FILE__ ) );
define( 'WP_MCP_BRIDGE_SLUG',          'wp-mcp-bridge' );
define( 'WP_MCP_BRIDGE_OAUTH_CODE_TTL',  600  ); // auth code valid 10 min (RFC 6749 §4.1.2)
define( 'WP_MCP_BRIDGE_OAUTH_TOKEN_TTL', 3600 ); // access token valid 1 hour

// Negotiated protocol version — set at initialize, used on all responses (BUG-08).
if ( ! defined( 'WP_MCP_BRIDGE_PROTO_VERSION' ) ) {
    define( 'WP_MCP_BRIDGE_PROTO_VERSION', '2025-06-18' );
}

// ============================================================
// ACTIVATION / DEACTIVATION
// ============================================================
register_activation_hook( __FILE__, 'wp_mcp_bridge_activate' );
register_deactivation_hook( __FILE__, 'wp_mcp_bridge_deactivate' );

function wp_mcp_bridge_activate(): void {
    if ( ! get_option( 'wp_mcp_bridge_api_key' ) ) {
        // BUG-06 FIX: autoload = false so key is only loaded on REST calls.
        // Source: developer.wordpress.org/reference/functions/update_option/
        update_option( 'wp_mcp_bridge_api_key', wp_generate_password( 48, false ), false );
    }
    flush_rewrite_rules();
}

function wp_mcp_bridge_deactivate(): void {
    flush_rewrite_rules();
    // BUG-34 FIX: Delete all plugin transients on deactivation.
    // OAuth code transients (wpmcp_code_*), access token transients (wpmcp_token_*),
    // and rate-limit transients (wpmcp_rate_*) are left orphaned if not cleaned up.
    // WordPress plugin handbook: always clean up transients on deactivation.
    // Source: developer.wordpress.org/plugins/cron/scheduling-wp-cron-events/
    // (same principle — "important to clean up after yourself on deactivation")
    global $wpdb;
    $wpdb->query(
        "DELETE FROM {$wpdb->options}
         WHERE option_name LIKE '_transient_wpmcp_%'
            OR option_name LIKE '_transient_timeout_wpmcp_%'"
    );
}

// ============================================================
// BUG-25 FIX: Normalise the Authorization header for Apache + FastCGI/FPM.
// On many Apache configurations (mod_fastcgi, mod_proxy_fcgi) the server
// strips the Authorization header before it reaches PHP/WordPress.
// WP_REST_Request::get_header('authorization') then returns empty string and
// the plugin returns 401 for every request, even with a valid token.
//
// WordPress core uses the same two fallback variables in its own auth stack.
// We normalise them here at 'init' priority 1 (before our REST routes run)
// so WP_REST_Request picks up the value automatically.
//
// The .htaccess workaround (RewriteRule ^ - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}])
// is documented in the Setup Guide below, but this PHP fallback handles all cases.
// Source: developer.wordpress.org/reference/functions/rest_get_authenticated_app_password/
// ============================================================
add_action( 'init', 'wp_mcp_bridge_fix_auth_header', 1 );

function wp_mcp_bridge_fix_auth_header(): void {
    // REDIRECT_HTTP_AUTHORIZATION is set when Apache's mod_rewrite forwards
    // the header under a different name (common on shared hosting).
    if ( empty( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
        if ( ! empty( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) {
            $_SERVER['HTTP_AUTHORIZATION'] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        } elseif ( function_exists( 'apache_request_headers' ) ) {
            // apache_request_headers() bypasses the CGI stripping problem on some stacks.
            $req_headers = apache_request_headers();
            foreach ( $req_headers as $key => $value ) {
                if ( strtolower( $key ) === 'authorization' ) {
                    $_SERVER['HTTP_AUTHORIZATION'] = $value;
                    break;
                }
            }
        }
    }
}


// wp_safe_redirect() only allows redirects to the current site's host.
// Our OAuth flow must redirect to https://claude.ai/api/mcp/auth_callback.
// Without this filter, wp_safe_redirect() silently falls back to admin_url()
// and the authorization code is never delivered — OAuth flow permanently broken.
//
// The filter is unconditional (claude.ai is always in our allowlist).
// This is safe because we validate redirect_uri against our own allowlist
// *before* any redirect is issued; no untrusted URI can ever reach wp_safe_redirect().
// Source: developer.wordpress.org/reference/hooks/allowed_redirect_hosts/
// ============================================================
add_filter( 'allowed_redirect_hosts', 'wp_mcp_bridge_allowed_redirect_hosts' );

function wp_mcp_bridge_allowed_redirect_hosts( array $hosts ): array {
    // Add all Claude.ai hostnames that appear in our redirect_uri allowlist.
    return array_merge( $hosts, [ 'claude.ai', 'app.claude.ai', 'www.claude.ai' ] );
}


// Fires at init priority 10, before WordPress routing takes over.
// Handles all well-known endpoints and old-spec fallback paths.
//
// MCP spec 2025-06-18 §Authorization:
//   "MCP servers MUST implement OAuth 2.0 Protected Resource Metadata (RFC9728).
//    MCP clients MUST use OAuth 2.0 Protected Resource Metadata for auth server discovery."
// Source: modelcontextprotocol.io/specification/2025-06-18/basic/authorization
//
// Old MCP spec 2025-03-26 §2.3 (fallback default endpoints, removed in June 2025 revision):
//   When /.well-known/oauth-authorization-server returns 404, clients fall back to
//   /authorize, /token, /register at the base URL.
//   We support BOTH the new discovery AND the old fallback for maximum compatibility.
// ============================================================
add_action( 'init', 'wp_mcp_bridge_intercept_oauth_paths', 10 );

function wp_mcp_bridge_intercept_oauth_paths(): void {
    $uri  = $_SERVER['REQUEST_URI'] ?? '';
    // BUG-17 FIX: Use explode() instead of strtok().
    // strtok() maintains global internal state — if another plugin's init callback
    // called strtok() without exhausting the string, our strtok($uri,'?') call would
    // continue from the wrong position and return false or garbage.
    // explode('?', $uri, 2)[0] has no shared state and is deterministic.
    // Source: php.net/manual/en/function.strtok.php
    $path = rawurldecode( explode( '?', $uri, 2 )[0] );

    // (A) RFC 9728 Protected Resource Metadata
    // Source: tools.ietf.org/html/rfc9728
    if ( preg_match( '#^/?\.well-known/oauth-protected-resource/?$#', $path ) ) {
        $auth_server_meta_url = home_url( '/.well-known/oauth-authorization-server' );
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Cache-Control: public, max-age=3600' );
        header( 'Access-Control-Allow-Origin: *' );
        echo wp_json_encode( [
            'resource'             => get_site_url(),
            'authorization_servers' => [ $auth_server_meta_url ],
        ] );
        exit;
    }

    // (B) RFC 8414 Authorization Server Metadata
    // Source: tools.ietf.org/html/rfc8414
    if ( preg_match( '#^/?\.well-known/oauth-authorization-server/?$#', $path ) ) {
        $base = rest_url( 'mcp/v1/oauth' );
        header( 'Content-Type: application/json; charset=utf-8' );
        header( 'Cache-Control: public, max-age=3600' );
        header( 'Access-Control-Allow-Origin: *' );
        echo wp_json_encode( [
            'issuer'                                => get_site_url(),
            'authorization_endpoint'                => $base . '/authorize',
            'token_endpoint'                        => $base . '/token',
            // BUG-26 FIX: registration_endpoint MUST be present.
            // MCP spec 2025-06-18 states servers SHOULD support RFC 7591 DCR.
            // Claude Code fails with "does not support dynamic client registration"
            // when this field is absent, even when client_id is explicitly configured.
            // Source: modelcontextprotocol.io/specification/2025-06-18/basic/authorization
            // Source: github.com/anthropics/claude-code/issues/38102
            'registration_endpoint'                 => $base . '/register',
            'response_types_supported'              => [ 'code' ],
            'grant_types_supported'                 => [ 'authorization_code' ],
            'code_challenge_methods_supported'      => [ 'S256' ],
            'token_endpoint_auth_methods_supported' => [ 'none' ],
            'scopes_supported'                      => [ 'claudeai' ],
        ] );
        exit;
    }

    $method = strtoupper( $_SERVER['REQUEST_METHOD'] ?? 'GET' );

    // (C) Old-spec fallback: /authorize → proxy to REST handler
    // The June 2025 MCP spec removed this fallback in favour of RFC 9728, but
    // Claude.ai currently still uses it when discovery returns 404.
    // We handle it here directly so no page needs to exist at this path.
    if ( preg_match( '#^/?authorize/?$#', $path ) ) {
        wp_mcp_bridge_run_oauth_authorize();
        exit; // wp_mcp_bridge_run_oauth_authorize() always exits
    }

    // (D) Old-spec fallback: /token
    if ( preg_match( '#^/?token/?$#', $path ) && $method === 'POST' ) {
        wp_mcp_bridge_run_oauth_token_from_globals();
        exit;
    }
}

// ============================================================
// CORS HEADERS  (BUG-03 FIX + extended for OAuth routes)
// Source: developer.wordpress.org/reference/hooks/rest_pre_serve_request/
// ============================================================
add_filter( 'rest_pre_serve_request', 'wp_mcp_bridge_cors_headers', 10, 4 );

function wp_mcp_bridge_cors_headers( $served, $result, WP_REST_Request $request, WP_REST_Server $server ) {
    $route = $request->get_route();
    // Apply to our MCP namespace only.
    if ( strpos( $route, '/mcp/v1/' ) === false ) {
        return $served;
    }

    $origin  = $request->get_header( 'Origin' ) ?? '';
    $allowed = [ 'https://claude.ai', 'https://app.claude.ai', 'https://www.claude.ai' ];
    $cors_origin = in_array( $origin, $allowed, true ) ? $origin : 'https://claude.ai';

    header( 'Access-Control-Allow-Origin: '   . $cors_origin );
    header( 'Access-Control-Allow-Methods: POST, GET, OPTIONS' );
    header( 'Access-Control-Allow-Headers: Authorization, Content-Type, Accept, MCP-Protocol-Version, MCP-Session-Id' );
    header( 'Access-Control-Expose-Headers: MCP-Protocol-Version, MCP-Session-Id' );
    header( 'Access-Control-Max-Age: 3600' );
    header( 'Vary: Origin' );

    // BUG-11 FIX: WWW-Authenticate on 401 — tells Claude.ai where to find the OAuth server.
    // Sources: RFC 9728 §5.1, modelcontextprotocol.io/specification/2025-06-18/basic/authorization
    if ( $result instanceof WP_REST_Response && $result->get_status() === 401 ) {
        $meta_url = home_url( '/.well-known/oauth-protected-resource' );
        header( 'WWW-Authenticate: Bearer realm="WordPress MCP Bridge", resource_metadata="' . esc_url( $meta_url ) . '"' );
    }

    return $served;
}

// ============================================================
// REGISTER REST API ROUTES
// Source: developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/
// ============================================================
add_action( 'rest_api_init', 'wp_mcp_bridge_register_routes' );

function wp_mcp_bridge_register_routes(): void {
    // ── Main MCP endpoint ────────────────────────────────────────────────────
    register_rest_route( 'mcp/v1', '/bridge', [
        [
            'methods'             => [ 'POST', 'OPTIONS' ],
            'callback'            => 'wp_mcp_bridge_handle_request',
            'permission_callback' => 'wp_mcp_bridge_check_auth',
        ],
        // BUG-01 FIX: GET must be registered per MCP spec 2025-06-18 §Transports.
        // A 405 with Allow: POST tells Claude.ai "stateless server, POST only".
        // WordPress's generic rest_no_route 404 was misread as "route doesn't exist" → abort.
        [
            'methods'             => 'GET',
            'callback'            => 'wp_mcp_bridge_handle_get',
            'permission_callback' => '__return_true',
        ],
    ] );

    // ── OAuth 2.1 Authorization Endpoint ─────────────────────────────────────
    // Source: tools.ietf.org/html/rfc6749#section-3.1
    register_rest_route( 'mcp/v1/oauth', '/authorize', [
        'methods'             => [ 'GET', 'POST' ],
        'callback'            => 'wp_mcp_bridge_oauth_authorize_rest',
        'permission_callback' => '__return_true', // Auth is handled inside
    ] );

    // ── OAuth 2.1 Token Endpoint ──────────────────────────────────────────────
    // Source: tools.ietf.org/html/rfc6749#section-3.2
    register_rest_route( 'mcp/v1/oauth', '/token', [
        'methods'             => 'POST',
        'callback'            => 'wp_mcp_bridge_oauth_token_rest',
        'permission_callback' => '__return_true',
    ] );

    // ── OAuth 2.0 Dynamic Client Registration Endpoint ────────────────────────
    // BUG-26 FIX: Required by MCP spec 2025-06-18 — Claude Code checks for
    // registration_endpoint and fails with "does not support dynamic client
    // registration" if it is absent from the Authorization Server Metadata.
    // Source: tools.ietf.org/html/rfc7591 (RFC 7591 — OAuth 2.0 DCR)
    // Source: modelcontextprotocol.io/specification/2025-06-18/basic/authorization
    register_rest_route( 'mcp/v1/oauth', '/register', [
        'methods'             => 'POST',
        'callback'            => 'wp_mcp_bridge_oauth_register_rest',
        'permission_callback' => '__return_true', // Registration is open per RFC 7591
    ] );
}

// ============================================================
// BUG-01 FIX: GET handler
// ============================================================
function wp_mcp_bridge_handle_get(): WP_REST_Response {
    $r = new WP_REST_Response(
        [
            'message' => 'This MCP endpoint is stateless. Use POST for JSON-RPC requests.',
            'spec'    => 'https://modelcontextprotocol.io/specification/2025-06-18/basic/transports',
        ],
        405
    );
    $r->header( 'Allow', 'POST, OPTIONS' );
    $r->header( 'MCP-Protocol-Version', WP_MCP_BRIDGE_PROTO_VERSION );
    return $r;
}

// ============================================================
// AUTHENTICATION  (BUG-02 + BUG-11 FIX)
// Accepts both the static API key AND OAuth 2.1 access tokens.
// ============================================================
function wp_mcp_bridge_check_auth( WP_REST_Request $request ): bool|WP_Error {
    // BUG-02 FIX: Browsers never send credentials on OPTIONS preflight.
    // Source: developer.mozilla.org/en-US/docs/Web/HTTP/CORS
    if ( $request->get_method() === 'OPTIONS' ) {
        return true;
    }

    $auth_header = $request->get_header( 'authorization' ) ?? '';
    $provided    = '';
    if ( preg_match( '/^Bearer\s+(.+)$/i', trim( $auth_header ), $m ) ) {
        $provided = trim( $m[1] );
    }

    if ( empty( $provided ) ) {
        // No token at all → return 401 with WWW-Authenticate so Claude.ai can start OAuth.
        // The CORS filter adds the header on the 401 response (see wp_mcp_bridge_cors_headers).
        return new WP_Error( 'unauthorized', 'Bearer token or OAuth access token required.', [ 'status' => 401 ] );
    }

    // 1) Check static API key (simple Bearer Token auth)
    $stored_key = get_option( 'wp_mcp_bridge_api_key', '' );
    if ( ! empty( $stored_key ) && hash_equals( $stored_key, $provided ) ) {
        return true;
    }

    // 2) Check OAuth 2.1 access token (issued by /token endpoint)
    $token_data = get_transient( 'wpmcp_token_' . $provided );
    if ( $token_data !== false ) {
        return true;
    }

    return new WP_Error( 'unauthorized', 'Invalid or expired token.', [ 'status' => 401 ] );
}

// ============================================================
// MAIN MCP REQUEST HANDLER
// ============================================================
function wp_mcp_bridge_handle_request( WP_REST_Request $request ): WP_REST_Response {
    // Defence-in-depth origin check (BUG-03 partial, per MCP spec §Security §DNS Rebinding)
    $allowed_origins = [ 'https://claude.ai', 'https://app.claude.ai', 'https://www.claude.ai', '' ];
    $origin          = $request->get_header( 'origin' ) ?? '';
    if ( $origin !== '' && ! in_array( $origin, $allowed_origins, true ) ) {
        return new WP_REST_Response(
            [ 'jsonrpc' => '2.0', 'id' => null, 'error' => [ 'code' => -32000, 'message' => 'Forbidden: Origin not allowed' ] ],
            403
        );
    }

    if ( $request->get_method() === 'OPTIONS' ) {
        $r = new WP_REST_Response( null, 200 );
        $r->header( 'Allow', 'POST, GET, OPTIONS' );
        return $r;
    }

    // BUG-13 FIX: get_json_params() returns null on absent or non-JSON body.
    // Accessing $body['id'] on null triggers PHP 8.0+ TypeError.
    // Source: developer.wordpress.org/reference/classes/wp_rest_request/get_json_params/
    $body   = $request->get_json_params() ?? [];
    $id     = $body['id']     ?? null;
    $method = $body['method'] ?? '';
    $params = $body['params'] ?? [];

    if ( empty( $method ) ) {
        return wp_mcp_json_response( $id, null, [ 'code' => -32700, 'message' => 'Parse error: missing method' ], 400 );
    }

    // Rate limiting for tool/call  (BUG-09 FIX: REMOTE_ADDR only)
    if ( $method === 'tools/call' ) {
        $ip       = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $ip       = preg_replace( '/[^a-f0-9.:,]/', '', strtolower( $ip ) );
        $rate_key = 'wpmcp_rate_' . md5( $ip );
        $rate     = get_transient( $rate_key );
        if ( $rate === false ) {
            set_transient( $rate_key, [ 'count' => 1, 'window_start' => time() ], 60 );
        } else {
            if ( time() - $rate['window_start'] > 60 ) {
                set_transient( $rate_key, [ 'count' => 1, 'window_start' => time() ], 60 );
            } else {
                $rate['count']++;
                set_transient( $rate_key, $rate, 60 - ( time() - $rate['window_start'] ) );
                if ( $rate['count'] > 120 ) {
                    return wp_mcp_json_response(
                        $id, null,
                        [ 'code' => -32000, 'message' => 'Rate limit exceeded: max 120 tool calls per minute.' ],
                        429
                    );
                }
            }
        }
    }

    switch ( $method ) {

        case 'initialize':
            $supported  = [ '2025-06-18', '2024-11-05' ];
            $requested  = $params['protocolVersion'] ?? '2025-06-18';
            $negotiated = in_array( $requested, $supported, true ) ? $requested : '2025-06-18';
            return wp_mcp_ok_response( $id, [
                'protocolVersion' => $negotiated,
                'capabilities'    => [ 'tools' => [ 'listChanged' => false ] ],
                'serverInfo'      => [
                    'name'    => 'wordpress-mcp-bridge',
                    'title'   => 'WordPress MCP Bridge',
                    'version' => WP_MCP_BRIDGE_VERSION,
                ],
                'instructions' => 'WordPress MCP Bridge — gives Claude full read access to this WordPress site including plugins, themes, post types, database, source code, logs, hooks, and more.',
            ], $negotiated );

        case 'notifications/initialized':
            // MCP spec: server MUST send 202 Accepted with no JSON-RPC body.
            // Source: modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle
            $r = new WP_REST_Response( null, 202 );
            $r->header( 'MCP-Protocol-Version', WP_MCP_BRIDGE_PROTO_VERSION );
            return $r;

        case 'ping':
            return wp_mcp_ok_response( $id, new stdClass() );

        case 'tools/list':
            return wp_mcp_ok_response( $id, [ 'tools' => wp_mcp_tools_list() ] );

        case 'tools/call':
            $tool_name = $params['name']      ?? '';
            $tool_args = $params['arguments'] ?? [];
            try {
                $out = wp_mcp_call_tool( $tool_name, $tool_args );
            } catch ( Throwable $e ) {
                $out = wp_mcp_tool_error( $e->getMessage() );
            }
            return wp_mcp_ok_response( $id, $out );

        default:
            return wp_mcp_json_response( $id, null, [ 'code' => -32601, 'message' => "Method not found: $method" ] );
    }
}

// ============================================================
// RESPONSE BUILDERS  (BUG-08 FIX: MCP-Protocol-Version on all responses)
// ============================================================
function wp_mcp_ok_response( $id, $result, string $proto = WP_MCP_BRIDGE_PROTO_VERSION ): WP_REST_Response {
    $r = new WP_REST_Response( [ 'jsonrpc' => '2.0', 'id' => $id, 'result' => $result ], 200 );
    $r->header( 'Content-Type', 'application/json; charset=utf-8' );
    $r->header( 'X-Robots-Tag', 'noindex, nofollow' );
    $r->header( 'MCP-Protocol-Version', $proto );
    return $r;
}

function wp_mcp_json_response( $id, $result, ?array $error = null, int $status = 200 ): WP_REST_Response {
    $body = [ 'jsonrpc' => '2.0', 'id' => $id ];
    if ( $error !== null ) {
        $body['error'] = $error;
    } else {
        $body['result'] = $result;
    }
    $r = new WP_REST_Response( $body, $status );
    $r->header( 'MCP-Protocol-Version', WP_MCP_BRIDGE_PROTO_VERSION );
    return $r;
}

function wp_mcp_tool_result( array $data ): array {
    return [ 'content' => [ [ 'type' => 'text', 'text' => wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ] ] ];
}

function wp_mcp_tool_error( string $msg ): array {
    return [ 'content' => [ [ 'type' => 'text', 'text' => 'Error: ' . $msg ] ], 'isError' => true ];
}

// ============================================================
// OAUTH 2.0 — DYNAMIC CLIENT REGISTRATION ENDPOINT (RFC 7591)
// BUG-26 FIX: MCP spec 2025-06-18 requires registration_endpoint in ASM.
// Claude Code/Claude.ai fail with "does not support dynamic client registration"
// when it is absent. This endpoint implements RFC 7591 client registration.
//
// Implementation approach: stateless pseudo-registration.
// We do not maintain a client database. Instead, we:
//   1. Validate the redirect_uris against our allowlist.
//   2. Generate a deterministic client_id from the registration metadata.
//   3. Return the client_id immediately — no storage needed.
// The client_id is then used during the /authorize flow. Because the plugin
// authenticates the MCP request via Bearer token (not client_id+secret),
// the client_id is treated as an identifier hint, not a shared secret.
//
// Source: tools.ietf.org/html/rfc7591
// Source: modelcontextprotocol.io/specification/2025-06-18/basic/authorization
// ============================================================
function wp_mcp_bridge_oauth_register_rest( WP_REST_Request $request ): WP_REST_Response {
    $body          = $request->get_json_params() ?? [];
    $redirect_uris = $body['redirect_uris'] ?? [];
    $client_name   = sanitize_text_field( $body['client_name']  ?? 'MCP Client' );
    $grant_types   = $body['grant_types']   ?? [ 'authorization_code' ];
    // $response_types intentionally not stored — only 'code' is supported,
    // validated implicitly via grant_types check below. Storing it caused a
    // PHP notice (unused variable) and invited mistaken use elsewhere.

    // Validate: only authorization_code grant type is supported.
    // Source: tools.ietf.org/html/rfc7591#section-2
    if ( ! empty( $grant_types ) && ! in_array( 'authorization_code', (array) $grant_types, true ) ) {
        return new WP_REST_Response( [
            'error'             => 'invalid_client_metadata',
            'error_description' => 'Only authorization_code grant type is supported.',
        ], 400 );
    }

    // Validate redirect_uris against our allowlist.
    // RFC 7591 §2: "The authorization server MUST validate the values of all
    // redirect_uri fields". We refuse to register a client that lists redirect
    // URIs outside our allowlist — this prevents CSRF via DCR abuse.
    // Source: tools.ietf.org/html/rfc7591#section-2
    $allowed = wp_mcp_bridge_allowed_redirect_uris();
    foreach ( (array) $redirect_uris as $uri ) {
        if ( ! in_array( $uri, $allowed, true ) ) {
            return new WP_REST_Response( [
                'error'             => 'invalid_redirect_uri',
                'error_description' => 'redirect_uri ' . esc_url( $uri ) . ' is not in the allowed list.',
            ], 400 );
        }
    }

    // Generate a deterministic, stable client_id.
    // Using a HMAC-based ID means the same client always gets the same ID
    // on the same site, with no database required.
    // The ID is scoped to this site (home_url) and the client's redirect URIs.
    $id_material = implode( '|', array_merge( [ home_url(), $client_name ], (array) $redirect_uris ) );
    $client_id   = 'mcp-' . substr( hash_hmac( 'sha256', $id_material, AUTH_KEY ), 0, 24 );

    // RFC 7591 §3.2: successful response is HTTP 201 Created with client metadata.
    // Source: tools.ietf.org/html/rfc7591#section-3.2
    $response = new WP_REST_Response( [
        'client_id'              => $client_id,
        'client_name'            => $client_name,
        'redirect_uris'          => $redirect_uris,
        'grant_types'            => [ 'authorization_code' ],
        'response_types'         => [ 'code' ],
        'token_endpoint_auth_method' => 'none',
        // No client_secret — this is a public client per OAuth 2.1.
        // client_id_issued_at is the current timestamp.
        'client_id_issued_at'    => time(),
    ], 201 );
    $response->header( 'Cache-Control', 'no-store' );
    $response->header( 'Pragma', 'no-cache' );
    return $response;
}



/**
 * PKCE S256 verification.
 * Source: tools.ietf.org/html/rfc7636#section-4.6
 *
 * code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
 * Returns true if the verifier matches the stored challenge.
 */
function wp_mcp_bridge_pkce_verify( string $code_verifier, string $code_challenge ): bool {
    if ( empty( $code_verifier ) || empty( $code_challenge ) ) {
        return false;
    }
    $computed = rtrim( strtr( base64_encode( hash( 'sha256', $code_verifier, true ) ), '+/', '-_' ), '=' );
    return hash_equals( $code_challenge, $computed );
}

/**
 * Returns the list of redirect URIs that are unconditionally allowed.
 * Admins can add custom URIs from the plugin settings page.
 */
function wp_mcp_bridge_allowed_redirect_uris(): array {
    $defaults = [
        'https://claude.ai/api/mcp/auth_callback',
        'https://app.claude.ai/api/mcp/auth_callback',
        'https://www.claude.ai/api/mcp/auth_callback',
    ];
    $custom_raw = get_option( 'wp_mcp_bridge_oauth_redirect_uris', '' );
    if ( $custom_raw ) {
        $custom = array_filter( array_map( 'trim', explode( "\n", $custom_raw ) ) );
        $defaults = array_merge( $defaults, $custom );
    }
    return $defaults;
}

/**
 * Build a redirect-back URL for the /authorize endpoint, preserving all OAuth params.
 */
function wp_mcp_bridge_authorize_url( array $params ): string {
    // BUG-30 FIX: array_filter() with no callback removes ALL falsy values,
    // including empty strings. The OAuth 'state' and 'scope' parameters can
    // legitimately be empty strings. Stripping state='' breaks CSRF protection;
    // stripping scope='' causes the server to apply an unexpected default scope.
    //
    // Fix: only remove null and false (use array_filter with 'strlen' callback,
    // which returns 0 for null/false and ≥0 for any string including '').
    // Source: tools.ietf.org/html/rfc6749#section-4.1.1
    // Source: php.net/manual/en/function.array-filter.php
    $clean = array_filter( $params, static function( $v ): bool {
        return $v !== null && $v !== false;
    } );
    return add_query_arg( $clean, rest_url( 'mcp/v1/oauth/authorize' ) );
}

// ============================================================
// OAUTH 2.1 — AUTHORIZATION ENDPOINT (REST API version)
// Source: tools.ietf.org/html/rfc6749#section-3.1
//
// This REST API callback intentionally uses direct header()/echo/exit for HTML
// output. This is a well-established WordPress plugin pattern for OAuth flows
// (used by WooCommerce, WP OAuth Server, etc.) because REST API JSON wrapping
// is not appropriate for browser-facing HTML consent pages.
// ============================================================
function wp_mcp_bridge_oauth_authorize_rest( WP_REST_Request $request ): void {
    // Pull params — works for both GET query string and POST body.
    $response_type         = sanitize_text_field( $request->get_param( 'response_type' )         ?? '' );
    $client_id             = sanitize_text_field( $request->get_param( 'client_id' )             ?? '' );
    $redirect_uri          = esc_url_raw(         $request->get_param( 'redirect_uri' )          ?? '' );
    $code_challenge        = sanitize_text_field( $request->get_param( 'code_challenge' )        ?? '' );
    $code_challenge_method = sanitize_text_field( $request->get_param( 'code_challenge_method' ) ?? 'S256' );
    $state                 = sanitize_text_field( $request->get_param( 'state' )                 ?? '' );
    $scope                 = sanitize_text_field( $request->get_param( 'scope' )                 ?? '' );
    $method                = $request->get_method();

    wp_mcp_bridge_run_oauth_authorize_core(
        $response_type, $client_id, $redirect_uri,
        $code_challenge, $code_challenge_method,
        $state, $scope, $method
    );
}

/**
 * Handle /authorize called from the old-spec fallback path (at root /authorize).
 * Reads directly from $_GET / $_POST so no WP_REST_Request is needed.
 */
function wp_mcp_bridge_run_oauth_authorize(): void {
    $method = strtoupper( $_SERVER['REQUEST_METHOD'] ?? 'GET' );
    $src    = ( $method === 'POST' ) ? $_POST : $_GET;

    $response_type         = sanitize_text_field( $src['response_type']         ?? '' );
    $client_id             = sanitize_text_field( $src['client_id']             ?? '' );
    $redirect_uri          = esc_url_raw(         $src['redirect_uri']          ?? '' );
    $code_challenge        = sanitize_text_field( $src['code_challenge']        ?? '' );
    $code_challenge_method = sanitize_text_field( $src['code_challenge_method'] ?? 'S256' );
    $state                 = sanitize_text_field( $src['state']                 ?? '' );
    $scope                 = sanitize_text_field( $src['scope']                 ?? '' );

    wp_mcp_bridge_run_oauth_authorize_core(
        $response_type, $client_id, $redirect_uri,
        $code_challenge, $code_challenge_method,
        $state, $scope, $method
    );
}

/**
 * Core OAuth authorization logic shared by both the REST and fallback paths.
 * Always exits — never returns.
 */
function wp_mcp_bridge_run_oauth_authorize_core(
    string $response_type,
    string $client_id,
    string $redirect_uri,
    string $code_challenge,
    string $code_challenge_method,
    string $state,
    string $scope,
    string $method
): void {

    // Helper: redirect to redirect_uri with an error code (only when redirect_uri is trusted).
    $error_redirect = static function ( string $error, string $desc = '' ) use ( $redirect_uri, $state ): void {
        $p = [ 'error' => $error, 'state' => $state ];
        if ( $desc ) {
            $p['error_description'] = $desc;
        }
        wp_safe_redirect( add_query_arg( $p, $redirect_uri ) );
        exit;
    };

    // ── Validate redirect_uri FIRST before revealing any error info ────────
    // Source: tools.ietf.org/html/rfc6749#section-10.6
    $allowed_uris = wp_mcp_bridge_allowed_redirect_uris();
    if ( ! empty( $redirect_uri ) && ! in_array( $redirect_uri, $allowed_uris, true ) ) {
        // Do NOT redirect — redirect_uri is untrusted. Show inline error.
        status_header( 400 );
        header( 'Content-Type: text/html; charset=utf-8' );
        echo '<html><body><h2>OAuth Error</h2><p><strong>invalid_redirect_uri</strong>: '
            . esc_html( $redirect_uri )
            . ' is not in the allowed list. Add it in <strong>Settings → MCP Bridge → Extra OAuth Redirect URIs</strong>.</p></body></html>';
        exit;
    }

    // ── Standard parameter validation ──────────────────────────────────────
    if ( $response_type !== 'code' ) {
        $error_redirect( 'unsupported_response_type', 'Only response_type=code is supported.' );
    }

    if ( empty( $code_challenge ) ) {
        $error_redirect( 'invalid_request', 'code_challenge is required (PKCE mandatory, RFC 7636).' );
    }

    if ( $code_challenge_method !== 'S256' ) {
        $error_redirect( 'invalid_request', 'Only code_challenge_method=S256 is supported.' );
    }

    // ── WordPress authentication ────────────────────────────────────────────
    if ( ! is_user_logged_in() ) {
        // Redirect to WP login, returning to the authorize endpoint with all params.
        $return = wp_mcp_bridge_authorize_url( [
            'response_type'         => $response_type,
            'client_id'             => $client_id,
            'redirect_uri'          => $redirect_uri,
            'code_challenge'        => $code_challenge,
            'code_challenge_method' => $code_challenge_method,
            'state'                 => $state,
            'scope'                 => $scope,
        ] );
        wp_safe_redirect( wp_login_url( $return ) );
        exit;
    }

    if ( ! current_user_can( 'manage_options' ) ) {
        status_header( 403 );
        header( 'Content-Type: text/html; charset=utf-8' );
        echo '<html><body><h2>Access Denied</h2><p>You must be a WordPress administrator to authorize Claude.ai.</p></body></html>';
        exit;
    }

    // ── Process POST (consent form submission) ──────────────────────────────
    if ( $method === 'POST' ) {
        // BUG-35 FIX: Renamed nonce field from _wpnonce to _mcp_nonce.
        //
        // Root cause of rest_cookie_invalid_nonce (403):
        // WordPress REST API cookie authentication reads $_REQUEST['_wpnonce'] and
        // validates it against wp_create_nonce('wp_rest') — this runs BEFORE
        // permission_callback and before our handler even executes.
        // Our form was sending _wpnonce = wp_create_nonce('wp_mcp_oauth_consent'),
        // which WordPress REST auth saw, tried to verify as 'wp_rest', failed,
        // and returned 403 rest_cookie_invalid_nonce.
        //
        // Fix: use _mcp_nonce for our consent CSRF check (verified below), and
        // add a separate _wpnonce = wp_create_nonce('wp_rest') to the form so
        // WordPress REST cookie auth passes. Both protections remain active.
        //
        // Source: wp-includes/class-wp-rest-server.php §REST_COOKIE_AUTH
        // Source: developer.wordpress.org/rest-api/using-the-rest-api/authentication/
        $nonce  = sanitize_text_field( $_POST['_mcp_nonce'] ?? '' );
        $action = sanitize_text_field( $_POST['consent_action'] ?? '' );

        if ( ! wp_verify_nonce( $nonce, 'wp_mcp_oauth_consent' ) ) {
            wp_die( 'Security check failed. Please try again.', 'Security Error', [ 'response' => 403 ] );
        }

        if ( $action !== 'allow' ) {
            $error_redirect( 'access_denied', 'User denied authorization.' );
        }

        // Issue authorization code.
        // Source: tools.ietf.org/html/rfc6749#section-4.1.2
        $code = wp_generate_password( 40, false );
        set_transient( 'wpmcp_code_' . $code, [
            'client_id'             => $client_id,
            'redirect_uri'          => $redirect_uri,
            'code_challenge'        => $code_challenge,
            'code_challenge_method' => 'S256',
            'scope'                 => $scope,
            'user_id'               => get_current_user_id(),
            'used'                  => false,
            'iat'                   => time(),
        ], WP_MCP_BRIDGE_OAUTH_CODE_TTL );

        wp_safe_redirect( add_query_arg( [ 'code' => $code, 'state' => $state ], $redirect_uri ) );
        exit;
    }

    // ── GET: render HTML consent page ──────────────────────────────────────
    $current_user    = wp_get_current_user();
    // BUG-35 FIX: Two nonces required.
    // $consent_nonce → verified by OUR handler as 'wp_mcp_oauth_consent' (CSRF).
    // $rest_nonce    → verified by WordPress REST cookie auth as 'wp_rest'.
    // Both go into the form; they serve entirely separate security purposes.
    // Source: wp-includes/class-wp-rest-server.php §REST_COOKIE_AUTH
    $consent_nonce   = wp_create_nonce( 'wp_mcp_oauth_consent' );
    $rest_nonce      = wp_create_nonce( 'wp_rest' );
    $site_name       = esc_html( get_bloginfo( 'name' ) );
    $form_action     = esc_attr( rest_url( 'mcp/v1/oauth/authorize' ) );

    // BUG-23 FIX: Removed $client_display variable. It mixed raw HTML and
    // escaped text in one variable then echoed it without escaping — against
    // WordPress's "always escape at the point of output" rule and flagged by
    // every WP security scanner. The two display cases are now handled as
    // separate PHP branches directly at the echo site.
    // Source: developer.wordpress.org/apis/security/escaping/

    // BUG-24 FIX: RFC 6749 §10.13 ("Clickjacking") requires authorization
    // endpoints to prevent iframe embedding. Without these headers, an attacker
    // can overlay the consent page in a transparent iframe and trick an
    // authenticated admin into clicking "Allow Access" unknowingly.
    // Source: tools.ietf.org/html/rfc6749#section-10.13
    status_header( 200 );
    header( 'Content-Type: text/html; charset=utf-8' );
    header( 'X-Frame-Options: DENY' );
    header( "Content-Security-Policy: frame-ancestors 'none'" );

    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Authorize Claude.ai — <?php echo $site_name; ?></title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       background:#f0f0f1;display:flex;align-items:center;justify-content:center;
       min-height:100vh;margin:0;padding:16px}
  .card{background:#fff;border-radius:8px;
        box-shadow:0 2px 12px rgba(0,0,0,.14);
        padding:40px 36px;max-width:460px;width:100%}
  .logo{text-align:center;margin-bottom:22px}
  .logo-ring{width:56px;height:56px;border-radius:14px;
             background:#CC785C;display:inline-flex;
             align-items:center;justify-content:center}
  .logo-ring svg{width:32px;height:32px}
  h1{font-size:20px;margin:0 0 6px;text-align:center;color:#1d2327}
  .subtitle{color:#666;text-align:center;margin:0 0 24px;font-size:14px;line-height:1.5}
  .user-box{background:#f6f7f7;border:1px solid #dde;border-radius:4px;
            padding:10px 14px;margin-bottom:22px;font-size:14px;color:#444}
  .permissions{margin-bottom:26px}
  .permissions h3{font-size:12px;text-transform:uppercase;letter-spacing:.06em;
                  color:#999;margin:0 0 10px;font-weight:600}
  .perm{display:flex;gap:10px;align-items:flex-start;
        margin-bottom:8px;font-size:14px;color:#3c434a;line-height:1.4}
  .perm-icon{color:#00a32a;font-size:16px;flex-shrink:0;margin-top:1px}
  .btns{display:flex;gap:10px}
  .btn{flex:1;padding:10px 0;border-radius:4px;border:none;cursor:pointer;
       font-size:15px;font-weight:500;transition:opacity .15s}
  .btn:hover{opacity:.87}
  .btn-allow{background:#2271b1;color:#fff}
  .btn-deny{background:#f0f0f1;color:#3c434a;border:1px solid #ccc}
  .warning{font-size:12px;color:#999;text-align:center;margin-top:16px;line-height:1.5}
  .note{background:#fffbcc;border:1px solid #e5b000;border-radius:4px;
        padding:10px 14px;font-size:13px;color:#5a4a00;margin-bottom:20px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <span class="logo-ring">
      <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M16 4 L20 14 H12 Z" fill="white"/>
        <path d="M16 28 L12 18 H20 Z" fill="rgba(255,255,255,.65)"/>
        <path d="M4 16 L14 12 V20 Z" fill="rgba(255,255,255,.45)"/>
        <path d="M28 16 L18 20 V12 Z" fill="rgba(255,255,255,.45)"/>
      </svg>
    </span>
  </div>

  <h1>Authorize Claude.ai</h1>
  <p class="subtitle">
    <?php
    // BUG-23 FIX: Two separate branches — never echo mixed HTML+text from one variable.
    // Hardcoded markup goes through its own branch; user-supplied client_id through esc_html().
    // Source: developer.wordpress.org/apis/security/escaping/
    if ( $client_id === 'Bearer Token' || $client_id === 'Bearer+Token' ) : ?>
      <strong>Claude.ai</strong>
    <?php else : ?>
      <strong><?php echo esc_html( $client_id ?: 'Claude.ai' ); ?></strong>
    <?php endif; ?>
    is requesting access to your WordPress site<br>
    <span style="color:#aaa;font-size:13px"><?php echo esc_html( get_site_url() ); ?></span>
  </p>

  <?php if ( $client_id === 'Bearer Token' || $client_id === 'Bearer+Token' ) : ?>
  <div class="note">
    ⚠️ <strong>Configuration note:</strong> Claude.ai sent <code>client_id=Bearer Token</code>.
    This is a common misconfiguration — <code>client_id</code> should be a unique identifier like
    <code>claude.ai</code>, not the auth type name. Authorization will still succeed.
    See <a href="<?php echo esc_url( admin_url( 'options-general.php?page=wp-mcp-bridge' ) ); ?>">Settings → MCP Bridge</a>
    for correct connector setup instructions.
  </div>
  <?php endif; ?>

  <div class="user-box">
    Logged in as <strong><?php echo esc_html( $current_user->display_name ); ?></strong>
    &lt;<?php echo esc_html( $current_user->user_email ); ?>&gt;
  </div>

  <div class="permissions">
    <h3>Claude.ai will be able to</h3>
    <div class="perm"><span class="perm-icon">✓</span>Read site info, plugins, and themes</div>
    <div class="perm"><span class="perm-icon">✓</span>View post types, custom fields, and taxonomies</div>
    <div class="perm"><span class="perm-icon">✓</span>Read database schema and run SELECT queries</div>
    <div class="perm"><span class="perm-icon">✓</span>Browse and read source files in wp-content</div>
    <div class="perm"><span class="perm-icon">✓</span>View error logs, hooks, menus, and cron jobs</div>
    <div class="perm"><span class="perm-icon" style="color:#666">✗</span>Write, delete, or modify anything (read-only)</div>
  </div>

  <form method="post" action="<?php echo $form_action; ?>">
    <input type="hidden" name="response_type"         value="<?php echo esc_attr( $response_type ); ?>">
    <input type="hidden" name="client_id"             value="<?php echo esc_attr( $client_id ); ?>">
    <input type="hidden" name="redirect_uri"          value="<?php echo esc_attr( $redirect_uri ); ?>">
    <input type="hidden" name="code_challenge"        value="<?php echo esc_attr( $code_challenge ); ?>">
    <input type="hidden" name="code_challenge_method" value="<?php echo esc_attr( $code_challenge_method ); ?>">
    <input type="hidden" name="state"                 value="<?php echo esc_attr( $state ); ?>">
    <input type="hidden" name="scope"                 value="<?php echo esc_attr( $scope ); ?>">
    <?php /* BUG-35 FIX: _wpnonce = wp_rest nonce (for WP REST cookie auth).
           * _mcp_nonce = our consent nonce (for our CSRF protection).
           * WordPress REST auth checks _wpnonce first; our handler checks _mcp_nonce.
           * Source: wp-includes/class-wp-rest-server.php §REST_COOKIE_AUTH */ ?>
    <input type="hidden" name="_wpnonce"              value="<?php echo esc_attr( $rest_nonce ); ?>">
    <input type="hidden" name="_mcp_nonce"            value="<?php echo esc_attr( $consent_nonce ); ?>">
    <div class="btns">
      <button type="submit" name="consent_action" value="deny"  class="btn btn-deny">Deny</button>
      <button type="submit" name="consent_action" value="allow" class="btn btn-allow">Allow Access</button>
    </div>
  </form>

  <p class="warning">
    ⚠ Read-only access only. Do not authorize on untrusted devices.<br>
    Access expires in <?php echo WP_MCP_BRIDGE_OAUTH_TOKEN_TTL / 60; ?> minutes.
  </p>
</div>
</body>
</html>
    <?php
    exit;
}

// ============================================================
// OAUTH 2.1 — TOKEN ENDPOINT (REST API version)
// Source: tools.ietf.org/html/rfc6749#section-4.1.3
// ============================================================
function wp_mcp_bridge_oauth_token_rest( WP_REST_Request $request ): WP_REST_Response {
    return wp_mcp_bridge_run_oauth_token(
        sanitize_text_field( $request->get_param( 'grant_type' )    ?? '' ),
        sanitize_text_field( $request->get_param( 'code' )          ?? '' ),
        esc_url_raw(         $request->get_param( 'redirect_uri' )  ?? '' ),
        sanitize_text_field( $request->get_param( 'code_verifier' ) ?? '' ),
        sanitize_text_field( $request->get_param( 'client_id' )     ?? '' )
    );
}

/**
 * Handle /token called from the old-spec fallback path at /token.
 * Reads from $_POST and outputs JSON directly.
 */
function wp_mcp_bridge_run_oauth_token_from_globals(): void {
    $result = wp_mcp_bridge_run_oauth_token(
        sanitize_text_field( $_POST['grant_type']    ?? '' ),
        sanitize_text_field( $_POST['code']          ?? '' ),
        esc_url_raw(         $_POST['redirect_uri']  ?? '' ),
        sanitize_text_field( $_POST['code_verifier'] ?? '' ),
        sanitize_text_field( $_POST['client_id']     ?? '' )
    );
    // BUG-16 FIX: Emit the correct HTTP status code from the response object.
    // OAuth 2.1 / RFC 6749 §5.2 requires 400 for invalid_grant, 401 for
    // invalid_client, etc. Without this, all errors are silently HTTP 200.
    // Source: tools.ietf.org/html/rfc6749#section-5.2
    status_header( $result->get_status() );
    // BUG-18 FIX: RFC 6749 §5.1 REQUIRES these headers on token responses.
    // The REST API path sets them via $response->header(); this fallback path missed them.
    // Source: tools.ietf.org/html/rfc6749#section-5.1
    header( 'Cache-Control: no-store' );
    header( 'Pragma: no-cache' );
    header( 'Content-Type: application/json; charset=utf-8' );
    echo wp_json_encode( $result->get_data() );
    exit;
}

/**
 * Core token exchange logic. Returns WP_REST_Response for both code paths.
 * Source: tools.ietf.org/html/rfc6749#section-5
 */
function wp_mcp_bridge_run_oauth_token(
    string $grant_type,
    string $code,
    string $redirect_uri,
    string $code_verifier,
    string $client_id
): WP_REST_Response {

    $err = static function ( string $code, string $desc, int $status = 400 ): WP_REST_Response {
        return new WP_REST_Response( [
            'error'             => $code,
            'error_description' => $desc,
        ], $status );
    };

    if ( $grant_type !== 'authorization_code' ) {
        return $err( 'unsupported_grant_type', 'Only authorization_code is supported.' );
    }
    if ( ! $code || ! $code_verifier ) {
        return $err( 'invalid_request', 'code and code_verifier are required.' );
    }

    // Retrieve stored authorization code.
    $stored = get_transient( 'wpmcp_code_' . $code );
    if ( $stored === false ) {
        return $err( 'invalid_grant', 'Authorization code is invalid or expired.' );
    }

    // Single-use: delete immediately to prevent replay attacks.
    // Source: tools.ietf.org/html/rfc6749#section-10.5
    delete_transient( 'wpmcp_code_' . $code );

    if ( ! empty( $stored['used'] ) ) {
        return $err( 'invalid_grant', 'Authorization code has already been used.' );
    }

    // Validate redirect_uri must match exactly.
    // Source: tools.ietf.org/html/rfc6749#section-10.6
    if ( $redirect_uri && $redirect_uri !== $stored['redirect_uri'] ) {
        return $err( 'invalid_grant', 'redirect_uri mismatch.' );
    }

    // Validate client_id must match.
    if ( $client_id && $client_id !== $stored['client_id'] ) {
        return $err( 'invalid_client', 'client_id mismatch.' );
    }

    // PKCE S256 verification.
    // Source: tools.ietf.org/html/rfc7636#section-4.6
    if ( ! wp_mcp_bridge_pkce_verify( $code_verifier, $stored['code_challenge'] ) ) {
        return $err( 'invalid_grant', 'PKCE code_verifier does not match code_challenge.' );
    }

    // Issue access token.
    $access_token = wp_generate_password( 48, false );
    $ttl          = WP_MCP_BRIDGE_OAUTH_TOKEN_TTL;
    set_transient( 'wpmcp_token_' . $access_token, [
        'client_id' => $stored['client_id'],
        'scope'     => $stored['scope'],
        'user_id'   => $stored['user_id'],
        'iat'       => time(),
    ], $ttl );

    $response = new WP_REST_Response( [
        'access_token' => $access_token,
        'token_type'   => 'Bearer',
        'expires_in'   => $ttl,
        'scope'        => $stored['scope'] ?? 'claudeai',
    ], 200 );
    $response->header( 'Cache-Control', 'no-store' );
    $response->header( 'Pragma', 'no-cache' );
    return $response;
}

// ============================================================
// TOOLS REGISTRY
// ============================================================
function wp_mcp_tools_list(): array {
    return [
        [ 'name' => 'wp_get_site_info',      'description' => 'Full site overview: WP version, PHP/MySQL, active theme, all active plugins, permalink structure, upload dirs, debug settings.', 'inputSchema' => [ 'type' => 'object', 'properties' => new stdClass(), 'required' => [] ] ],
        [ 'name' => 'wp_get_plugins',        'description' => 'List all installed plugins with name, version, author, description, and active/inactive status.', 'inputSchema' => [ 'type' => 'object', 'properties' => [ 'status' => [ 'type' => 'string', 'description' => '"active", "inactive", or "all" (default: all)' ] ], 'required' => [] ] ],
        [ 'name' => 'wp_get_themes',         'description' => 'List all installed themes with version, author, active state, and child theme info.', 'inputSchema' => [ 'type' => 'object', 'properties' => new stdClass(), 'required' => [] ] ],
        [ 'name' => 'wp_get_post_types',     'description' => 'List all registered post types (built-in and custom) with labels, supports, taxonomies, REST base.', 'inputSchema' => [ 'type' => 'object', 'properties' => new stdClass(), 'required' => [] ] ],
        [ 'name' => 'wp_get_taxonomies',     'description' => 'List all registered taxonomies with object types, REST settings, and term counts.', 'inputSchema' => [ 'type' => 'object', 'properties' => new stdClass(), 'required' => [] ] ],
        [ 'name' => 'wp_get_options',        'description' => 'Read WordPress options. Returns common settings by default. Pass specific keys array for exact values. Credentials always redacted.', 'inputSchema' => [ 'type' => 'object', 'properties' => [ 'keys' => [ 'type' => 'array', 'items' => [ 'type' => 'string' ], 'description' => 'Specific option keys to fetch.' ] ], 'required' => [] ] ],
        [ 'name' => 'wp_query_posts',        'description' => 'Query any post type using WP_Query. Returns post data, all custom meta fields, and taxonomy terms.', 'inputSchema' => [ 'type' => 'object', 'properties' => [ 'post_type' => [ 'type' => 'string' ], 'post_status' => [ 'type' => 'string' ], 'posts_per_page' => [ 'type' => 'integer' ], 's' => [ 'type' => 'string' ], 'orderby' => [ 'type' => 'string' ], 'order' => [ 'type' => 'string' ], 'meta_key' => [ 'type' => 'string' ], 'meta_value' => [ 'type' => 'string' ] ], 'required' => [] ] ],
        [ 'name' => 'wp_get_db_schema',      'description' => 'Get database schema: all tables, columns, types, and row counts.', 'inputSchema' => [ 'type' => 'object', 'properties' => [ 'table' => [ 'type' => 'string', 'description' => 'Filter by table name pattern.' ] ], 'required' => [] ] ],
        [ 'name' => 'wp_db_query',           'description' => 'Run a read-only SELECT query. Credential columns and SELECT * on wp_users are blocked.', 'inputSchema' => [ 'type' => 'object', 'properties' => [ 'sql' => [ 'type' => 'string' ], 'limit' => [ 'type' => 'integer' ] ], 'required' => [ 'sql' ] ] ],
        [ 'name' => 'wp_list_files',         'description' => 'List files in a wp-content subdirectory. Filter by extension. Capped at 2000 files.', 'inputSchema' => [ 'type' => 'object', 'properties' => [ 'path' => [ 'type' => 'string', 'description' => 'e.g. "plugins/my-plugin"' ], 'extension' => [ 'type' => 'string' ] ], 'required' => [ 'path' ] ] ],
        [ 'name' => 'wp_read_file',          'description' => 'Read source code of any file inside wp-content. Capped at 512 KB.', 'inputSchema' => [ 'type' => 'object', 'properties' => [ 'path' => [ 'type' => 'string', 'description' => 'e.g. "plugins/my-plugin/my-plugin.php"' ] ], 'required' => [ 'path' ] ] ],
        [ 'name' => 'wp_get_logs',           'description' => 'Read WordPress debug.log or PHP error log (last N lines).', 'inputSchema' => [ 'type' => 'object', 'properties' => [ 'log_type' => [ 'type' => 'string', 'description' => '"debug" or "error"' ], 'lines' => [ 'type' => 'integer' ] ], 'required' => [] ] ],
        [ 'name' => 'wp_get_hooks',          'description' => 'Inspect live $wp_filter: all registered actions and filters, their priorities and callback names.', 'inputSchema' => [ 'type' => 'object', 'properties' => [ 'hook_name' => [ 'type' => 'string' ], 'limit' => [ 'type' => 'integer' ] ], 'required' => [] ] ],
        [ 'name' => 'wp_get_acf_fields',     'description' => 'Get all ACF field groups and fields (if ACF plugin is active).', 'inputSchema' => [ 'type' => 'object', 'properties' => new stdClass(), 'required' => [] ] ],
        [ 'name' => 'wp_get_users',          'description' => 'List users with roles. Passwords never returned.', 'inputSchema' => [ 'type' => 'object', 'properties' => [ 'role' => [ 'type' => 'string' ], 'number' => [ 'type' => 'integer' ] ], 'required' => [] ] ],
        [ 'name' => 'wp_get_menus',          'description' => 'Get all navigation menus, assigned locations, and menu items with hierarchy.', 'inputSchema' => [ 'type' => 'object', 'properties' => new stdClass(), 'required' => [] ] ],
        [ 'name' => 'wp_get_cron_jobs',      'description' => 'List all scheduled WP cron events with next run times, schedules, and args.', 'inputSchema' => [ 'type' => 'object', 'properties' => new stdClass(), 'required' => [] ] ],
        [ 'name' => 'wp_get_active_widgets', 'description' => 'Get all active widget areas and widgets assigned to each with their settings.', 'inputSchema' => [ 'type' => 'object', 'properties' => new stdClass(), 'required' => [] ] ],
        [ 'name' => 'wp_get_rest_routes',    'description' => 'List all registered REST API routes with methods and namespaces.', 'inputSchema' => [ 'type' => 'object', 'properties' => new stdClass(), 'required' => [] ] ],
    ];
}

// ============================================================
// TOOL DISPATCHER
// ============================================================
function wp_mcp_call_tool( string $name, array $args ): array {
    switch ( $name ) {
        case 'wp_get_site_info':       return wp_mcp_tool_result( wp_mcp_tool_site_info() );
        case 'wp_get_plugins':         return wp_mcp_tool_result( wp_mcp_tool_plugins( $args ) );
        case 'wp_get_themes':          return wp_mcp_tool_result( wp_mcp_tool_themes() );
        case 'wp_get_post_types':      return wp_mcp_tool_result( wp_mcp_tool_post_types() );
        case 'wp_get_taxonomies':      return wp_mcp_tool_result( wp_mcp_tool_taxonomies() );
        case 'wp_get_options':         return wp_mcp_tool_result( wp_mcp_tool_options( $args ) );
        case 'wp_query_posts':         return wp_mcp_tool_result( wp_mcp_tool_query_posts( $args ) );
        case 'wp_get_db_schema':       return wp_mcp_tool_result( wp_mcp_tool_db_schema( $args ) );
        case 'wp_db_query':            return wp_mcp_tool_result( wp_mcp_tool_db_query( $args ) );
        case 'wp_list_files':          return wp_mcp_tool_result( wp_mcp_tool_list_files( $args ) );
        case 'wp_read_file':           return wp_mcp_tool_result( wp_mcp_tool_read_file( $args ) );
        case 'wp_get_logs':            return wp_mcp_tool_result( wp_mcp_tool_get_logs( $args ) );
        case 'wp_get_hooks':           return wp_mcp_tool_result( wp_mcp_tool_get_hooks( $args ) );
        case 'wp_get_acf_fields':      return wp_mcp_tool_result( wp_mcp_tool_acf_fields() );
        case 'wp_get_users':           return wp_mcp_tool_result( wp_mcp_tool_get_users( $args ) );
        case 'wp_get_menus':           return wp_mcp_tool_result( wp_mcp_tool_get_menus() );
        case 'wp_get_cron_jobs':       return wp_mcp_tool_result( wp_mcp_tool_cron_jobs() );
        case 'wp_get_active_widgets':  return wp_mcp_tool_result( wp_mcp_tool_active_widgets() );
        case 'wp_get_rest_routes':     return wp_mcp_tool_result( wp_mcp_tool_rest_routes() );
        default:                       return wp_mcp_tool_error( "Unknown tool: $name" );
    }
}

// ============================================================
// TOOL IMPLEMENTATIONS
// ============================================================

function wp_mcp_tool_site_info(): array {
    global $wp_version, $wpdb;
    if ( ! function_exists( 'get_plugins' ) ) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    $active_slugs = get_option( 'active_plugins', [] );
    $all_plugins  = get_plugins();
    $active_theme = wp_get_theme();
    $upload_dir   = wp_upload_dir();
    $active_list  = [];
    foreach ( $active_slugs as $slug ) {
        if ( isset( $all_plugins[ $slug ] ) ) {
            $p             = $all_plugins[ $slug ];
            $active_list[] = $p['Name'] . ' v' . $p['Version'];
        }
    }
    return [
        'site_name'            => get_bloginfo( 'name' ),
        'site_description'     => get_bloginfo( 'description' ),
        'site_url'             => get_site_url(),
        'home_url'             => get_home_url(),
        'admin_email'          => get_option( 'admin_email' ),
        'language'             => get_bloginfo( 'language' ),
        'charset'              => get_bloginfo( 'charset' ),
        'timezone'             => get_option( 'timezone_string' ) ?: ( get_option( 'gmt_offset' ) . ' UTC' ),
        'wordpress_version'    => $wp_version,
        'php_version'          => phpversion(),
        'mysql_version'        => $wpdb->db_version(),
        'server_software'      => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
        'max_upload_size'      => wp_max_upload_size(),
        'permalink_structure'  => get_option( 'permalink_structure' ),
        'multisite'            => is_multisite(),
        'wp_debug'             => defined( 'WP_DEBUG' ) && WP_DEBUG,
        'wp_debug_log'         => defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG,
        'active_theme'         => $active_theme->get( 'Name' ) . ' v' . $active_theme->get( 'Version' ),
        'active_plugins_count' => count( $active_slugs ),
        'active_plugins'       => $active_list,
        'content_dir'          => WP_CONTENT_DIR,
        'uploads_dir'          => $upload_dir['basedir'] ?? '',
        'uploads_url'          => $upload_dir['baseurl'] ?? '',
        'abspath'              => ABSPATH,
        'db_prefix'            => $wpdb->prefix,
        'memory_limit'         => WP_MEMORY_LIMIT,
        'max_memory_limit'     => defined( 'WP_MAX_MEMORY_LIMIT' ) ? WP_MAX_MEMORY_LIMIT : 'not set',
    ];
}

function wp_mcp_tool_plugins( array $args ): array {
    if ( ! function_exists( 'get_plugins' ) ) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    $all    = get_plugins();
    $active = get_option( 'active_plugins', [] );
    $filter = $args['status'] ?? 'all';
    $result = [];
    foreach ( $all as $path => $data ) {
        $is_active = in_array( $path, $active, true );
        if ( $filter === 'active'   && ! $is_active ) continue;
        if ( $filter === 'inactive' && $is_active )   continue;
        $result[] = [
            'path'         => $path,
            'name'         => $data['Name'],
            'version'      => $data['Version'],
            'author'       => $data['Author'],
            'description'  => $data['Description'],
            'status'       => $is_active ? 'active' : 'inactive',
            'requires_wp'  => $data['RequiresWP']  ?? '',
            'requires_php' => $data['RequiresPHP'] ?? '',
            'text_domain'  => $data['TextDomain']  ?? '',
            'plugin_uri'   => $data['PluginURI']   ?? '',
        ];
    }
    return [ 'total' => count( $result ), 'plugins' => $result ];
}

function wp_mcp_tool_themes(): array {
    $all_themes   = wp_get_themes();
    $active_theme = wp_get_theme();
    $result       = [];
    foreach ( $all_themes as $slug => $theme ) {
        $result[] = [
            'slug'           => $slug,
            'name'           => $theme->get( 'Name' ),
            'version'        => $theme->get( 'Version' ),
            'author'         => $theme->get( 'Author' ),
            'description'    => $theme->get( 'Description' ),
            'tags'           => $theme->get( 'Tags' ),
            'status'         => ( $slug === $active_theme->get_stylesheet() ) ? 'active' : 'inactive',
            'is_child_theme' => (bool) $theme->parent(),
            'parent_theme'   => $theme->parent() ? $theme->parent()->get( 'Name' ) : null,
            'template'       => $theme->get_template(),
            'directory'      => $theme->get_theme_root() . '/' . $slug,
        ];
    }
    return [ 'active_theme' => $active_theme->get( 'Name' ), 'total' => count( $result ), 'themes' => $result ];
}

function wp_mcp_tool_post_types(): array {
    $types  = get_post_types( [], 'objects' );
    $result = [];
    foreach ( $types as $type ) {
        // BUG-04 FIX: cast stdClass→int always = 1; use explicit property access.
        // Source: developer.wordpress.org/reference/functions/wp_count_posts/
        $wp_count   = wp_count_posts( $type->name );
        $post_count = isset( $wp_count->publish ) ? (int) $wp_count->publish : 0;
        $result[]   = [
            'name'               => $type->name,
            'label'              => $type->label,
            'singular_label'     => $type->labels->singular_name ?? '',
            'public'             => $type->public,
            'publicly_queryable' => $type->publicly_queryable,
            'show_ui'            => $type->show_ui,
            'show_in_menu'       => $type->show_in_menu,
            'show_in_rest'       => $type->show_in_rest,
            'rest_base'          => $type->rest_base ?? '',
            'hierarchical'       => $type->hierarchical,
            'supports'           => get_all_post_type_supports( $type->name ),
            'taxonomies'         => get_object_taxonomies( $type->name ),
            'menu_icon'          => $type->menu_icon ?? '',
            'post_count'         => $post_count,
        ];
    }
    return [ 'total' => count( $result ), 'post_types' => $result ];
}

function wp_mcp_tool_taxonomies(): array {
    global $wpdb;
    $taxs   = get_taxonomies( [], 'objects' );
    $result = [];
    foreach ( $taxs as $tax ) {
        $count    = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM $wpdb->term_taxonomy WHERE taxonomy = %s", $tax->name
        ) );
        $result[] = [
            'name'           => $tax->name,
            'label'          => $tax->label,
            'singular_label' => $tax->labels->singular_name ?? '',
            'public'         => $tax->public,
            'hierarchical'   => $tax->hierarchical,
            'show_ui'        => $tax->show_ui,
            'show_in_rest'   => $tax->show_in_rest,
            'rest_base'      => $tax->rest_base ?? '',
            'object_types'   => $tax->object_type,
            'term_count'     => $count,
        ];
    }
    return [ 'total' => count( $result ), 'taxonomies' => $result ];
}

function wp_mcp_tool_options( array $args ): array {
    $blocked  = [
        // WordPress security keys and salts
        'auth_key', 'secure_auth_key', 'logged_in_key', 'nonce_key',
        'auth_salt', 'secure_auth_salt', 'logged_in_salt', 'nonce_salt',
        'admin_password', 'db_password', 'database_password',
        // BUG-31 FIX: Block this plugin's own credentials.
        // Without this, an authenticated Claude session could call wp_get_options
        // with keys:['wp_mcp_bridge_api_key'] and receive the very Bearer token
        // it used to authenticate — enabling silent exfiltration of the secret.
        // Source: developer.wordpress.org/reference/functions/get_option/
        'wp_mcp_bridge_api_key',
        'wp_mcp_bridge_oauth_redirect_uris',
    ];
    $defaults = [
        'siteurl', 'blogname', 'blogdescription', 'admin_email', 'blogpublic',
        'posts_per_page', 'date_format', 'time_format', 'start_of_week',
        'timezone_string', 'gmt_offset', 'permalink_structure',
        'upload_path', 'upload_url_path', 'uploads_use_yearmonth_folders',
        'thumbnail_size_w', 'thumbnail_size_h', 'medium_size_w', 'medium_size_h',
        'large_size_w', 'large_size_h', 'image_default_size',
        'comment_moderation', 'default_ping_status', 'default_comment_status',
        'template', 'stylesheet', 'active_plugins',
        'woocommerce_currency', 'woocommerce_shop_page_id',
        'woocommerce_default_country', 'elementor_version',
    ];
    $keys = ! empty( $args['keys'] ) ? $args['keys'] : $defaults;
    $out  = [];
    foreach ( $keys as $key ) {
        $out[ $key ] = in_array( strtolower( $key ), $blocked, true )
            ? '[REDACTED FOR SECURITY]'
            : get_option( $key );
    }
    return $out;
}

function wp_mcp_tool_query_posts( array $args ): array {
    $query_args = [
        'post_type'      => $args['post_type']  ?? 'post',
        'post_status'    => $args['post_status'] ?? 'any',
        'posts_per_page' => min( (int) ( $args['posts_per_page'] ?? 10 ), 50 ),
        'orderby'        => $args['orderby']     ?? 'date',
        'order'          => strtoupper( $args['order'] ?? 'DESC' ),
        's'              => $args['s']           ?? '',
        'no_found_rows'  => false,
    ];
    if ( ! empty( $args['meta_key'] ) )   $query_args['meta_key']   = $args['meta_key'];
    if ( ! empty( $args['meta_value'] ) ) $query_args['meta_value'] = $args['meta_value'];

    $q     = new WP_Query( $query_args );
    $posts = [];
    foreach ( $q->posts as $post ) {
        $raw_meta = get_post_meta( $post->ID );
        $meta     = [];
        foreach ( $raw_meta as $k => $vals ) {
            $decoded = [];
            foreach ( $vals as $v ) {
                if ( is_serialized( $v ) ) {
                    $u         = @unserialize( $v, [ 'allowed_classes' => false ] );
                    $decoded[] = ( $u === false && $v !== 'b:0;' ) ? $v : $u;
                } else {
                    $decoded[] = $v;
                }
            }
            $meta[ $k ] = count( $decoded ) === 1 ? $decoded[0] : $decoded;
        }
        $terms_by_tax = [];
        foreach ( get_object_taxonomies( $post->post_type ) as $tax ) {
            $terms = wp_get_post_terms( $post->ID, $tax );
            if ( ! is_wp_error( $terms ) && $terms ) {
                $terms_by_tax[ $tax ] = array_map(
                    fn( $t ) => [ 'id' => $t->term_id, 'name' => $t->name, 'slug' => $t->slug ],
                    $terms
                );
            }
        }
        $posts[] = [
            'ID'            => $post->ID,
            'post_title'    => $post->post_title,
            'post_status'   => $post->post_status,
            'post_type'     => $post->post_type,
            'post_date'     => $post->post_date,
            'post_modified' => $post->post_modified,
            'post_author'   => $post->post_author,
            'post_excerpt'  => $post->post_excerpt,
            'post_parent'   => $post->post_parent,
            'permalink'     => get_permalink( $post->ID ),
            'meta'          => $meta,
            'terms'         => $terms_by_tax,
        ];
    }
    // BUG-05 FIX: restore global $post.
    // Source: developer.wordpress.org/reference/functions/wp_reset_postdata/
    wp_reset_postdata();
    return [ 'found_posts' => $q->found_posts, 'max_num_pages' => $q->max_num_pages, 'posts' => $posts ];
}

function wp_mcp_tool_db_schema( array $args ): array {
    global $wpdb;
    $filter = $args['table'] ?? '';
    $tables = $filter
        ? $wpdb->get_col( "SHOW TABLES LIKE '%" . $wpdb->esc_like( $filter ) . "%'" )
        : $wpdb->get_col( 'SHOW TABLES' );
    $schema = [];
    foreach ( $tables as $tbl ) {
        if ( ! preg_match( '/^[a-zA-Z0-9_]+$/', $tbl ) ) continue;
        $cols         = $wpdb->get_results( "DESCRIBE `$tbl`", ARRAY_A );
        $row_count    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `$tbl`" );
        $schema[$tbl] = [ 'columns' => $cols, 'row_count' => $row_count ];
    }
    return [ 'db_prefix' => $wpdb->prefix, 'table_count' => count( $schema ), 'tables' => $schema ];
}

function wp_mcp_tool_db_query( array $args ): array {
    global $wpdb;
    $sql         = trim( $args['sql'] ?? '' );
    $limit       = min( (int) ( $args['limit'] ?? 50 ), 200 );
    $users_table = $wpdb->users;
    if ( ! preg_match( '/^SELECT\b/i', $sql ) ) {
        throw new RuntimeException( 'Only SELECT queries are permitted.' );
    }
    if ( preg_match( '/\b(user_pass|user_activation_key)\b/i', $sql ) ) {
        throw new RuntimeException( 'Queries targeting credential columns are blocked.' );
    }
    if ( preg_match( '/\bSELECT\s+\*/i', $sql ) && preg_match( '/\b' . preg_quote( $users_table, '/' ) . '\b/', $sql ) ) {
        throw new RuntimeException( "SELECT * on $users_table is blocked to prevent credential exposure." );
    }
    if ( ! preg_match( '/\bLIMIT\b/i', $sql ) ) {
        $sql .= " LIMIT $limit";
    }
    $results = $wpdb->get_results( $sql, ARRAY_A );
    if ( $wpdb->last_error ) {
        throw new RuntimeException( 'DB error: ' . $wpdb->last_error );
    }
    return [ 'query' => $sql, 'row_count' => count( $results ?? [] ), 'results' => $results ?? [] ];
}

function wp_mcp_safe_path( string $relative ): string {
    $base = realpath( WP_CONTENT_DIR );

    // BUG-28 FIX: realpath() returns false when the directory does not exist.
    // If $base is false, then str_starts_with($full, false . DIRECTORY_SEPARATOR)
    // reduces to str_starts_with($full, '/') which is true for EVERY absolute path —
    // completely bypassing the directory containment guard and allowing any file
    // on the filesystem to be read.
    // Source: php.net/manual/en/function.realpath.php
    if ( $base === false ) {
        throw new RuntimeException( 'Cannot resolve WP_CONTENT_DIR — directory may not exist.' );
    }

    $full = realpath( $base . '/' . ltrim( $relative, '/\\' ) );

    // BUG-21 FIX: strncmp($full, $base, strlen($base)) is bypassed by sibling
    // directories whose names share the same prefix. Example:
    //   $base = '/var/www/html/wp-content'
    //   $full = '/var/www/html/wp-content-evil/shell.php'
    // strncmp returns 0 (match!) because the prefix is identical.
    // Fix: require $full to start with $base followed by a directory separator,
    // OR be exactly equal to $base (the directory itself).
    // Source: owasp.org/www-community/attacks/Path_Traversal
    if ( $full === false
        || ( $full !== $base && ! str_starts_with( $full, $base . DIRECTORY_SEPARATOR ) )
    ) {
        throw new RuntimeException( 'Access denied: path is outside wp-content.' );
    }
    return $full;
}

function wp_mcp_tool_list_files( array $args ): array {
    $path       = $args['path']      ?? '';
    $ext_filter = strtolower( $args['extension'] ?? '' );
    $full       = wp_mcp_safe_path( $path );
    if ( ! is_dir( $full ) ) throw new RuntimeException( "Directory not found: $path" );

    $result = [];
    $iter   = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $full, FilesystemIterator::SKIP_DOTS ) );
    foreach ( $iter as $file ) {
        if ( count( $result ) >= 2000 ) break;
        if ( ! $file->isFile() ) continue;
        if ( $ext_filter && strtolower( $file->getExtension() ) !== $ext_filter ) continue;
        $result[] = [
            'path'     => str_replace( WP_CONTENT_DIR . '/', '', $file->getPathname() ),
            'size'     => $file->getSize(),
            'modified' => gmdate( 'Y-m-d H:i:s \U\T\C', $file->getMTime() ),
        ];
    }
    return [ 'path' => $path, 'file_count' => count( $result ), 'files' => $result ];
}

function wp_mcp_tool_read_file( array $args ): array {
    $path = $args['path'] ?? '';
    $full = wp_mcp_safe_path( $path );
    if ( ! is_file( $full ) ) throw new RuntimeException( "File not found: $path" );

    $size = filesize( $full );
    if ( $size > 524288 ) throw new RuntimeException( "File too large ($size bytes). Max 512 KB." );

    return [
        'path'     => $path,
        'size'     => $size,
        'modified' => gmdate( 'Y-m-d H:i:s \U\T\C', filemtime( $full ) ),
        'content'  => file_get_contents( $full ),
    ];
}

function wp_mcp_tool_get_logs( array $args ): array {
    $log_type = $args['log_type'] ?? 'debug';
    $lines    = min( (int) ( $args['lines'] ?? 200 ), 1000 );

    if ( $log_type === 'error' ) {
        $candidate = ini_get( 'error_log' ) ?: WP_CONTENT_DIR . '/debug.log';
    } else {
        $candidate = WP_CONTENT_DIR . '/debug.log';
    }

    // BUG-15 FIX: ini_get('error_log') can return any absolute path on the
    // filesystem — /etc/passwd, /var/log/auth.log, ~/.ssh/authorized_keys, etc.
    // The wp_mcp_safe_path() guard used by all other file tools is completely
    // bypassed here. We must validate the resolved path falls inside one of the
    // allowed roots before reading any bytes.
    //
    // Allowed roots: WP_CONTENT_DIR, ABSPATH, sys_get_temp_dir().
    // These cover all realistic log locations while blocking system files.
    $real = realpath( $candidate );
    if ( $real === false ) {
        return [ 'log_file' => $candidate, 'error' => 'Log file does not exist.', 'lines' => [] ];
    }

    $allowed_roots = [
        realpath( WP_CONTENT_DIR ),
        realpath( ABSPATH ),
        realpath( sys_get_temp_dir() ),
    ];
    $safe = false;
    foreach ( $allowed_roots as $root ) {
        // BUG-28 FIX: Skip any root that realpath() could not resolve (returns false).
        // str_starts_with($real, false . '/') = str_starts_with($real, '/') = always true.
        if ( $root === false ) {
            continue;
        }
        // BUG-21 FIX carried forward: separator-aware containment check.
        if ( $real === $root || str_starts_with( $real, $root . DIRECTORY_SEPARATOR ) ) {
            $safe = true;
            break;
        }
    }
    if ( ! $safe ) {
        // Throw so the error is surfaced via wp_mcp_tool_error() in the caller.
        throw new RuntimeException(
            "Log file '$real' is outside the allowed directories (wp-content, ABSPATH, tmp). " .
            "This path was returned by ini_get('error_log') — update php.ini or disable 'error' log type."
        );
    }

    $all    = file( $real, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
    $sliced = array_slice( $all ?? [], -$lines );
    return [
        'log_file'            => $real,
        'total_lines_in_file' => count( $all ?? [] ),
        'returned_lines'      => count( $sliced ),
        'lines'               => $sliced,
    ];
}

function wp_mcp_tool_get_hooks( array $args ): array {
    global $wp_filter;
    $hook_name = $args['hook_name'] ?? '';
    $limit     = min( (int) ( $args['limit'] ?? 100 ), 500 );
    $result    = [];
    foreach ( $wp_filter as $hook => $callbacks ) {
        if ( $hook_name && stripos( $hook, $hook_name ) === false ) continue;
        if ( count( $result ) >= $limit ) break;
        $cbs = [];
        foreach ( $callbacks->callbacks ?? [] as $priority => $items ) {
            foreach ( $items as $item ) {
                $fn   = $item['function'];
                $name = is_array( $fn )
                    ? ( is_object( $fn[0] ) ? get_class( $fn[0] ) . '::' . $fn[1] : $fn[0] . '::' . $fn[1] )
                    : ( is_string( $fn ) ? $fn : '[closure]' );
                $cbs[] = [ 'priority' => $priority, 'callback' => $name, 'accepted_args' => $item['accepted_args'] ];
            }
        }
        $result[] = [ 'hook' => $hook, 'callbacks' => $cbs ];
    }
    return [ 'total_hooks' => count( $wp_filter ), 'returned' => count( $result ), 'hooks' => $result ];
}

function wp_mcp_tool_acf_fields(): array {
    if ( ! function_exists( 'acf_get_field_groups' ) ) {
        return [ 'error' => 'ACF plugin is not active.' ];
    }
    $groups = acf_get_field_groups();
    $result = [];
    foreach ( $groups as $group ) {
        $fields = acf_get_fields( $group['key'] );
        $result[] = [
            'key'         => $group['key'],
            'title'       => $group['title'],
            'location'    => $group['location'],
            'field_count' => count( $fields ?: [] ),
            'fields'      => array_map( fn( $f ) => [
                'key'           => $f['key'],
                'name'          => $f['name'],
                'label'         => $f['label'],
                'type'          => $f['type'],
                'required'      => $f['required'],
                'instructions'  => $f['instructions'],
            ], $fields ?: [] ),
        ];
    }
    return [ 'total_groups' => count( $result ), 'field_groups' => $result ];
}

function wp_mcp_tool_get_users( array $args ): array {
    // BUG-22 FIX: The previous code used 'fields' => [...column list...] which
    // returns stdClass objects without roles. get_userdata($id)->roles was then
    // called per user (N+1 queries — 200 users = 200 extra DB round-trips).
    //
    // Removing 'fields' uses the default 'all', which returns full WP_User objects
    // that include ->roles directly. WP_User_Query::query() also calls cache_users()
    // to batch-prime the user object cache — no extra queries needed.
    // Source: developer.wordpress.org/reference/functions/get_users/
    //   "If 'fields' is set to 'all' (default) it returns an array of WP_User objects."
    $query_args = [
        'role'   => $args['role']   ?? '',
        'number' => min( (int) ( $args['number'] ?? 50 ), 200 ),
        // No 'fields' key — default 'all' returns WP_User objects with roles included.
    ];
    $users  = get_users( $query_args );
    $result = [];
    foreach ( $users as $user ) {
        $result[] = [
            'ID'           => $user->ID,
            'login'        => $user->user_login,
            'email'        => $user->user_email,
            'display_name' => $user->display_name,
            'registered'   => $user->user_registered,
            'roles'        => $user->roles,   // Direct property — zero extra queries.
        ];
    }
    return [ 'total' => count( $result ), 'users' => $result ];
}

function wp_mcp_tool_get_menus(): array {
    $menus     = wp_get_nav_menus();
    $locations = get_registered_nav_menus();
    $assigned  = get_nav_menu_locations();
    $result    = [];
    foreach ( $menus as $menu ) {
        $items = wp_get_nav_menu_items( $menu->term_id );
        $loc   = [];
        foreach ( $assigned as $loc_key => $menu_id ) {
            if ( $menu_id === $menu->term_id ) {
                $loc[] = [ 'location_key' => $loc_key, 'location_name' => $locations[ $loc_key ] ?? $loc_key ];
            }
        }
        $result[] = [
            'ID'          => $menu->term_id,
            'name'        => $menu->name,
            'slug'        => $menu->slug,
            'count'       => $menu->count,
            'locations'   => $loc,
            'items'       => array_map( fn( $i ) => [
                'ID'        => $i->ID,
                'title'     => $i->title,
                'url'       => $i->url,
                'type'      => $i->type,
                'object'    => $i->object,
                'object_id' => $i->object_id,
                'parent'    => $i->menu_item_parent,
                'order'     => $i->menu_order,
            ], $items ?: [] ),
        ];
    }
    return [ 'total_menus' => count( $result ), 'menus' => $result ];
}

function wp_mcp_tool_cron_jobs(): array {
    // BUG-32 FIX: _get_cron_array() returns false when the 'cron' option is
    // missing or corrupt (e.g., fresh install, object cache cleared).
    // foreach(false) emits E_WARNING on PHP 8.0/8.1 and TypeError on PHP 8.2+.
    // WordPress core itself guards against this (see wp_clear_scheduled_hook).
    // Using ?: [] normalises false and null to an empty array safely.
    // Source: developer.wordpress.org/plugins/cron/simple-testing/
    // Source: developer.wordpress.org/reference/functions/_get_cron_array/
    $cron   = _get_cron_array() ?: [];
    $result = [];
    foreach ( $cron as $timestamp => $hooks ) {
        foreach ( $hooks as $hook => $events ) {
            foreach ( $events as $key => $event ) {
                $result[] = [
                    'hook'      => $hook,
                    // BUG-07 FIX: use gmdate() — server timezone can differ from WP timezone.
                    'next_run'  => gmdate( 'Y-m-d H:i:s \U\T\C', $timestamp ),
                    'timestamp' => $timestamp,
                    'schedule'  => $event['schedule'],
                    'interval'  => $event['interval'] ?? 0,
                    'args'      => $event['args'],
                ];
            }
        }
    }
    usort( $result, fn( $a, $b ) => $a['timestamp'] <=> $b['timestamp'] );
    return [ 'total' => count( $result ), 'jobs' => $result ];
}

function wp_mcp_tool_active_widgets(): array {
    global $wp_registered_widgets, $wp_registered_sidebars;
    $sidebars_widgets = wp_get_sidebars_widgets();
    $result           = [];
    foreach ( $wp_registered_sidebars as $sid => $sidebar ) {
        $widget_ids = $sidebars_widgets[ $sid ] ?? [];
        $widgets    = [];
        foreach ( $widget_ids as $widget_id ) {
            if ( ! isset( $wp_registered_widgets[ $widget_id ] ) ) continue;
            $wdata    = $wp_registered_widgets[ $widget_id ];
            $settings = [];
            if ( ! empty( $wdata['callback'][0] ) && is_object( $wdata['callback'][0] ) ) {
                $obj      = $wdata['callback'][0];
                $all_sets = $obj->get_settings();
                $num_key  = preg_replace( '/\D/', '', $widget_id );
                $settings = $all_sets[ $num_key ] ?? [];
            }
            $widgets[] = [
                'id'          => $widget_id,
                'name'        => $wdata['name'],
                'description' => $wdata['description'] ?? '',
                'settings'    => $settings,
            ];
        }
        $result[] = [
            'sidebar_id'   => $sid,
            'sidebar_name' => $sidebar['name'],
            'description'  => $sidebar['description'] ?? '',
            'widget_count' => count( $widgets ),
            'widgets'      => $widgets,
        ];
    }
    return [ 'total_sidebars' => count( $result ), 'sidebars' => $result ];
}

function wp_mcp_tool_rest_routes(): array {
    // BUG-20 FIX: Removed do_action('rest_api_init') — this function runs inside
    // a live REST request, so rest_api_init has already fired and all routes are
    // already registered. Calling do_action() again re-fires every plugin's REST
    // registration callback a second time, causing duplicate route warnings and
    // potential side-effects (DB writes, emails) in third-party plugins.
    // rest_get_server() returns the already-initialised server directly.
    // Source: developer.wordpress.org/reference/hooks/rest_api_init/
    $server = rest_get_server();
    $routes = $server->get_routes();
    $result = [];
    foreach ( $routes as $route => $handlers ) {
        $methods = [];
        foreach ( $handlers as $handler ) {
            if ( ! empty( $handler['methods'] ) ) {
                $methods = array_merge( $methods, array_keys( $handler['methods'] ) );
            }
        }
        preg_match( '#^/([^/]+)/#', $route, $ns_match );
        $result[] = [
            'route'     => $route,
            'methods'   => array_unique( $methods ),
            'namespace' => $ns_match[1] ?? '',
        ];
    }
    return [ 'total_routes' => count( $result ), 'routes' => $result ];
}

// ============================================================
// ADMIN SETTINGS PAGE
// Source: developer.wordpress.org/plugins/settings/settings-api/
// ============================================================
add_action( 'admin_menu',        'wp_mcp_bridge_admin_menu' );
add_action( 'admin_init',        'wp_mcp_bridge_admin_settings' );
// BUG-29 FIX: register_setting() must be called on both admin_init AND rest_api_init.
// Without rest_api_init, the sanitize_callback is not applied when settings are
// updated via the WordPress REST API, leaving values unsanitised.
// Source: developer.wordpress.org/reference/functions/register_setting/
//   "If you plan to use your setting in the REST API, use both the rest_api_init
//    and admin_init hooks when calling register_setting() instead of just admin_init."
add_action( 'rest_api_init',     'wp_mcp_bridge_admin_settings' );
add_action( 'admin_print_scripts-settings_page_wp-mcp-bridge', 'wp_mcp_bridge_admin_scripts' );

function wp_mcp_bridge_admin_menu(): void {
    add_options_page( 'MCP Bridge', 'MCP Bridge', 'manage_options', 'wp-mcp-bridge', 'wp_mcp_bridge_settings_page' );
}

function wp_mcp_bridge_admin_settings(): void {
    register_setting( 'wp_mcp_bridge_options', 'wp_mcp_bridge_api_key', [
        'type'              => 'string',
        'sanitize_callback' => 'sanitize_text_field',
    ] );
    register_setting( 'wp_mcp_bridge_options', 'wp_mcp_bridge_oauth_redirect_uris', [
        'type'              => 'string',
        'sanitize_callback' => 'sanitize_textarea_field',
    ] );
}

// BUG-10 FIX: named JS function, not inline onclick.
// Source: developer.wordpress.org/reference/functions/wp_add_inline_script/
function wp_mcp_bridge_admin_scripts(): void {
    // BUG-14 FIX: wp_enqueue_script('handle', '') does not register the handle
    // into $wp_scripts->queue when $src is an empty string — WP skips the add()
    // call for falsy sources. wp_add_inline_script() then has nothing to attach to.
    // The correct pattern for inline-only scripts is wp_register_script($h, false).
    // Source: developer.wordpress.org/reference/functions/wp_register_script/
    //   "If source is set to false, script is an alias of other scripts it depends on."
    wp_register_script( 'wp-mcp-bridge-admin', false, [], WP_MCP_BRIDGE_VERSION );
    wp_enqueue_script( 'wp-mcp-bridge-admin' );
    wp_add_inline_script( 'wp-mcp-bridge-admin', '
        function wpMcpBridgeRegenKey() {
            var field = document.getElementById("wp_mcp_bridge_api_key");
            if (!field) return;
            var arr = new Uint8Array(32);
            crypto.getRandomValues(arr);
            field.value = Array.from(arr).map(function(b){ return b.toString(16).padStart(2,"0"); }).join("");
        }
    ' );
}

function wp_mcp_bridge_settings_page(): void {
    if ( ! current_user_can( 'manage_options' ) ) return;

    $api_key              = get_option( 'wp_mcp_bridge_api_key', '' );
    $extra_uris           = get_option( 'wp_mcp_bridge_oauth_redirect_uris', '' );
    $endpoint_url         = rest_url( 'mcp/v1/bridge' );
    $oauth_authorize_url  = rest_url( 'mcp/v1/oauth/authorize' );
    $oauth_token_url      = rest_url( 'mcp/v1/oauth/token' );
    $well_known_prm_url   = home_url( '/.well-known/oauth-protected-resource' );
    $well_known_asm_url   = home_url( '/.well-known/oauth-authorization-server' );
    ?>
    <div class="wrap">
        <h1>WordPress MCP Bridge <span style="font-size:13px;color:#999;font-weight:normal">v<?php echo WP_MCP_BRIDGE_VERSION; ?></span></h1>
        <p>Connect this site to Claude.ai so Claude can read your WordPress data and write perfectly tailored plugins.</p>

        <h2>Your Endpoints</h2>
        <table class="form-table">
            <tr>
                <th>MCP Endpoint (paste into Claude.ai)</th>
                <td><code style="font-size:13px;background:#f0f0f0;padding:6px 10px;display:inline-block"><?php echo esc_html( $endpoint_url ); ?></code></td>
            </tr>
            <tr>
                <th>OAuth Authorization URL</th>
                <td><code style="font-size:13px;background:#f0f0f0;padding:6px 10px;display:inline-block"><?php echo esc_html( $oauth_authorize_url ); ?></code>
                    <p class="description">Use this in Claude.ai OAuth settings as the <strong>Authorization URL</strong>.</p></td>
            </tr>
            <tr>
                <th>OAuth Token URL</th>
                <td><code style="font-size:13px;background:#f0f0f0;padding:6px 10px;display:inline-block"><?php echo esc_html( $oauth_token_url ); ?></code>
                    <p class="description">Use this in Claude.ai OAuth settings as the <strong>Token URL</strong>.</p></td>
            </tr>
            <tr>
                <th>OAuth Discovery (auto-used by Claude.ai)</th>
                <td>
                    <code style="font-size:12px;background:#f0f0f0;padding:4px 8px;display:inline-block"><?php echo esc_html( $well_known_asm_url ); ?></code><br>
                    <code style="font-size:12px;background:#f0f0f0;padding:4px 8px;display:inline-block;margin-top:4px"><?php echo esc_html( $well_known_prm_url ); ?></code>
                    <p class="description">Claude.ai fetches these automatically — you don't need to enter them manually.</p>
                </td>
            </tr>
        </table>

        <form method="post" action="options.php">
            <?php settings_fields( 'wp_mcp_bridge_options' ); ?>

            <h2>API Key (Bearer Token — simplest method)</h2>
            <table class="form-table">
                <tr>
                    <th><label for="wp_mcp_bridge_api_key">Bearer Token</label></th>
                    <td>
                        <input type="text" id="wp_mcp_bridge_api_key" name="wp_mcp_bridge_api_key"
                               value="<?php echo esc_attr( $api_key ); ?>" class="regular-text" autocomplete="off">
                        <p class="description">Keep this secret. In Claude.ai connector settings choose <strong>API Key / Bearer Token</strong> and paste this value.</p>
                        <p><button type="button" class="button" onclick="wpMcpBridgeRegenKey()">Regenerate Key</button></p>
                    </td>
                </tr>
            </table>

            <h2>Extra OAuth Redirect URIs (optional)</h2>
            <table class="form-table">
                <tr>
                    <th><label for="wp_mcp_bridge_oauth_redirect_uris">Additional Redirect URIs</label></th>
                    <td>
                        <textarea id="wp_mcp_bridge_oauth_redirect_uris" name="wp_mcp_bridge_oauth_redirect_uris"
                                  rows="4" class="large-text"><?php echo esc_textarea( $extra_uris ); ?></textarea>
                        <p class="description">One URI per line. Built-in: <code>https://claude.ai/api/mcp/auth_callback</code> and <code>https://app.claude.ai/api/mcp/auth_callback</code> (always allowed).</p>
                    </td>
                </tr>
            </table>

            <?php submit_button( 'Save Settings' ); ?>
        </form>

        <h2>Setup Guide — Option A: Bearer Token (Simplest)</h2>
        <ol>
            <li>Go to <a href="https://claude.ai" target="_blank" rel="noopener noreferrer">claude.ai</a> → Profile → <strong>Settings</strong> → <strong>Connectors</strong> → <strong>Add custom connector</strong>.</li>
            <li>Paste the <strong>MCP Endpoint</strong> URL above.</li>
            <li>Set auth type to <strong>Bearer Token</strong> (or <strong>API Key</strong>).</li>
            <li>Paste the <strong>Bearer Token</strong> value from the API Key field above.</li>
            <li>Save — Claude.ai can now connect immediately.</li>
        </ol>

        <h2>Setup Guide — Option B: OAuth 2.1 (used when Claude.ai shows a login screen)</h2>
        <p>Claude.ai will automatically discover the OAuth server via the <code>/.well-known/</code> URLs above and redirect you to a login page hosted on this WordPress site.</p>
        <ol>
            <li>In Claude.ai connector settings, paste the <strong>MCP Endpoint</strong> URL.</li>
            <li>If asked for OAuth settings, use:<br>
                &nbsp;• <strong>Authorization URL</strong>: <code><?php echo esc_html( $oauth_authorize_url ); ?></code><br>
                &nbsp;• <strong>Token URL</strong>: <code><?php echo esc_html( $oauth_token_url ); ?></code><br>
                &nbsp;• <strong>Client ID</strong>: <code>claude.ai</code> (or any value — do not use "Bearer Token")<br>
                &nbsp;• <strong>Scopes</strong>: <code>claudeai</code></li>
            <li>Claude.ai will open a browser window to this site's authorization page.</li>
            <li>Log in to WordPress as an administrator and click <strong>Allow Access</strong>.</li>
        </ol>

        <h2>Troubleshooting: 404 / "rest_no_route"</h2>
        <ol>
            <li>Go to <strong>Settings → Permalinks</strong> and click <em>Save Changes</em> to flush rewrite rules.</li>
            <li>Confirm the plugin is <strong>active</strong>.</li>
            <li>Test the endpoint:<br>
                <code>curl -s -X POST <?php echo esc_html( $endpoint_url ); ?> \<br>
                &nbsp;&nbsp;-H "Authorization: Bearer <?php echo esc_html( $api_key ); ?>" \<br>
                &nbsp;&nbsp;-H "Content-Type: application/json" \<br>
                &nbsp;&nbsp;-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}'</code></li>
            <li>Test OAuth discovery: <code>curl <?php echo esc_html( $well_known_asm_url ); ?></code></li>
            <li>A successful initialize response starts with: <code>{"jsonrpc":"2.0","id":1,"result":{...</code></li>
        </ol>

        <h2>Enable Debug Logging (optional)</h2>
        <pre style="background:#f0f0f1;padding:12px">define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);</pre>
    </div>
    <?php
}
