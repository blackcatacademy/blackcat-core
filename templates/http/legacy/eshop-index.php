<?php

declare(strict_types=1);

use BlackCat\Core\Database;
use BlackCat\Core\Log\Logger;
use BlackCat\Core\Templates\Templates;
use BlackCat\Core\TrustedShared;
use BlackCat\Core\Security\CSRF;
use BlackCat\Core\Security\Recaptcha;

// index.php — frontcontroller
if (php_sapi_name() === 'cli') return; // prevent CLI accidental run

// --- ROUTING HELPERS (updated: supports greedy {name+} tokens) ---
function bc_normalize_path(string $path): string {
    $p = rawurldecode($path);
    $p = preg_replace('#/+#', '/', $p);
    $p = '/' . ltrim($p, '/');
    if ($p !== '/' && substr($p, -1) === '/') $p = rtrim($p, '/');
    return $p;
}

function bc_match_route_pattern(string $pattern, string $path) {
    $orig = $pattern;
    $parts = preg_split('#(\{[a-zA-Z0-9_]+\+?\})#', $orig, -1, PREG_SPLIT_DELIM_CAPTURE);
    $rx = '';
    foreach ($parts as $part) {
        if (preg_match('#^\{([a-zA-Z0-9_]+)(\+)?\}$#', $part, $mm)) {
            $name = $mm[1];
            $greedy = isset($mm[2]) && $mm[2] === '+';
            $rx .= $greedy ? '(?P<' . $name . '>.+)' : '(?P<' . $name . '>[^/]+)';
        } else {
            $rx .= preg_quote($part, '#');
        }
    }
    $regex = '#^' . $rx . '$#i';
    if (preg_match($regex, ltrim($path, '/'), $m)) {
        $params = [];
        foreach ($m as $k => $v) if (is_string($k)) $params[$k] = $v;
        return ['params' => $params, 'pattern' => $pattern, 'regex' => $regex];
    }
    return false;
}

function bc_build_route_path(string $pattern, array $params): string {
    $out = $pattern;
    preg_match_all('/\{([a-z0-9_]+)(\+)?\}/i', $pattern, $ph);
    $placeholders = $ph[1] ?? [];
    $mods = $ph[2] ?? [];
    foreach ($placeholders as $i => $k) {
        $isGreedy = isset($mods[$i]) && $mods[$i] === '+';
        $val = $params[$k] ?? '';
        if ($isGreedy) {
            $segments = explode('/', $val);
            $segments = array_map('rawurlencode', $segments);
            $rep = implode('/', $segments);
        } else {
            $rep = rawurlencode($val);
        }
        $out = str_replace('{' . $k . ($isGreedy ? '+' : '') . '}', $rep, $out);
    }
    return '/' . ltrim($out, '/');
}

// adjust according to where you expose the notify endpoint
$reqPath = bc_normalize_path(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/');
if ($reqPath === '/eshop/notify' || $reqPath === '/notify') {
    // minimal bootstrap that only initializes Database (or whatever minimal libs you need)
    require_once __DIR__ . '/inc/bootstrap_database_minimal.php'; // nebo path kde máš minimal_bootstrap.php

    // include the lightweight handler (the file you already prepared)
    // make sure this file expects minimal_bootstrap to have run
    require __DIR__ . '/gopay/notify.php';

    // terminate — don't load full frontcontroller
    exit;
}

require_once __DIR__ . '/inc/bootstrap.php'; // bootstrap by měl inicializovat Database::init(...) + session + CSRF apod.

// --- Acquire Database singleton (expect Database::init() was volané v bootstrapu) ---
try {
    $database = Database::getInstance();
} catch (Throwable $e) {
    // pokud DB není inicializovaná, zkusíme logovat a ukončit s užitečnou stránkou
    try { if (class_exists(Logger::class, true)) Logger::error('Database not initialized in index.php', null, ['exception' => (string)$e]); } catch (Throwable $_) {}
    http_response_code(500);
    echo (class_exists(Templates::class, true) ? Templates::render('pages/error.php', ['message' => 'Database not available', 'user' => null]) : '<h1>Internal server error</h1><p>Database not available.</p>');
    exit;
}

// --- current user (bootstrap může nastavit $userId / $user) ---
$currentUserId = $userId ?? null;
$user = $user ?? null;

// --- Route detection (parametric + REST friendly) ---
$rawPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
$rawPath = bc_normalize_path($rawPath);

// base path (např. '/eshop') — adjust pokud je jiný
$BASE = '/eshop';
$path = $rawPath;
if (stripos($path, $BASE) === 0) {
    $path = substr($path, strlen($BASE));
    $path = $path === '' ? '/' : $path;
}
$path = bc_normalize_path($path); // normalized path inside app

// fallback route candidate string without leading slash and sanitized for simple static routes
$routeCandidate = ltrim($path, '/');
if ($routeCandidate === '') $routeCandidate = 'home';

// current HTTP method (for REST handlers)
$httpMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// keep for canonical checks later
$requestedPath = $path;

// --- detect fragment/ajax request (to return only content without header/footer) ---
$isFragmentRequest = false;
// explicit query param ?ajax=1 or ?fragment=1
if (isset($_GET['ajax']) && (string)$_GET['ajax'] === '1') $isFragmentRequest = true;
if (isset($_GET['fragment']) && (string)$_GET['fragment'] === '1') $isFragmentRequest = true;
// X-Requested-With header (classic AJAX)
if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') $isFragmentRequest = true;
// optional: accept header asking HTML fragment (not required)
if (isset($_SERVER['HTTP_ACCEPT']) && stripos($_SERVER['HTTP_ACCEPT'], 'text/html') !== false && isset($_GET['ajax'])) $isFragmentRequest = true;

// --- Routes: string = handler file (default share true), array = ['file'=>..., 'share'=> true|false|[keys]] ---
$routes = [
    /*
    // pattern routes
    'catalog_page' => [
        'pattern' => 'catalog/page/{page}',
        'file'    => 'catalog.php',
        'methods' => ['GET'],
        'share'   => true,
        'canonical' => 'catalog/page/{page}',
    ],
    'catalog' => [
        'pattern' => 'catalog',
        'file'    => 'catalog.php',
        'methods' => ['GET'],
        'share'   => true,
    ],
    // detail route with id+slug (canonical includes slug)
    'detail' => [
        'pattern' => 'detail/{id}-{slug}',
        'file'    => 'detail.php',
        'methods' => ['GET'],
        'share'   => true,
        'canonical' => 'detail/{id}-{slug}',
    ],
    // pagination or legacy slug fallback: allow detail/{id} and redirect to canonical
    'detail_short' => [
        'pattern' => 'detail/{id}',
        'file'    => 'detail.php',
        'methods' => ['GET'],
        'share'   => true,
        'canonical' => 'detail/{id}-{slug}', // handler should provide slug in returned vars if possible
    ],

    // actions (POST)
    'cart_add' => [
        'pattern' => 'actions/cart_add',
        'file'    => 'actions/cart_add.php',
        'methods' => ['POST'],
        'share'   => ['db','csrfToken'], // only minimal shared
    ],

    // REST-like API example
    'api_orders' => [
        'pattern' => 'api/orders/{id}',
        'file'    => 'api/orders.php',
        'methods' => ['GET','PUT','DELETE','POST'],
        'share'   => false,
        'is_api'  => true,
    ], */
    'home' => [
    'pattern' => 'home',
    'file'    => 'main-page.php',
    'methods' => ['GET'],
    'share'   => ['db','csrfToken'],
    'is_api'  => false,
    ],
    'catalog'        => 'catalog.php',
    'contact'           => 'contact.php',
    'detail'         => 'detail.php',
    'cart'           => 'cart.php',
    'order_submit'       => '/actions/order_submit.php',
    'order'          => 'order.php',
    'password_reset_confirm' => 'password_reset_confirm.php',
    'faq'         => 'faq.php',
    'google'         => 'google_auth.php',
    'profile'        => 'profile.php',
    'download'       => 'download.php',
    'gdpr'           => 'gdpr.php',
    'vop'            => 'vop.php',
    'reklamacie'     => 'reklamacie.php',
    'gopay_return'         => '/gopay_return.php',
    'contact_send' => [
    'pattern' => 'send',
    'file'    => 'actions/send.php',
    'methods' => ['POST'],
    'share'   => ['config','Logger','MailHelper','Mailer','Recaptcha','KEYS_DIR','CSRF'],
    'is_api'  => true,
    ],
    'newsletter_subscribe' => [
    'pattern' => 'subscribe',
    'file'    => 'actions/subscribe.php',
    'methods' => ['POST'],
    'share'   => ['config','Logger','MailHelper','Mailer','Recaptcha','KEYS_DIR','CSRF','db'],
    'is_api'  => true,
    ],
    'csrf_token' => [
    'pattern' => 'csrf_token',
    'file'    => 'actions/csrf_token.php',
    'methods' => ['GET'],
    'share'   => ['CSRF'],
    'is_api'  => true,
    ],
    'newsletter_confirm' => [
    'pattern' => 'newsletter_confirm',
    'file'    => 'newsletter_confirm.php',
    'methods' => ['GET'],
    'share'   => ['db','database','KEYS_DIR','KeyManager','Logger','Mailer','Crypto'],
    'is_api'  => false,
    ],
    'newsletter_unsubscribe' => [
    'pattern' => 'newsletter_unsubscribe',
    'file'    => 'newsletter_unsubscribe.php',
    'methods' => ['GET'],
    'share'   => ['db','database','KEYS_DIR','KeyManager','Logger'],
    'is_api'  => false,
    ],
    'register' => [
        'pattern' => 'register',
        'file'    => 'actions/register.php',
        'methods' => ['GET', 'POST'],
        'share'   => ['config','Logger','MailHelper','Mailer','Recaptcha','KEYS_DIR','CSRF','csrfToken','db','KeyManager','Validator','LoginLimiter','Crypto'],
        'is_api'  => true,
    ],
    'login' => [
    'pattern' => 'login',
    'file'    => 'actions/login.php',
    'methods' => ['GET', 'POST'],
    'share'   => ['config','Logger','db','Auth','SessionManager','KeyManager','CSRF','csrfToken','KEYS_DIR','Crypto'],
    'is_api'  => true,
    ],
    'logout' => [
    'pattern' => 'logout',
    'file'    => 'actions/logout.php',
    'methods' => ['POST'],
    'share'   => ['Logger','db','SessionManager','KeyManager','CSRF'],
    'is_api'  => true,
    ],
    'password_reset' => [
    'pattern' => 'password_reset',
    'file'    => 'actions/password_reset.php',
    'methods' => ['GET', 'POST'],
    'share'   => ['KeyManager','Logger','Validator','CSRF','db','Mailer','MailHelper','KEYS_DIR','csrfToken'],
    'is_api'  => true,
    ],
    'password_reset_confirm' => [
    'pattern' => 'password_reset_confirm',
    'file'    => 'actions/password_reset_confirm.php',
    'methods' => ['GET', 'POST'],
    'share'   => ['KeyManager','Logger','Validator','CSRF','db','KEYS_DIR','csrfToken'],
    'is_api'  => true,
    ],
    'verify' => [
    'pattern' => 'verify',
    'file'    => 'actions/verify.php',
    'methods' => ['GET', 'POST'],
    'share'   => ['KeyManager','Logger','CSRF','db','KEYS_DIR','csrfToken'],
    'is_api'  => true,
    ],
    'cart_add' => [
    'pattern' => 'cart_add',
    'file'    => 'actions/cart_add.php',
    'methods' => ['POST'],
    'share'   => ['Logger','db','CSRF','user'],
    'is_api'  => true,
    ],
    'cart_clear' => [
    'pattern' => 'cart_clear',
    'file'    => 'actions/cart_clear.php',
    'methods' => ['POST'],
    'share'   => ['Logger','db','CSRF','user'],
    'is_api'  => true,
    ],
    'cart_mini' => [
    'pattern' => 'cart_mini',
    'file'    => 'actions/cart_mini.php',
    'methods' => ['GET'],
    'share'   => ['Logger','db','user'],
    'is_api'  => true,
    ],
    'checkout' => [
    'pattern' => 'checkout',
    'file'    => 'actions/checkout.php',
    'methods' => ['GET', 'POST'],
    'share'   => ['KeyManager','Logger','Crypto','CSRF','db','KEYS_DIR','csrfToken','user'],
    'is_api'  => true,
    ],
];

// --- Find matching route (pattern matching + method check) ---
$matchedRouteKey = null;
$handlerPath = null;
$shareSpec = true;
$params = [];

foreach ($routes as $key => $cfg) {
    // pokud se jméno trasy přesně rovná kandidátovi, použij ho přímo (podporuje i array configy)
    if ($routeCandidate === $key) {
        if (is_string($cfg)) {
            $matchedRouteKey = $key;
            $handlerPath = __DIR__ . '/' . ltrim($cfg, '/');
            $shareSpec = true;
            break;
        } elseif (is_array($cfg) && !empty($cfg['file'])) {
            $matchedRouteKey = $key;
            $handlerPath = __DIR__ . '/' . ltrim($cfg['file'], '/');
            $shareSpec = $cfg['share'] ?? true;
            // pokud má pattern, nechme také params prázdné
            break;
        }
    }
    // normalize cfg to uniform array
    if (is_string($cfg)) {
        // allow either 'home' => 'main-page.php' or 'contact' => 'contact.php'
        $pattern = ltrim($key, '/'); // treat key as simple route name
        // check simple match by routeCandidate (exact)
        if ($routeCandidate === $key || $routeCandidate === ltrim($cfg, '/')) {
            $matchedRouteKey = $key;
            $handlerPath = __DIR__ . '/' . ltrim($cfg, '/');
            $shareSpec = true;
            break;
        }
        continue;
    }

    $pattern = $cfg['pattern'] ?? null;
    if (!$pattern) continue;

    $match = bc_match_route_pattern($pattern, $path);
    if ($match === false) continue;

    // method check
    $allowed = $cfg['methods'] ?? ['GET'];
    $allowed = array_map('strtoupper', $allowed);
    if (!in_array($httpMethod, $allowed, true)) {
        // method not allowed -> 405
        http_response_code(405);
        echo Templates::render('pages/error.php', ['message' => 'Method Not Allowed', 'user' => $user]);
        exit;
    }

    // matched!
    $matchedRouteKey = $key;
    $handlerPath = __DIR__ . '/' . ltrim($cfg['file'], '/');
    $shareSpec = $cfg['share'] ?? true;
    $params = $match['params'];
    $routeCfg = $cfg;
    break;
}

if ($handlerPath === null) {
    // not found: 404
    http_response_code(404);
    echo Templates::render('pages/404.php', ['route' => $routeCandidate, 'user' => $user]);
    exit;
}

// --- Build trustedShared using TrustedShared helper ---
// TrustedShared::create bude best-effort: použije předanou Database, user a userId.
// EnrichUser=true zajistí načtení purchased_books (pokud máš v DB odpovídající metody).
// --- Build trustedShared using TrustedShared helper (fallback safe) ---
if (class_exists(TrustedShared::class, true)) {
    $trustedShared = TrustedShared::create([
        'database'     => $database,
        'user'         => $user,
        'userId'       => $currentUserId ?? null,
        'gopayAdapter' => $gopayAdapter ?? null,
        'enrichUser'   => true,
        'config'       => $config ?? [],
    ]);
} else {
    // fallback: keep minimal manual trustedShared to avoid fatal errors
    $trustedShared = [
        'user'         => $user,
        'csrfToken'    => $csrfToken ?? null,
        'categories'   => [],
        'db'           => $database,
        'gopayAdapter' => $gopayAdapter ?? null,
        'now_utc'      => gmdate('Y-m-d H:i:s'),
    ];
    if (class_exists(Logger::class, true)) {
        try { Logger::warn('TrustedShared class missing, using fallback'); } catch (Throwable $_) {}
    }
}

// --- Ensure $routeCfg exists (normalize string-style route entries) ---
if (!isset($routeCfg)) {
    $routeCfg = [];
    if (isset($routes[$matchedRouteKey])) {
        if (is_string($routes[$matchedRouteKey])) {
            $routeCfg['file'] = $routes[$matchedRouteKey];
            $routeCfg['share'] = true;
        } elseif (is_array($routes[$matchedRouteKey])) {
            $routeCfg = $routes[$matchedRouteKey];
        }
    }
}

// ensure shareSpec is set (may have been set earlier for pattern match)
$shareSpec = $routeCfg['share'] ?? $shareSpec ?? true;

// --- canonical redirect: if route defines 'canonical', build it and redirect if different ---
if (!empty($routeCfg['canonical'])) {
    $canonicalPattern = $routeCfg['canonical'];
    preg_match_all('/\{([a-z0-9_]+)\+?\}/i', $canonicalPattern, $ph);
    $placeholders = $ph[1] ?? [];
    $canBuild = true;
    foreach ($placeholders as $phk) {
        if (!array_key_exists($phk, $params)) { $canBuild = false; break; }
    }
    if ($canBuild) {
        $canonicalPath = bc_build_route_path($canonicalPattern, $params);
        // porovnej dekódované formy, aby se nerozhodovalo kvůli rozdílnému percent-encodingu
        if (rawurldecode($canonicalPath) !== rawurldecode($requestedPath)) {
            $qs = $_SERVER['QUERY_STRING'] ?? '';
            $loc = rtrim($BASE, '/') . $canonicalPath . ($qs !== '' ? '?'.$qs : '');
            header('Location: ' . $loc, true, 301);
            exit;
        }
    }
}

// --- Decide which trustedShared keys to inject into handler scope (sharedForInclude) ---
$sharedForInclude = [];
try {
    if (method_exists(TrustedShared::class, 'select')) {
        $sharedForInclude = TrustedShared::select($trustedShared, $shareSpec);
    } else {
        $sharedForInclude = $shareSpec === true ? $trustedShared : [];
    }
} catch (Throwable $e) {
    $sharedForInclude = $shareSpec === true ? $trustedShared : [];
}

// --- Prepare $sharedForInclude using TrustedShared helper (centralized mapping) ---
try {
    // pass $config as opt so prepareForHandler can build config from it when needed
    $sharedForInclude = TrustedShared::prepareForHandler($trustedShared, $shareSpec, ['config' => $config ?? []]);
} catch (Throwable $e) {
    // fallback to previous best-effort selection
    try { if (class_exists(Logger::class, true)) Logger::warn('prepareForHandler failed, falling back', null, ['exception' => (string)$e]); } catch (Throwable $_) {}
    if (method_exists(TrustedShared::class, 'select')) {
        $sharedForInclude = TrustedShared::select($trustedShared, $shareSpec);
    } else {
        $sharedForInclude = $shareSpec === true ? $trustedShared : [];
    }
}

// --- Route meta checks (auth, roles) ---
$routeMeta = $routeCfg['meta'] ?? [];
if (!empty($routeMeta['auth_required'])) {
    if (empty($currentUserId) && empty($user)) {
        $loginUrl = rtrim($BASE, '/') . '/login?redirect=' . rawurlencode($requestedPath . (!empty($_SERVER['QUERY_STRING']) ? '?'.$_SERVER['QUERY_STRING'] : ''));
        header('Location: ' . $loginUrl, true, 302);
        exit;
    }
    if (!empty($routeMeta['roles']) && is_array($routeMeta['roles'])) {
        $userRoles = $user['roles'] ?? [];
        $ok = false;
        foreach ($routeMeta['roles'] as $r) {
            if (in_array($r, (array)$userRoles, true)) { $ok = true; break; }
        }
        if (!$ok) {
            http_response_code(403);
            echo Templates::render('pages/error.php', ['message' => 'Forbidden', 'user' => $user]);
            exit;
        }
    }
}

// bezpečnost: zkontroluj existenci handleru dříve, než ho include-ujeme
if (empty($handlerPath) || !is_string($handlerPath) || !is_file($handlerPath) || !is_readable($handlerPath)) {
    try { if (class_exists(Logger::class, true)) Logger::warn('Handler file missing or not readable', null, ['handler' => $handlerPath]); } catch (Throwable $_) {}
    http_response_code(500);
    echo Templates::render('pages/error.php', ['message' => 'Internal server error (handler missing)', 'user' => $user]);
    exit;
}

// --- Handler include in isolated scope, with selected shared vars extracted (EXTR_SKIP) ---
$handlerResult = (function(string $handlerPath, array $sharedVars, array $params = []) {
    if (!empty($sharedVars) && is_array($sharedVars)) {
        extract($sharedVars, EXTR_SKIP);
    }
    // inject params as $params and also extract individual params (EXTR_SKIP)
    if (!empty($params)) {
        ${'params'} = $params;
        extract($params, EXTR_SKIP);
    } else {
        ${'params'} = [];
    }

    ob_start();
    try {
        $ret = include $handlerPath;
        $out = (string) ob_get_clean();
    } catch (Throwable $e) {
        if (ob_get_length() !== false) @ob_end_clean();
        try { if (class_exists(Logger::class, true)) Logger::systemError($e); } catch (Throwable $_) {}
        $errHtml = class_exists(Templates::class, true) ? Templates::render('pages/error.php', ['message' => 'Internal server error', 'user' => null]) : '<h1>Internal server error</h1>';
        return ['ret' => ['content' => $errHtml, 'status' => 500], 'content' => $errHtml];
    }

    return ['ret' => $ret, 'content' => $out];
})($handlerPath, $sharedForInclude, $params);

// --- Special handling for handlers that return JSON (API style) ---
// If the handler returned an array with a 'json' key, treat it as an API response.
// Expected shape from handler: ['status'=>int, 'json'=>array, 'headers'=>array]
if (is_array($handlerResult['ret']) && array_key_exists('json', $handlerResult['ret'])) {
    $ret = $handlerResult['ret'];
    // status
    $status = isset($ret['status']) ? (int)$ret['status'] : 200;
    if ($status < 100 || $status >= 600) $status = 200;
    http_response_code($status);

    // custom headers (if any)
    $headers = $ret['headers'] ?? [];
    if (is_array($headers)) {
        foreach ($headers as $hn => $hv) {
            // allow string or array values
            if (is_array($hv)) {
                foreach ($hv as $v) header((string)$hn . ': ' . (string)$v, false);
            } else {
                header((string)$hn . ': ' . (string)$hv, false);
            }
        }
    }

    // default content-type for API
    if (!headers_sent()) header('Content-Type: application/json; charset=utf-8');

    // encode JSON safely
    $jsonBody = $handlerResult['ret']['json'];
    $encoded = json_encode($jsonBody, JSON_UNESCAPED_UNICODE);
    if ($encoded === false) {
        // fallback minimal response
        echo json_encode(['success' => false, 'message' => 'Server error (json encode)'], JSON_UNESCAPED_UNICODE);
    } else {
        echo $encoded;
    }
    // ensure we stop further processing
    exit;
}

// --- If headers were already sent (redirect etc.), flush captured output and stop ---
if (headers_sent()) {
    if (!empty($handlerResult['content'])) echo $handlerResult['content'];
    return;
}

// --- Normalize handler return into $result (template | content | vars) ---
$result = ['template' => null, 'content' => null, 'vars' => []];
if (is_array($handlerResult['ret'])) {
    if (!empty($handlerResult['ret']['template'])) $result['template'] = (string)$handlerResult['ret']['template'];
    if (!empty($handlerResult['ret']['content']))  $result['content']  = (string)$handlerResult['ret']['content'];
    if (!empty($handlerResult['ret']['vars']) && is_array($handlerResult['ret']['vars'])) $result['vars'] = $handlerResult['ret']['vars'];
}
// --- Apply optional HTTP status code returned by handler ---
if (isset($handlerResult['ret']['status'])) {
    $status = (int) $handlerResult['ret']['status'];
    if ($status >= 100 && $status < 600) {
        http_response_code($status);
    }
}
// Prefer echoed content if handler didn't set 'content' explicitly
if ($result['content'] === null && $handlerResult['content'] !== '') {
    $result['content'] = $handlerResult['content'];
}

// --- Decide which trustedShared keys to pass to the template (sharedForTemplate) ---
$sharedForTemplate = [];
try {
    if (method_exists(TrustedShared::class, 'select')) {
        $sharedForTemplate = TrustedShared::select($trustedShared, $shareSpec);
    } else {
        $sharedForTemplate = $shareSpec === true ? $trustedShared : [];
    }
} catch (Throwable $_) {
    $sharedForTemplate = $shareSpec === true ? $trustedShared : [];
}

// --- Compose final variables for template ---
// We want to PROTECT trustedShared from being overwritten by handler vars,
// so we merge handler vars first, then sharedForTemplate (shared wins).
$contentVars = array_merge($result['vars'], $sharedForTemplate);

// --- Ensure navActive is available to header/footer ---
$trustedShared['navActive'] = $contentVars['navActive']
    ?? ($matchedRouteKey ?? $routeCandidate ?? '');

// --- Render selection logic ---
$contentHtml = '';

if (!empty($result['template'])) {
    $template = $result['template'];

    // Prevent path traversal and absolute paths.
    if (strpos($template, '..') !== false || strpos($template, "\0") !== false || (isset($template[0]) && $template[0] === '/')) {
        try { if (class_exists(Logger::class, true)) Logger::warn('Invalid template path returned by handler', null, ['template' => $template]); } catch (Throwable $_) {}
        $contentHtml = Templates::render('pages/error.php', ['message' => 'Invalid template', 'user' => $user]);
    } else {
        // Resolve to templates directory: templates/<template>
        $tplPath = __DIR__ . '/templates/' . ltrim($template, '/');
        if (!is_file($tplPath) || !is_readable($tplPath)) {
            try { if (class_exists(Logger::class, true)) Logger::warn('Template file missing', null, ['template' => $template, 'path' => $tplPath]); } catch (Throwable $_) {}
            $contentHtml = Templates::render('pages/error.php', ['message' => 'Template not found', 'user' => $user]);
        } else {
            // Call renderer with final vars so template receives db, categories, user, etc.
            $contentHtml = Templates::render($template, $contentVars);
        }
    }

} elseif (!empty($contentVars['VAR'])) {
    // handler returned raw HTML via vars['VAR']
    $contentHtml = (string) $contentVars['VAR'];
} elseif (!empty($result['content'])) {
    $contentHtml = $result['content'];
} else {
    $contentHtml = Templates::render('pages/error.php', ['message' => 'Empty content', 'user' => $user]);
}

// --- ensure content-type header ---
if (!headers_sent()) header('Content-Type: text/html; charset=utf-8');

// If fragment request — return only content (no header/footer)
if (!empty($isFragmentRequest)) {
    if (!headers_sent()) header('Content-Type: text/html; charset=utf-8');
    echo $contentHtml;
    return; // nebo exit;
}

// otherwise render full page as before
echo Templates::render('partials/header.php', $trustedShared);
echo $contentHtml;
echo Templates::render('partials/footer.php', $trustedShared);
// done