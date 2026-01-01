<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

/**
 * Inspect PHP runtime hardening posture.
 *
 * This is a diagnostics / install-time helper (not a sandbox).
 *
 * The goal is to:
 * - detect unsafe PHP/ini settings that increase attack surface,
 * - highlight settings that break TrustKernel Web3 transport (curl vs allow_url_fopen),
 * - provide actionable recommendations.
 */
final class PhpRuntimeInspector
{
    /**
     * @return array{
     *   php:array{
     *     version:string,
     *     sapi:string,
     *     os:string
     *   },
     *   ini:array{
     *     allow_url_fopen:bool,
     *     allow_url_include:bool,
     *     open_basedir:string,
     *     disable_functions:string,
     *     disable_classes:string,
     *     expose_php:bool,
     *     display_errors:bool,
     *     display_startup_errors:bool,
     *     log_errors:bool,
     *     cgi_fix_pathinfo:bool,
     *     enable_dl:bool,
     *     phar_readonly:bool,
     *     session_cookie_secure:bool,
     *     session_cookie_samesite:string,
     *     auto_prepend_file:string,
     *     auto_append_file:string
     *   },
     *   transport:array{
     *     curl_available:bool,
     *     url_fopen_available:bool
     *   },
     *   disabled_functions:list<string>,
     *   findings:list<array{
     *     severity:'info'|'warn'|'error',
     *     code:string,
     *     message:string,
     *     recommendation:?string
     *   }>
     * }
     */
    public static function inspect(): array
    {
        $allowUrlFopen = self::iniBool('allow_url_fopen');
        $allowUrlInclude = self::iniBool('allow_url_include');
        $openBasedir = self::iniString('open_basedir');
        $disableFunctionsRaw = self::iniString('disable_functions');
        $disableClassesRaw = self::iniString('disable_classes');
        $exposePhp = self::iniBool('expose_php');
        $displayErrors = self::iniBool('display_errors');
        $displayStartupErrors = self::iniBool('display_startup_errors');
        $logErrors = self::iniBool('log_errors');
        $cgiFixPathinfo = self::iniBool('cgi.fix_pathinfo');
        $enableDl = self::iniBool('enable_dl');
        $pharReadonly = self::iniBool('phar.readonly');
        $sessionCookieSecure = self::iniBool('session.cookie_secure');
        $sessionCookieSameSite = self::iniString('session.cookie_samesite');
        $autoPrependFile = self::iniString('auto_prepend_file');
        $autoAppendFile = self::iniString('auto_append_file');

        $disabledFunctions = self::parseDisabledFunctions($disableFunctionsRaw);

        $curlAvailable = function_exists('curl_init')
            && function_exists('curl_setopt_array')
            && function_exists('curl_exec')
            && function_exists('curl_getinfo')
            && function_exists('curl_close');

        $urlFopenAvailable = $allowUrlFopen && function_exists('file_get_contents');

        /** @var list<array{severity:'info'|'warn'|'error',code:string,message:string,recommendation:?string}> $findings */
        $findings = [];

        if ($allowUrlInclude) {
            self::addFinding(
                $findings,
                'error',
                'allow_url_include_enabled',
                'allow_url_include is enabled (remote code inclusion risk).',
                'Set php.ini: allow_url_include=0'
            );
        }

        if ($autoPrependFile !== '') {
            self::addFinding(
                $findings,
                'warn',
                'auto_prepend_file_set',
                'auto_prepend_file is set; this increases the risk of hidden code injection.',
                'Prefer leaving auto_prepend_file empty (or strictly control it via immutable config).'
            );
        }
        if ($autoAppendFile !== '') {
            self::addFinding(
                $findings,
                'warn',
                'auto_append_file_set',
                'auto_append_file is set; this increases the risk of hidden code injection.',
                'Prefer leaving auto_append_file empty (or strictly control it via immutable config).'
            );
        }

        if ($displayErrors || $displayStartupErrors) {
            self::addFinding(
                $findings,
                'warn',
                'display_errors_enabled',
                'display_errors/display_startup_errors is enabled (information disclosure).',
                'Set php.ini: display_errors=0 and display_startup_errors=0 (log errors instead).'
            );
        }

        if (!$logErrors) {
            self::addFinding(
                $findings,
                'warn',
                'log_errors_disabled',
                'log_errors is disabled; security incidents become harder to detect.',
                'Set php.ini: log_errors=1'
            );
        }

        if ($exposePhp) {
            self::addFinding(
                $findings,
                'info',
                'expose_php_enabled',
                'expose_php is enabled (X-Powered-By header).',
                'Set php.ini: expose_php=0'
            );
        }

        if ($openBasedir === '') {
            self::addFinding(
                $findings,
                'info',
                'open_basedir_unset',
                'open_basedir is not set (no filesystem sandbox at the PHP layer).',
                'Consider configuring open_basedir to restrict PHP filesystem access (may require per-host tuning).'
            );
        }

        if ($cgiFixPathinfo && in_array(PHP_SAPI, ['fpm-fcgi', 'cgi', 'cgi-fcgi'], true)) {
            self::addFinding(
                $findings,
                'error',
                'cgi_fix_pathinfo_enabled',
                'cgi.fix_pathinfo is enabled (pathinfo/RCE risk in some FPM/CGI configurations).',
                'Set php.ini: cgi.fix_pathinfo=0'
            );
        }

        if ($enableDl) {
            self::addFinding(
                $findings,
                'warn',
                'enable_dl_enabled',
                'enable_dl is enabled (runtime extension loading increases attack surface).',
                'Set php.ini: enable_dl=0'
            );
        }

        if (!$pharReadonly) {
            self::addFinding(
                $findings,
                'warn',
                'phar_readonly_disabled',
                'phar.readonly is disabled; this can increase the risk of phar-based gadget attacks.',
                'Set php.ini: phar.readonly=1'
            );
        }

        if (!$sessionCookieSecure) {
            self::addFinding(
                $findings,
                'info',
                'session_cookie_secure_disabled',
                'session.cookie_secure is disabled; enable it for HTTPS deployments.',
                'Set php.ini: session.cookie_secure=1 (for HTTPS-only sites).'
            );
        }

        if ($sessionCookieSameSite === '') {
            self::addFinding(
                $findings,
                'info',
                'session_cookie_samesite_unset',
                'session.cookie_samesite is not set; consider a strict default for modern browsers.',
                'Set php.ini: session.cookie_samesite=Strict (or Lax if your flows require it).'
            );
        }

        $dangerous = [
            'exec',
            'shell_exec',
            'system',
            'passthru',
            'popen',
            'proc_open',
            'pcntl_exec',
        ];

        $missingDisabled = [];
        foreach ($dangerous as $fn) {
            if (!in_array($fn, $disabledFunctions, true)) {
                $missingDisabled[] = $fn;
            }
        }
        if ($missingDisabled !== []) {
            self::addFinding(
                $findings,
                'info',
                'dangerous_functions_not_disabled',
                'Some dangerous process-exec functions are not disabled: ' . implode(', ', $missingDisabled),
                'Consider php.ini: disable_functions=' . implode(',', $dangerous) . ' (verify your app does not require them).'
            );
        }

        // TrustKernel Web3 transport constraints:
        // - Prefer curl (lets you turn off allow_url_fopen, which reduces SSRF surface).
        // - If curl is not available, allow_url_fopen must be enabled for DefaultWeb3Transport fallback.
        if ($curlAvailable) {
            if ($allowUrlFopen) {
                self::addFinding(
                    $findings,
                    'info',
                    'allow_url_fopen_enabled_with_curl',
                    'allow_url_fopen is enabled even though curl is available.',
                    'For smaller SSRF surface, consider disabling allow_url_fopen and relying on curl for outbound RPC.'
                );
            }
        } else {
            if (!$allowUrlFopen) {
                self::addFinding(
                    $findings,
                    'error',
                    'no_transport_for_web3',
                    'Neither curl is available nor allow_url_fopen is enabled. TrustKernel Web3 RPC will not work.',
                    'Install ext-curl or enable allow_url_fopen.'
                );
            } else {
                self::addFinding(
                    $findings,
                    'warn',
                    'using_url_fopen_transport',
                    'curl is not available; TrustKernel will fall back to allow_url_fopen HTTP transport.',
                    'Prefer installing ext-curl and disabling allow_url_fopen for smaller SSRF surface.'
                );
            }
        }

        return [
            'php' => [
                'version' => PHP_VERSION,
                'sapi' => PHP_SAPI,
                'os' => PHP_OS_FAMILY,
            ],
            'ini' => [
                'allow_url_fopen' => $allowUrlFopen,
                'allow_url_include' => $allowUrlInclude,
                'open_basedir' => $openBasedir,
                'disable_functions' => $disableFunctionsRaw,
                'disable_classes' => $disableClassesRaw,
                'expose_php' => $exposePhp,
                'display_errors' => $displayErrors,
                'display_startup_errors' => $displayStartupErrors,
                'log_errors' => $logErrors,
                'cgi_fix_pathinfo' => $cgiFixPathinfo,
                'enable_dl' => $enableDl,
                'phar_readonly' => $pharReadonly,
                'session_cookie_secure' => $sessionCookieSecure,
                'session_cookie_samesite' => $sessionCookieSameSite,
                'auto_prepend_file' => $autoPrependFile,
                'auto_append_file' => $autoAppendFile,
            ],
            'transport' => [
                'curl_available' => $curlAvailable,
                'url_fopen_available' => $urlFopenAvailable,
            ],
            'disabled_functions' => $disabledFunctions,
            'findings' => $findings,
        ];
    }

    private static function iniString(string $key): string
    {
        $val = ini_get($key);
        if (!is_string($val)) {
            return '';
        }
        $val = trim($val);
        return $val;
    }

    private static function iniBool(string $key): bool
    {
        $val = ini_get($key);
        if ($val === false) {
            return false;
        }
        $s = strtolower(trim((string) $val));

        if ($s === '' || $s === '0' || $s === 'off' || $s === 'false' || $s === 'no') {
            return false;
        }

        return true;
    }

    /**
     * @return list<string>
     */
    private static function parseDisabledFunctions(string $raw): array
    {
        $raw = trim($raw);
        if ($raw === '') {
            return [];
        }

        $parts = preg_split('/[\\s,]+/', $raw) ?: [];
        $out = [];
        foreach ($parts as $p) {
            $p = strtolower(trim((string) $p));
            if ($p === '') {
                continue;
            }
            $out[] = $p;
        }

        return array_values(array_unique($out));
    }

    /**
     * @param list<array{severity:'info'|'warn'|'error',code:string,message:string,recommendation:?string}> $findings
     * @param 'info'|'warn'|'error' $severity
     */
    private static function addFinding(array &$findings, string $severity, string $code, string $message, ?string $recommendation = null): void
    {
        $findings[] = [
            'severity' => $severity,
            'code' => $code,
            'message' => $message,
            'recommendation' => $recommendation,
        ];
    }
}
