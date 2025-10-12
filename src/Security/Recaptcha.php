<?php
declare(strict_types=1);

namespace BlackCat\Core\Security;

/**
 * Simple reCAPTCHA v2/v3 verifier.
 *
 * Konstruktor:
 *   new Recaptcha(string $secret, float $minScore = 0.4, array $opts = [])
 *
 * Opcional $opts:
 *   - timeout: int seconds (default 8)
 *   - endpoint: verification URL (default google)
 *   - logger: null | string (class name) | callable | object
 *       If string and class exists, static methods will be used when possible (error/info/debug).
 *       If callable, will be called as fn($level, $message, $ctx = []).
 *       If object, will call $obj->error/$obj->info/$obj->debug when available.
 *   - httpClient: callable(string $url, array $postFields, int $timeout): array ['code'=>int,'body'=>string,'error'=>string|null]
 *   - cache: PSR-16 style cache object with get/set (optional) to cache token results short-term
 */
final class Recaptcha
{
    private string $secret;
    private float $minScore;
    private int $timeout;
    private string $endpoint;
    /** @var null|string|callable|object */
    private $logger;
    /** @var null|callable */
    private $httpClient;
    /** @var null|object */
    private $cache;

    public function __construct(string $secret, float $minScore = 0.4, array $opts = [])
    {
        $this->secret = $secret;
        $this->minScore = max(0.0, min(1.0, $minScore));
        $this->timeout = (int)($opts['timeout'] ?? 8);
        $this->endpoint = $opts['endpoint'] ?? 'https://www.google.com/recaptcha/api/siteverify';

        $loggerOpt = $opts['logger'] ?? null;
        if (is_string($loggerOpt) && class_exists($loggerOpt)) {
            $this->logger = $loggerOpt; // store class name
        } elseif (is_callable($loggerOpt)) {
            $this->logger = $loggerOpt; // store callable
        } elseif (is_object($loggerOpt)) {
            $this->logger = $loggerOpt; // instance with methods
        } else {
            $this->logger = null;
        }

        $this->httpClient = isset($opts['httpClient']) && is_callable($opts['httpClient']) ? $opts['httpClient'] : null;
        $this->cache = $opts['cache'] ?? null;
    }

    /**
     * Verify token.
     * Returns array:
     *  - ok: bool
     *  - score: float|null
     *  - action: string|null
     *  - raw: array|null (decoded JSON)
     *  - error: string|null
     */
    public function verify(string $token, ?string $remoteIp = null): array
    {
        if (trim($token) === '') {
            $this->logDebug('recaptcha token empty');
            return ['ok' => false, 'score' => null, 'action' => null, 'raw' => null, 'error' => 'token_empty'];
        }

        // optional short-term cache: many clients re-send same token — avoid duplicate remote calls
        $cacheKey = null;
        if ($this->cache) {
            $cacheKey = 'recaptcha_' . hash('sha256', $token);
            try {
                $cached = $this->cache->get($cacheKey);
                if (is_array($cached)) {
                    $this->logDebug('recaptcha result from cache');
                    return $cached;
                }
            } catch (\Throwable $_) {
                // ignore cache failures (do not break verification)
                $this->logDebug('recaptcha cache get failed');
            }
        }

        $post = [
            'secret' => $this->secret,
            'response' => $token,
        ];
        if ($remoteIp !== null && $remoteIp !== '') $post['remoteip'] = $remoteIp;

        try {
            $resp = $this->doHttpPost($this->endpoint, $post, $this->timeout);
        } catch (\Throwable $e) {
            $this->logError('Recaptcha HTTP error', ['exception' => (string)$e]);
            return ['ok' => false, 'score' => null, 'action' => null, 'raw' => null, 'error' => 'http_exception'];
        }

        if (!isset($resp['code']) || (int)$resp['code'] !== 200) {
            $this->logError('Recaptcha non-200', ['code' => $resp['code'] ?? null, 'err' => $resp['error'] ?? null]);
            return ['ok' => false, 'score' => null, 'action' => null, 'raw' => null, 'error' => 'recaptcha_http_' . ((int)($resp['code'] ?? 0))];
        }

        $data = json_decode($resp['body'] ?? '', true);
        if (!is_array($data)) {
            $this->logError('Recaptcha invalid json', ['body' => substr((string)($resp['body'] ?? ''), 0, 200)]);
            return ['ok' => false, 'score' => null, 'action' => null, 'raw' => null, 'error' => 'invalid_json'];
        }

        $success = !empty($data['success']);
        $score = isset($data['score']) ? (float)$data['score'] : null;
        $action = isset($data['action']) ? (string)$data['action'] : null;

        $ok = $success && ($score === null || $score >= $this->minScore);

        $result = [
            'ok' => $ok,
            'score' => $score,
            'action' => $action,
            'raw' => $data,
            'error' => $ok ? null : 'recaptcha_failed',
        ];

        // cache short-term (e.g., 60s) to avoid duplicate calls
        if ($this->cache && $cacheKey) {
            try {
                $this->cache->set($cacheKey, $result, 60);
            } catch (\Throwable $_) {
                $this->logDebug('recaptcha cache set failed');
            }
        }

        return $result;
    }

    /**
     * Default HTTP post (curl) or injected callable
     * callable must return ['code'=>int,'body'=>string,'error'=>string|null]
     */
    private function doHttpPost(string $url, array $postFields, int $timeout): array
    {
        if (is_callable($this->httpClient)) {
            try {
                return call_user_func($this->httpClient, $url, $postFields, $timeout);
            } catch (\Throwable $e) {
                $this->logError('recaptcha httpClient callable exception', ['exception' => (string)$e]);
                throw $e;
            }
        }

        // native curl fallback
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($postFields),
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => max(1, (int)floor($timeout / 2)),
        ]);
        $body = curl_exec($ch);
        $err = curl_error($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return ['code' => $code, 'body' => $body === false ? '' : (string)$body, 'error' => $err ?: null];
    }

    /* ----------------------
     * Logging helpers
     * ---------------------- */
    private function logDebug(string $msg, array $ctx = []): void
    {
        $this->log('debug', $msg, $ctx);
    }
    private function logInfo(string $msg, array $ctx = []): void
    {
        $this->log('info', $msg, $ctx);
    }
    private function logError(string $msg, array $ctx = []): void
    {
        $this->log('error', $msg, $ctx);
    }

    /**
     * Generic logger invoker supporting:
     *  - callable: fn($level, $msg, $ctx)
     *  - object: $obj->error/$obj->info/$obj->debug if exists
     *  - class name string: call static methods if available (e.g. Logger::error)
     */
    private function log(string $level, string $msg, array $ctx = []): void
    {
        if ($this->logger === null) return;

        // callable($level, $msg, $ctx)
        if (is_callable($this->logger)) {
            try {
                call_user_func($this->logger, $level, $msg, $ctx);
            } catch (\Throwable $_) {
                // swallow logging errors
            }
            return;
        }

        // object instance with methods
        if (is_object($this->logger)) {
            try {
                if (method_exists($this->logger, $level)) {
                    $this->logger->{$level}($msg, $ctx);
                    return;
                }
                // fallback to generic method names
                if (method_exists($this->logger, 'error') && $level === 'error') {
                    $this->logger->error($msg, $ctx);
                    return;
                }
            } catch (\Throwable $_) {}
            return;
        }

        // string: class name — call static method if exists
        if (is_string($this->logger) && class_exists($this->logger)) {
            try {
                $cls = $this->logger;
                if (method_exists($cls, $level)) {
                    $cls::{$level}($msg, null, $ctx);
                    return;
                }
                // try some common fallbacks
                if ($level === 'error' && method_exists($cls, 'systemError')) {
                    $cls::systemError(new \RuntimeException($msg));
                    return;
                }
                if ($level === 'error' && method_exists($cls, 'systemMessage')) {
                    $cls::systemMessage('error', $msg, null, $ctx);
                    return;
                }
            } catch (\Throwable $_) {}
            return;
        }
    }
}