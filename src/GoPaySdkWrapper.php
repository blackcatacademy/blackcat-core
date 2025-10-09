<?php
declare(strict_types=1);

/**
 * - PSR-3 Logger dependency.
 * - Uses FileCache for OAuth token caching.
 * - Falls back to direct HTTP if official SDK isn't available or fails.
 * - Sanitizes payloads before logging.
 */
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
// use LockingCacheInterface;

final class GoPayTokenException extends \RuntimeException {}
final class GoPayHttpException extends \RuntimeException {}
final class GoPayPaymentException extends \RuntimeException {}

final class GoPaySdkWrapper implements PaymentGatewayInterface
{
    private array $cfg;
    private ?object $client = null;
    private CacheInterface $cache;
    private LoggerInterface $logger;
    private string $cacheKey;
    private const PERMANENT_TOKEN_ERRORS = [
    'invalid_client',
    'invalid_grant',
    'unauthorized_client',
    'invalid_request',
    'unsupported_grant_type',
    'invalid_scope',
    ];

    public function __construct(array $cfg, LoggerInterface $logger, CacheInterface $cache)
    {
        $this->cfg = $cfg;
        $this->logger = $logger;
        $this->cache = $cache;
        $this->cacheKey = 'gopay_oauth_token_' . substr(hash('sha256', ($this->cfg['clientId'] ?? '') . '|' . ($this->cfg['gatewayUrl'] ?? '')), 0, 32);

        // basic config validation
        $required = ['gatewayUrl', 'clientId', 'clientSecret', 'goid', 'scope'];
        $missing = [];
        foreach ($required as $k) {
            if (empty($this->cfg[$k])) {
                $missing[] = $k;
            }
        }
        if (!empty($missing)) {
            throw new \InvalidArgumentException('GoPay config missing keys: ' . implode(',', $missing));
        }

        // prefer robustní init SDK — pokus v try/catch bez spolehnutí na přesné class_exists checks
        try {
            if (class_exists('\GoPay\Api')) {
                $this->client = \GoPay\Api::payments([
                    'goid' => $this->cfg['goid'],
                    'clientId' => $this->cfg['clientId'],
                    'clientSecret' => $this->cfg['clientSecret'],
                    'gatewayUrl' => $this->cfg['gatewayUrl'],
                    'language' => $this->cfg['language'] ?? 'EN',
                    'scope' => $this->cfg['scope'],
                ]);
            }
        } catch (\Throwable $e) {
            $this->client = null;
            $this->logSafe('warning', 'GoPay SDK init failed, falling back to HTTP', ['exception' => $e]);
        }
    }

    /**
     * Safe JSON encode helper (throws on error).
     */
    private function safeJsonEncode(mixed $v): string
    {
        $s = json_encode($v);
        if ($s === false) {
            $msg = json_last_error_msg();
            $ex = new \RuntimeException('JSON encode failed: ' . $msg);
            $this->logSafe('error', 'JSON encode failed', ['phase' => 'json_encode', 'exception' => $ex->getMessage()]);
            throw $ex;
        }
        return $s;
    }

    /**
     * Build HTTP header array from assoc map to avoid fragile numeric indices.
     * @param array $assoc e.g. ['Authorization'=>'Bearer x', 'Content-Type'=>'application/json']
     * @return array ['Key: Value', ...]
     */
    private function buildHeaders(array $assoc): array
    {
        $out = [];
        foreach ($assoc as $k => $v) {
            if ($v === null) continue;
            $key = trim((string)$k);
            if ($key === '') continue;
            if (is_array($v) || is_object($v)) {
                $v = json_encode($v);
            }
            $val = trim((string)$v);
            $out[] = $key . ': ' . $val;
        }
        return $out;
    }

    /**
     * Get OAuth token (cached).
     *
     * @return string
     * @throws \RuntimeException
     */
    public function getToken(): string
    {
        // fast path
        $tokenData = null;
        try { $tokenData = $this->cache->get($this->cacheKey); } catch (\Throwable $_) { $tokenData = null; }
            if (is_array($tokenData) && isset($tokenData['token'], $tokenData['expires_at']) && $tokenData['expires_at'] > time()) {
                return (string)$tokenData['token'];
            }

        $lockKey = 'gopay_token_lock_' . substr(hash('sha256', $this->cacheKey), 0, 12);
        $fp = null;
        $lockToken = null;
        $haveCacheLock = false;

        // 1) try cache-provided lock API
        if ($this->cache instanceof LockingCacheInterface) {
            try {
                $lockToken = $this->cache->acquireLock($lockKey, 10);
                $haveCacheLock = $lockToken !== null;
            } catch (\Throwable $_) {
                $haveCacheLock = false;
                $lockToken = null;
            }
        }

        // 2) fallback to file lock if cache lock not available
        $tempLockPath = sys_get_temp_dir() . '/gopay_token_lock_' . substr(hash('sha256', $this->cacheKey), 0, 12);
        if (!$haveCacheLock) {
            $fp = @fopen($tempLockPath, 'c+');
            if ($fp !== false) {
                $waitUntil = microtime(true) + 10.0; // 10s
                $got = false;
                while (microtime(true) < $waitUntil) {
                    if (flock($fp, LOCK_EX | LOCK_NB)) { $got = true; break; }
                    usleep(100_000 + random_int(0, 50_000));
                }
                if (!$got) {
                    $this->logSafe('warning', 'Could not acquire file lock for token fetch, proceeding without it', ['lock' => $tempLockPath]);
                    fclose($fp); $fp = null;
                }
            }
        }

        try {
            if (!$haveCacheLock && $fp === null) {
                // we couldn't get a lock — short randomized sleep to reduce contention
                usleep((100000 + random_int(0, 200000))); // 100-300 ms
            }
            // double-check cache while holding lock
            try { $tokenData = $this->cache->get($this->cacheKey); } catch (\Throwable $_) { $tokenData = null; }
                if (is_array($tokenData) && isset($tokenData['token'], $tokenData['expires_at']) && $tokenData['expires_at'] > time()) {
                    return (string)$tokenData['token'];
                }

            $url = rtrim($this->cfg['gatewayUrl'], '/') . '/api/oauth2/token';
            $credentials = base64_encode($this->cfg['clientId'] . ':' . $this->cfg['clientSecret']);
            $body = http_build_query(['grant_type' => 'client_credentials', 'scope' => $this->cfg['scope']]);

            $attempts = 3;
            $backoffMs = 200;
            $lastEx = null;
        for ($i = 0; $i < $attempts; $i++) {
            try {
                $assocHeaders = [
                    'Authorization' => 'Basic ' . $credentials,
                    'Accept'        => 'application/json',
                    'Content-Type'  => 'application/x-www-form-urlencoded',
                    'User-Agent'    => 'KnihyOdAutorov/GoPaySdkWrapper/1.1',
                    'Expect'        => '',
                ];
                $headers = $this->buildHeaders($assocHeaders);
                $resp = $this->doRequest('POST', $url, $headers, $body, ['raw' => true, 'expect_json' => true, 'attempts' => 1], $assocHeaders);
                $httpCode = $resp['http_code'] ?? 0;
                $decoded = $resp['json'] ?? null;
                $raw = $resp['body'] ?? '';

                // Successful response
                if ($httpCode >= 200 && $httpCode < 300 && is_array($decoded) && isset($decoded['access_token'], $decoded['expires_in'])) {
                    $expiresIn = (int)$decoded['expires_in'];
                    $safety = max(1, (int)($this->cfg['tokenTtlSafety'] ?? 10));
                    $ttl = max(1, $expiresIn - $safety);

                    // token_type check
                    $tokenType = isset($decoded['token_type']) ? strtolower((string)$decoded['token_type']) : 'bearer';
                    if ($tokenType !== 'bearer') {
                        $this->logSafe('warning', 'getToken: non-standard token_type received', ['token_type' => $decoded['token_type'] ?? null]);
                    }

                    try {
                        $this->cache->set($this->cacheKey, [
                            'token' => (string)$decoded['access_token'],
                            'expires_at' => time() + $ttl,
                            'token_type' => $decoded['token_type'] ?? null,
                            'fetched_at' => time(),
                        ], $ttl);
                    } catch (\Throwable $_) {}
                    return (string)$decoded['access_token'];
                }

                // If 4xx -> likely permanent (invalid client/credentials/etc.) — do not retry
                if ($httpCode >= 400 && $httpCode < 500) {
                    // try to extract specific error code from response body if available
                    $err = is_array($decoded) ? ($decoded['error'] ?? null) : null;
                    $errDesc = is_array($decoded) ? ($decoded['error_description'] ?? null) : null;

                    // treat common OAuth permanent errors as non-retriable
                    if ($err !== null && in_array($err, self::PERMANENT_TOKEN_ERRORS, true)) {
                        $msg = $errDesc ?: json_encode($decoded);
                        $ex = new GoPayTokenException("Permanent token error {$httpCode}: {$err} - {$msg}");
                        $this->logSafe('critical', 'Permanent OAuth token error', ['phase' => 'getToken', 'http_code' => $httpCode, 'error' => $err, 'exception' => $ex->getMessage()]);
                        throw $ex;
                    }

                    // If we don't know the error code, still don't brute-force retry too much.
                    // Treat other 4xx as permanent to avoid useless retries.
                    $msg = is_array($decoded) ? ($decoded['error_description'] ?? json_encode($decoded)) : $raw;
                    $ex = new GoPayTokenException("GoPay token endpoint returned HTTP {$httpCode}: {$msg}");
                    $this->logSafe('error', 'GoPay token endpoint returned 4xx', ['phase' => 'getToken', 'http_code' => $httpCode, 'exception' => $ex->getMessage()]);
                    throw $ex;
                }

                // For 5xx or unexpected status codes -> throw to outer catch and retry (transient)
                $msg = is_array($decoded) ? ($decoded['error_description'] ?? json_encode($decoded)) : $raw;
                throw new GoPayTokenException("GoPay token endpoint returned HTTP {$httpCode}: {$msg}");
            } catch (\Throwable $e) {
                $lastEx = $e;
                $this->logSafe('warning', 'getToken attempt failed', ['attempt' => $i + 1, 'exception' => $e]);
                // exponential backoff for transient failures (but don't sleep after last attempt)
                if ($i < $attempts - 1) {
                    $backoffMs = min($backoffMs * 2, 2000);
                    usleep(($backoffMs + random_int(0, 250)) * 1000);
                }
            }
        }

            $ex = $lastEx ?? new GoPayTokenException('Unknown error obtaining token');
            $this->logSafe('error', 'Failed to obtain GoPay OAuth token after retries', ['phase' => 'getToken', 'exception' => $ex->getMessage()]);
            throw new GoPayTokenException('Failed to obtain GoPay OAuth token: ' . $ex->getMessage());
        } finally {
            // release file lock
            if (isset($fp) && is_resource($fp)) {
                @fflush($fp);
                @flock($fp, LOCK_UN);
                @fclose($fp);
            }
            // release cache lock if used
            if ($lockToken !== null && $this->cache instanceof LockingCacheInterface) {
                try { $this->cache->releaseLock($lockKey, $lockToken); } catch (\Throwable $_) {}
            }
        }
    }

    /**
     * Create payment, return assoc array (decoded JSON).
     *
     * @param array $payload
     * @return array
     * @throws \RuntimeException
     */
    public function createPayment(array $payload): array
    {
        // ensure target.type and goid present
        $goidVal = (string)$this->cfg['goid'];
        if (empty($payload['target'])) {
            $payload['target'] = ['type' => 'ACCOUNT', 'goid' => $goidVal];
        } else {
            $payload['target']['type'] = $payload['target']['type'] ?? 'ACCOUNT';
            $payload['target']['goid'] = (string)($payload['target']['goid'] ?? $goidVal);
        }

        // try SDK first
        if ($this->client !== null && method_exists($this->client, 'createPayment')) {
            try {
                $resp = $this->client->createPayment($payload);
                if (is_object($resp)) $resp = json_decode(json_encode($resp), true);
                if (!is_array($resp)) {
                    throw new GoPayPaymentException('Unexpected SDK response type for createPayment');
                }
                return $resp;
            } catch (\Throwable $e) {
                $this->logSafe('warning', 'SDK createPayment failed, falling back to HTTP', ['exception' => $e]);
                // continue to HTTP fallback
            }
        }

        // HTTP fallback
        $token = $this->getToken();
        $url = rtrim($this->cfg['gatewayUrl'], '/') . '/api/payments/payment';
        $body = $this->safeJsonEncode($payload);
        $reqId = $this->headerId();
        $headerAssoc = [
            'Authorization' => 'Bearer ' . $token,
            'Content-Type'  => 'application/json',
            'Accept'        => 'application/json',
            'User-Agent'    => 'KnihyOdAutorov/GoPaySdkWrapper/1.1',
            // avoid "Expect: 100-continue" delays
            'Expect'        => '',
            'X-Request-Id'  => $reqId,
        ];
        $headers = $this->buildHeaders($headerAssoc);

        $this->logSafe('info', 'GoPay createPayment payload', ['payload' => $this->sanitizeForLog($payload), 'headers' => $this->sanitizeHeadersForLog($headerAssoc)]);

        // perform request with single retry-on-401
        $resp = $this->doRequest('POST', $url, $headers, $body, ['expect_json' => true, 'raw' => true], $headerAssoc);
        $httpCode = $resp['http_code'];
        $json = $resp['json'] ?? null;
        $raw = $resp['body'] ?? '';

        if ($httpCode === 401) {
            $this->logSafe('warning', 'Received 401 when creating payment — clearing token cache and retrying once', []);
            $this->clearTokenCache();
            $token = $this->getToken();
            $headerAssoc['Authorization'] = 'Bearer ' . $token;
            $headers = $this->buildHeaders($headerAssoc);
            $resp = $this->doRequest('POST', $url, $headers, $body, ['expect_json' => true, 'raw' => true], $headerAssoc);
            $httpCode = $resp['http_code'];
            $json = $resp['json'] ?? null;
            $raw = $resp['body'] ?? '';
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            $msg = is_array($json) ? ($json['error_description'] ?? ($json['message'] ?? json_encode($json))) : $raw;
            $ex = new \RuntimeException("GoPay returned HTTP {$httpCode}: {$msg}");
            $this->logSafe('error', 'GoPay returned non-2xx for createPayment', ['phase' => 'createPayment', 'http_code' => $httpCode, 'exception' => $ex->getMessage()]);
            throw $ex;
        }

        if (!is_array($json)) {
            $ex = new \RuntimeException("GoPay returned non-JSON body (HTTP {$httpCode}): {$raw}");
            $this->logSafe('error', 'GoPay returned non-JSON body in createPayment', ['phase' => 'createPayment', 'http_code' => $httpCode, 'body_sample' => substr($raw ?? '', 0, 500)]);
            throw $ex;
        }

        if (!isset($json['id']) && !isset($json['paymentId'])) {
            $ex = new \RuntimeException("GoPay response missing payment id. Response: " . json_encode($json));
            $this->logSafe('error', 'GoPay createPayment response missing payment id', ['phase' => 'createPayment', 'response' => $this->sanitizeForLog($json)]);
            throw $ex;
        } else {
            if(isset($json['id'])){
            try {
                $gatewayPaymentId = (string)$json['id'];
                if ($gatewayPaymentId === '') {
                    throw new \RuntimeException('Empty gateway payment id after normalization');
                }
                $statusCacheKey = 'gopay_status_' . substr(hash('sha256', $gatewayPaymentId), 0, 32);
            // ensure we have a cache object that implements set()
                if ($this->cache instanceof CacheInterface) {
                    try {
                        $this->cache->set($statusCacheKey, ['status' => $json, 'fetched_at' => time()], null);
                        $this->logSafe('info', 'Status cached from createPayment response', ['cache_key' => $statusCacheKey, 'id' => $gatewayPaymentId]);
                    } catch (\Throwable $cacheEx) {
                        $this->logSafe('warning', 'Caching of status from server response failed', ['cache_key' => $statusCacheKey, 'exception' => (string)$cacheEx, 'id' => $gatewayPaymentId]);
                    }
                } else {
                    $this->logSafe('warning', 'No cache instance available to store GoPay status', ['cache_key' => $statusCacheKey]);
                }
            } catch (\Throwable $e) {
                // defensive: don't break the happy path if caching/normalization fails
                $this->logSafe('warning', 'Failed to normalize/cache GoPay createPayment response', ['exception' => $e]);
            }
            }
        }
        return $json;
    }

    /**
     * Get status of payment (cached + fallback).
     *
     * @param string $gatewayPaymentId
     * @return array{status: array, from_cache: bool, fetched_at?: int|null}
     * @throws \RuntimeException on failure
     */
    public function getStatus(string $gatewayPaymentId): array
    {
        // --- safe cache key (no reserved chars) ---
        $statusCacheKey = 'gopay_status_' . substr(hash('sha256', $gatewayPaymentId), 0, 32);

        // Try to get from cache first
        try {
            $cached = $this->cache->get($statusCacheKey);
            if (is_array($cached) && isset($cached['status'])) {
                return ['status' => $cached['status'], 'from_cache' => true, 'fetched_at' => $cached['fetched_at'] ?? null];
            }
        } catch (\Throwable $e) {
            $this->logSafe('warning', 'Status cache get failed', ['cache_key' => $statusCacheKey, 'exception' => $e, 'id' => $gatewayPaymentId]);
        }

        $fromCache = false;
        $respArray = null;

        // SDK path (preferred)
        if ($this->client !== null && method_exists($this->client, 'getStatus')) {
            try {
                $resp = $this->client->getStatus($gatewayPaymentId);
                if (is_object($resp)) $resp = json_decode(json_encode($resp), true);
                if (!is_array($resp)) throw new \RuntimeException('Unexpected SDK response type for getStatus');

                $respArray = $resp;

                // Save permanent cache
                try { $this->cache->set($statusCacheKey, ['status' => $respArray, 'fetched_at' => time()], null); } catch (\Throwable $e) {
                    $this->logSafe('warning', 'Failed to set status cache (SDK path)', ['cache_key' => $statusCacheKey, 'exception' => $e]);
                }
            } catch (\Throwable $e) {
                $this->logSafe('warning', 'SDK getStatus failed, falling back to HTTP', ['exception' => $e]);
            }
        }

        // HTTP fallback
        if ($respArray === null) {
            $token = $this->getToken();
            $url = rtrim($this->cfg['gatewayUrl'], '/') . '/api/payments/payment/' . rawurlencode($gatewayPaymentId);

            $headerAssoc = [
                'Authorization' => 'Bearer ' . $token,
                'Accept'        => 'application/json',
                'User-Agent'    => 'KnihyOdAutorov/GoPaySdkWrapper/1.1',
                'Expect'        => '',
            ];
            $headers = $this->buildHeaders($headerAssoc);
            $resp = $this->doRequest('GET', $url, $headers, null, ['expect_json' => true, 'raw' => true], $headerAssoc);
            $httpCode = $resp['http_code'] ?? 0;
            $json = $resp['json'] ?? null;
            $raw = $resp['body'] ?? '';

            // Retry once if 401
            if ($httpCode === 401) {
                $this->logSafe('warning', 'getStatus received 401, clearing token and retrying', []);
                $this->clearTokenCache();
                $token = $this->getToken();
                $reqId = $this->headerId();
                $headerAssoc = [
                    'Authorization' => 'Bearer ' . $token,
                    'Accept'        => 'application/json',
                    'User-Agent'    => 'KnihyOdAutorov/GoPaySdkWrapper/1.1',
                    'Expect'        => '',
                    'X-Request-Id'  => $reqId,
                ];
                $headers = $this->buildHeaders($headerAssoc);
                $resp = $this->doRequest('GET', $url, $headers, null, ['expect_json' => true, 'raw' => true], $headerAssoc);
                $httpCode = $resp['http_code'] ?? 0;
                $json = $resp['json'] ?? null;
                $raw = $resp['body'] ?? '';
            }

            $this->logSafe('info', 'GoPay getStatus response', ['response' => $this->sanitizeForLog($json ?? $raw)]);

            if ($httpCode < 200 || $httpCode >= 300) {
                $msg = is_array($json) ? ($json['error_description'] ?? ($json['message'] ?? json_encode($json))) : $raw;
                $ex = new \RuntimeException("GoPay getStatus returned HTTP {$httpCode}: {$msg}");
                $this->logSafe('error', 'GoPay getStatus returned non-2xx', ['phase' => 'getStatus', 'id' => $gatewayPaymentId, 'http_code' => $httpCode, 'exception' => $ex->getMessage()]);
                throw $ex;
            }

            if (!is_array($json)) {
                $ex = new \RuntimeException("GoPay getStatus returned non-JSON body (HTTP {$httpCode}): {$raw}");
                $this->logSafe('error', 'GoPay getStatus returned non-JSON body', ['phase' => 'getStatus', 'id' => $gatewayPaymentId, 'body_sample' => substr($raw ?? '', 0, 500)]);
                throw $ex;
            }

            $respArray = $json;

            // Save permanent cache
            try { $this->cache->set($statusCacheKey, ['status' => $respArray, 'fetched_at' => time()], null); } catch (\Throwable $e) {
                $this->logSafe('warning', 'Failed to set status cache (HTTP path)', ['cache_key' => $statusCacheKey, 'exception' => $e, 'id' => $gatewayPaymentId]);
            }
        }

        return ['status' => $respArray, 'from_cache' => $fromCache];
    }

    /**
     * Refund payment.
     *
     * @param string $gatewayPaymentId
     * @param array $args
     * @return array
     */
    public function refundPayment(string $gatewayPaymentId, array $args): array
    {
        if ($this->client !== null && method_exists($this->client, 'refundPayment')) {
            try {
                $resp = $this->client->refundPayment($gatewayPaymentId, $args);
                if (is_object($resp)) $resp = json_decode(json_encode($resp), true);
                if (!is_array($resp)) throw new \RuntimeException('Unexpected SDK response type for refundPayment');
                return $resp;
            } catch (\Throwable $e) {
                $this->logSafe('warning', 'SDK refundPayment failed, falling back to HTTP', ['exception' => $e]);
            }
        }

        $token = $this->getToken();
        $url = rtrim($this->cfg['gatewayUrl'], '/') . '/api/payments/payment/' . rawurlencode($gatewayPaymentId) . '/refund';
        $reqId = $this->headerId();
        $headerAssoc = [
            'Authorization' => 'Bearer ' . $token,
            'Accept'        => 'application/json',
            'Content-Type'  => 'application/x-www-form-urlencoded',
            'User-Agent'    => 'KnihyOdAutorov/GoPaySdkWrapper/1.1',
            'Expect'        => '',
            'X-Request-Id'  => $reqId,
        ];
        $headers = $this->buildHeaders($headerAssoc);
        $body = http_build_query($args);
        $resp = $this->doRequest('POST', $url, $headers, $body, ['expect_json' => true, 'raw' => true], $headerAssoc);
        $httpCode = $resp['http_code'] ?? 0;
        $json = $resp['json'] ?? null;
        $raw = $resp['body'] ?? '';

        // retry once on 401
        if ($httpCode === 401) {
            $this->logSafe('warning', 'refundPayment received 401, clearing token and retrying', []);
            $this->clearTokenCache();
            $token = $this->getToken();
            $headerAssoc['Authorization'] = 'Bearer ' . $token;
            $headers = $this->buildHeaders($headerAssoc);
            $resp = $this->doRequest('POST', $url, $headers, $body, ['expect_json' => true, 'raw' => true], $headerAssoc);
            $httpCode = $resp['http_code'] ?? 0;
            $json = $resp['json'] ?? null;
            $raw = $resp['body'] ?? '';
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            $msg = is_array($json) ? ($json['error_description'] ?? ($json['message'] ?? json_encode($json))) : $raw;
            $ex = new \RuntimeException("GoPay refund returned HTTP {$httpCode}: {$msg}");
            $this->logSafe('error', 'GoPay refund returned non-2xx', ['phase' => 'refundPayment', 'id' => $gatewayPaymentId, 'http_code' => $httpCode, 'exception' => $ex->getMessage()]);
            throw $ex;
        }

        if (!is_array($json)) {
            $ex = new \RuntimeException("GoPay refund returned non-JSON body (HTTP {$httpCode}): {$raw}");
            $this->logSafe('error', 'GoPay refund returned non-JSON body', ['phase' => 'refundPayment', 'id' => $gatewayPaymentId, 'body_sample' => substr($raw ?? '', 0, 500)]);
            throw $ex;
        }

        return $json;
    }

    /* ---------------- helper methods ---------------- */
    /**
     * Safe request-id generator (try random_bytes, fallback to uniqid).
     */
    private function headerId(): string
    {
        try {
            return bin2hex(random_bytes(8));
        } catch (\Throwable $_) {
            // fallback: uniqid + random int to improve entropy
            return bin2hex(uniqid('', true)) . dechex(random_int(0, PHP_INT_MAX));
        }
    }

    /**
     * Clear cached token (best-effort, atomic when lock available).
     */
    private function clearTokenCache(): void
    {
        try {
            // If cache exposes distributed lock API, try to acquire it briefly to avoid race with refresh
            $lockKey = 'gopay_token_lock_clear_' . substr(hash('sha256', $this->cacheKey), 0, 12);
            $lockToken = null;
            $haveLock = false;

            if ($this->cache instanceof LockingCacheInterface) {
                try {
                    $lockToken = $this->cache->acquireLock($lockKey, 5); // short TTL
                    $haveLock = $lockToken !== null;
                } catch (\Throwable $_) {
                    $haveLock = false;
                    $lockToken = null;
                }
            }

            if ($this->cache instanceof CacheInterface) {
                try {
                    $this->cache->delete($this->cacheKey);
                } catch (\Throwable $e) {
                    // fallback to short-expiry if delete failed
                    try { $this->cache->set($this->cacheKey, null, 1); } catch (\Throwable $_) {}
                    $this->logSafe('warning', 'clearTokenCache: delete failed, used short-ttl fallback', ['exception' => $e]);
                }
            } else {
                // last-resort: set empty + 1s TTL so it expires almost immediately
                try { $this->cache->set($this->cacheKey, null, 1); } catch (\Throwable $_) {}
            }
        } catch (\Throwable $e) {
            // Do not throw, just log system error
            $this->logSafe('warning', 'clearTokenCache: unexpected error', ['exception' => $e]);
        } finally {
            // release lock if we acquired it
            if (!empty($lockToken) && $this->cache instanceof LockingCacheInterface) {
                try { $this->cache->releaseLock($lockKey, $lockToken); } catch (\Throwable $_) {}
            }
        }
    }

    /**
     * Central HTTP with retry/backoff.
     */
    private function doRequest(string $method, string $url, array $headers = [], ?string $body = null, array $options = [], ?array $assocHeaders = null): array
    {
        $attempts = $options['attempts'] ?? 3;
        $backoffMs = $options['backoff_ms'] ?? 200;
        $expectJson = $options['expect_json'] ?? false;
        $raw = $options['raw'] ?? false;
        $timeout = $options['timeout'] ?? 15;

        $lastEx = null;
        for ($i = 0; $i < $attempts; $i++) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $options['ssl_verify_peer'] ?? true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

            if (!empty($headers)) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);

            $resp = curl_exec($ch);
            $curlErrNo = curl_errno($ch);
            $curlErr = curl_error($ch);
            $info = curl_getinfo($ch);
            $httpCode = (int)$info['http_code'];

            // close the handle
            curl_close($ch);

            if ($resp === false || $curlErrNo !== 0) {
                $lastEx = new GoPayHttpException('CURL error: ' . $curlErr . ' (' . $curlErrNo . ')');
                $this->logSafe('warning', 'HTTP request failed (curl)', ['url' => $url, 'errno' => $curlErrNo, 'info' => $info, 'headers' => $this->sanitizeHeadersForLog($assocHeaders ?? [])]);
                $backoffMs = min($backoffMs * 2, 2000);
                usleep(($backoffMs + random_int(0, 250)) * 1000);
                continue;
            }

            // decode json when requested/possible
            $decoded = null;
            if ($expectJson) {
                if ($httpCode === 204 || $resp === '') {
                    $decoded = null;
                } else {
                    $decoded = json_decode($resp, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $sample = substr($resp, 0, 1000);
                        $this->logSafe('error', 'Invalid JSON response from remote', ['body_sample' => $sample, 'http_code' => $httpCode]);
                        throw new GoPayHttpException('Invalid JSON response: ' . json_last_error_msg());
                    }
                }
            }
            return ['http_code' => $httpCode, 'body' => $resp, 'json' => $decoded];
        }

        $ex = new GoPayHttpException('HTTP request failed after retries: ' . ($lastEx ? $lastEx->getMessage() : 'unknown'));
        $this->logSafe('error', 'HTTP request failed after retries', ['phase' => 'doRequest', 'url' => $url, 'exception' => $ex->getMessage()]);
        throw $ex;
    }

    /**
     * Generic sanitizer used by other helpers.
     *
     * Options:
     *  - 'sensitive_keys' => array of lowercased keys to redact
     *  - 'max_string' => int max length before truncation (0 = no truncation)
     *  - 'redact_patterns' => array of regexes; strings matching any pattern are redacted
     *  - 'header_mode' => bool when true, treat $data as header assoc (special header rules)
     *  - 'keep_throwable' => bool when true, keep Throwable objects unchanged
     *
     * Returns sanitized copy (same type: string|array|scalar)
     */
    private function sanitize(mixed $data, array $opts = []): mixed
    {
        $defaults = [
            'sensitive_keys' => [
                'account','number','pan','email','phone','phone_number','iban','accountnumber',
                'clientsecret','client_secret','card_number','cardnum','cc_number','ccnum','cvv','cvc',
                'payment_method_token','access_token','refresh_token','clientid','client_id','secret',
                'authorization','auth','password','pwd','token','api_key','apikey'
            ],
            'max_string' => 200,
            'redact_patterns' => [
                '/^(?:[A-Za-z0-9_\-]{20,})$/',         // long token-like
                '/^(?:[A-Fa-f0-9]{20,})$/',             // long hex
                '/^(?:[A-Za-z0-9+\/=]{40,})$/'          // base64-like long
            ],
            'header_mode' => false,
            'keep_throwable' => true,
        ];
        $o = array_merge($defaults, $opts);
        // normalize keys to lowercase for comparison
        $sensitiveKeys = array_map('strtolower', $o['sensitive_keys']);
        $maxString = (int)$o['max_string'];
        $redactPatterns = (array)$o['redact_patterns'];
        $headerMode = (bool)$o['header_mode'];
        $keepThrowable = (bool)$o['keep_throwable'];

        $recurse = function ($v, $k = null) use (&$recurse, $sensitiveKeys, $maxString, $redactPatterns, $headerMode, $keepThrowable) {
            // Keep Throwable objects intact (PSR loggers handle them)
            if ($keepThrowable && $v instanceof \Throwable) {
                return $v;
            }

            // Arrays -> recurse
            if (is_array($v)) {
                $out = [];
                foreach ($v as $kk => $vv) {
                    // if header mode and numeric keys -> preserve as-is (rare)
                    $out[$kk] = $recurse($vv, $kk);
                }
                return $out;
            }

            // Strings -> check sensitive keys/patterns and truncate
            if (is_string($v)) {
                // header mode: keys are header names; treat specially
                if ($headerMode && $k !== null) {
                    $lk = strtolower((string)$k);
                    if (in_array($lk, ['authorization','proxy-authorization'], true)) {
                        return '[REDACTED]';
                    }
                    // for other headers keep them but truncate if too long
                    if ($maxString > 0 && strlen($v) > $maxString) {
                        return substr($v, 0, $maxString) . '…';
                    }
                    return $v;
                }

                // redact by key name
                if ($k !== null && in_array(strtolower((string)$k), $sensitiveKeys, true)) {
                    return '[REDACTED]';
                }

                // redact by pattern (token-like strings)
                foreach ($redactPatterns as $pat) {
                    if (preg_match($pat, $v)) {
                        return '[REDACTED]';
                    }
                }

                // truncate
                if ($maxString > 0 && strlen($v) > $maxString) {
                    return substr($v, 0, $maxString) . '…';
                }
                return $v;
            }

            // Scalars: ints, floats, bool, null -> keep
            return $v;
        };

        return $recurse($data, null);
    }

    /**
     * Backwards-compatible wrapper for previous sanitizeForLog(array|string).
     *
     * Accepts either array or string; returns same type but sanitized.
     */
    private function sanitizeForLog(array|string $data): array|string
    {
        // if string, we treat as value (no key context) -> apply basic redaction+truncate
        if (is_string($data)) {
            return $this->sanitize($data, ['max_string' => 1000, 'keep_throwable' => false]);
        }
        return $this->sanitize($data, ['max_string' => 200, 'keep_throwable' => false]);
    }

    /**
     * Sanitize context for /logSafe (keeps Throwable objects).
     * returns array suitable for PSR-3 context.
     */
    private function sanitizeContext(array $context): array
    {
        return $this->sanitize($context, ['max_string' => 200, 'keep_throwable' => true]);
    }

    /**
     * Sanitize assoc-style headers (not the flat "Key: Value" strings).
     * Returns assoc array where Authorization-like headers are redacted.
     */
    private function sanitizeHeadersForLog(array $assoc): array
    {
        // sanitize() v header_mode zachová assoc klíče a rediguje Authorization
        return $this->sanitize($assoc, ['header_mode' => true, 'max_string' => 200, 'keep_throwable' => false]);
    }

    /**
     * Safe logging wrapper using PSR-3 log().
     *
     * - normalizes common aliases (warn/err/crit)
     * - sanitizes context to avoid leaking secrets or huge payloads
     * - always calls $logger->log(...) which every PSR-3 logger implements
     */
    private function logSafe(string $level, string $message, array $context = []): void
    {
        try {
            if (!isset($this->logger)) return;

            // normalize aliases
            $map = [
                'warn' => 'warning',
                'err'  => 'error',
                'crit' => 'critical',
            ];
            $level = $map[strtolower($level)] ?? strtolower($level);

            // allowed PSR levels
            $allowed = ['emergency','alert','critical','error','warning','notice','info','debug'];
            if (!in_array($level, $allowed, true)) {
                $level = 'info';
            }

            // sanitize context (redact tokens, truncate long text). Keep \Throwable objects intact.
            $ctx = $this->sanitizeContext($context);

            // If there's an 'exception' as string, try to convert it back to something helpful:
            // prefer passing an actual Throwable object if available; otherwise leave message.
            if (isset($ctx['exception']) && is_string($ctx['exception'])) {
                // keep string but place it under 'exception_message' to avoid confusion with Throwable
                $ctx['exception_message'] = $ctx['exception'];
                unset($ctx['exception']);
            }

            // Use PSR-3 standard log method
            $this->logger->log($level, $message, $ctx);
        } catch (\Throwable $_) {
            // Always swallow logging errors — we must not break main flow
        }
    }
}