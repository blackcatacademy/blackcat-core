<?php
declare(strict_types=1);

require_once __DIR__ . '/GoPayStatus.php';
/**
 * Final adapter for GoPay integration.
 *
 * Drop into: libs/GoPayAdapter.php
 *
 * NOTE: adapt GoPay SDK method names if they differ (createPayment, getStatus, refundPayment).
 */
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

final class GoPayAdapter
{
    private Database $db;
    private PaymentGatewayInterface $gopayClient; // instance of your GoPay SDK client (wrapper implementing expected methods)
    private LoggerInterface $logger;
    private ?object $mailer;     // optional Mailer for notifications
    private string $notificationUrl;
    private string $returnUrl;
    private int $reservationTtlSec = 900; // 15 minutes default
    private ?CacheInterface $cache = null;
    private bool $allowCreate = false;

    public function __construct(
        Database $db,
        PaymentGatewayInterface $gopayClient,
        LoggerInterface $logger,
        ?object $mailer = null,
        string $notificationUrl = '',
        string $returnUrl = '',
        ?CacheInterface $cache = null
    ) {
        $this->db = $db;
        $this->gopayClient = $gopayClient;
        $this->logger = $logger;
        $this->mailer = $mailer;
        $this->notificationUrl = $notificationUrl;
        $this->returnUrl = $returnUrl;
        $this->cache = $cache; // may be null, check before use
    }

    /*
    Notes:
    - $gopayClient must implement PaymentGatewayInterface (the wrapper above does).
    - If your existing adapter still typehints `object`, it's fine — this snippet is optional but improves static checks.
    */
    
    /**
     * Fetch order items and normalise structure for payment payload.
     *
     * Returns array of items like:
     *  [
     *    ['title' => '...', 'price_snapshot' => 12.34, 'qty' => 1],
     *    ...
     *  ]
     */
    private function fetchOrderItemsForPayload(int $orderId): array
    {
        try {
            // join na books pokud existuje pro hezčí název, fallback na order_items sloupce
            $sql = 'SELECT oi.*, b.title AS book_title
                    FROM order_items oi
                    LEFT JOIN books b ON b.id = oi.book_id
                    WHERE oi.order_id = :oid';
            $rows = $this->db->fetchAll($sql, [':oid' => $orderId]);

            $out = [];
            foreach ($rows as $r) {
                $title = $r['book_title'] ?? $r['title'] ?? $r['name'] ?? $r['product_name'] ?? 'item';

                $price = (float)($r['price_snapshot'] ?? $r['unit_price'] ?? $r['price'] ?? 0.0);
                $qty = (int)($r['qty'] ?? $r['quantity'] ?? 1);
                $out[] = [
                    'title' => (string)$title,
                    'price_snapshot' => $price,
                    'qty' => max(1, $qty),
                ];
            }

            return $out;
        } catch (\Throwable $e) {
            // non-fatal: loguj a vrať prázdné pole
            $this->logSafe('error', 'fetchOrderItemsForPayload failed', ['phase' => 'fetchOrderItemsForPayload', 'order_id' => $orderId, 'exception'=>$e]);
            return [];
        }
    }
    /**
     * Create a payment for an existing order (order must be created and reservations attached).
     * Returns ['payment_id'=>int, 'redirect_url'=>string, 'gopay'=>mixed]
     */
    public function createPaymentFromOrder(int $orderId, string $idempotencyKey): array
    {
        // require non-empty idempotency key (caller must provide it)
        if (trim((string)$idempotencyKey) === '') {
            throw new \InvalidArgumentException('idempotencyKey is required and must be non-empty');
        }
        $idempHash = hash('sha256', (string)$idempotencyKey);

        // unified idempotency quick-check via helper
        $cached = $this->lookupIdempotency($idempotencyKey);
        if ($cached !== null) {
            $this->logSafe('info', 'Idempotent createPaymentFromOrder hit (lookupIdempotency)', ['order_id' => $orderId]);
            return $cached;
        }

        // Load order (non-locking). We'll re-check & lock inside the short DB transaction
        $order = $this->db->fetch('SELECT * FROM orders WHERE id = :id', [':id' => $orderId]);
        if ($order === null) {
            throw new \RuntimeException('Order not found: ' . $orderId);
        }
        if ($order['status'] !== 'pending') {
            throw new \RuntimeException('Order not in pending state: ' . $orderId);
        }

        // Compose payment payload (keep your existing payload building)
        $amountCents = (int)round((float)$order['total'] * 100);
        $payload = [
            'amount' => $amountCents,
            'currency' => $order['currency'] ?? 'EUR',
            'order_number' => $order['uuid'] ?? (string)$order['id'],
            'callback' => [
                'return_url' => $this->returnUrl,
                'notification_url' => $this->notificationUrl,
            ],
            'order_description' => 'Objednávka ' . ($order['uuid'] ?? $order['id']),
            // items nastavíme níže
        ];
        $payload['items'] = array_map(function($it){
            return [
                'name' => $it['title'] ?? 'item',
                'amount' => (int)round(((float)($it['price_snapshot'] ?? 0.0))*100),
                'count' => (int)($it['qty'] ?? 1)
            ];
        }, $this->fetchOrderItemsForPayload($orderId));
        // verify totals (defensive)
        $sumItems = 0;
        foreach ($payload['items'] as $it) {
            if (!isset($it['amount']) || !is_int($it['amount']) || $it['amount'] < 0) {
                throw new \RuntimeException('Invalid item amount in payload');
            }
            $sumItems += $it['amount'] * max(1, (int)($it['count'] ?? 1));
        }
        if ($sumItems !== $payload['amount']) {
            // buď loguj a throw (STRICT), nebo jen warn
            $this->logSafe('warning', 'Payment amount mismatch between items and total', ['order_id'=>$orderId,'items_sum'=>$sumItems,'amount'=>$payload['amount']]);
            // volitelně: throw new \RuntimeException('Payment amount mismatch');
        }
        // ===== Idempotency reservation (prevents race) =====
        try {
            $this->db->prepareAndRun(
                'INSERT INTO idempotency_keys (key_hash, payment_id, ttl_seconds, created_at)
                VALUES (:k, NULL, :ttl, NOW())
                ON DUPLICATE KEY UPDATE key_hash = key_hash',
                [':k' => $idempHash, ':ttl' => 86400]
            );
        } catch (\Throwable $e) {
            // if duplicate -> someone else reserved/created; fallback to lookup
            $this->logSafe('info', 'Idempotency reservation exists, falling back to lookup', ['order_id'=>$orderId]);
            $cached = $this->lookupIdempotency($idempotencyKey);
            if ($cached !== null) return $cached;
            // otherwise, continue (race not resolved) — but at least we tried
        }
        // emergency: re-check idempotency one more time under DB lock
        $existing = $this->lookupIdempotency($idempotencyKey);
        if ($existing !== null) {
            $this->logSafe('info', 'Idempotency hit during createPaymentFromOrder second-check', ['order_id'=>$orderId]);
            return $existing;
        }
        // 2) Provisionální payment row (with re-check & FOR UPDATE lock)
        $provisionPaymentId = null;
        try {
            $this->db->transaction(function (Database $d) use ($orderId, $order, &$provisionPaymentId) {
                // re-lock order and ensure still pending
                $row = $d->fetch('SELECT id, status, total, currency FROM orders WHERE id = :id FOR UPDATE', [':id' => $orderId]);
                if ($row === null) {
                    throw new \RuntimeException('Order disappeared during processing: ' . $orderId);
                }
                if ($row['status'] !== 'pending') {
                    throw new \RuntimeException('Order no longer pending: ' . $orderId);
                }

                $d->prepareAndRun(
                    'INSERT INTO payments (order_id, gateway, transaction_id, status, amount, currency, details, created_at) 
                    VALUES (:oid, :gw, NULL, :st, :amt, :cur, NULL, NOW())',
                    [
                        ':oid' => $orderId,
                        ':gw' => 'gopay',
                        ':st' => 'initiated',
                        ':amt' => $this->safeDecimal($row['total']),
                        ':cur' => $row['currency'] ?? 'EUR'
                    ]
                );
                $provisionPaymentId = (int)$d->lastInsertId();
            });
        } catch (\Throwable $e) {
            $this->logSafe('error', 'provision_payment failed', ['phase'=>'provision_payment','exception'=>(string)$e]);
            throw $e;
        }

        // 3) Call GoPay
        try {
            $this->logSafe('info', 'Calling GoPay createPayment', ['order_id' => $orderId, 'payload' => $this->sanitizeForLog($payload)]);
            $gopayResponse = $this->gopayClient->createPayment($payload);
        } catch (\Throwable $e) {
            // Attempt to mark provisioned payment as failed to aid reconciliation
            try {
                if ($provisionPaymentId !== null) {
                    $this->db->prepareAndRun('UPDATE payments SET status = :st, details = :det, updated_at = NOW() WHERE id = :id', [
                        ':st' => 'failed',
                        ':det' => $this->jsonEncodeSafe(['error' => (string)$e]) ?? '{"error":"encoding_failed"}',
                        ':id' => $provisionPaymentId
                    ]);
                } else {
                    $this->logSafe('warning', 'Attempted to mark provisioned payment as failed but provisionPaymentId is null', ['order_id'=>$orderId]);
                }
            } catch (\Throwable $_) {}
            $this->logSafe('error', 'gopay.createPayment failed', ['phase' => 'gopay.createPayment', 'order_id' => $orderId, 'exception'=>$e]);
            throw $e;
        }

        // 4) Persist gateway id/details and idempotency inside transaction
        $this->db->transaction(function (Database $d) use ($orderId, $gopayResponse, $provisionPaymentId, $idempHash) {
            $gwId = $this->extractGatewayPaymentId($gopayResponse);

            // Do payments.details ukládáme JEN kratkou poznámku (ne celý gateway payload).
            // Pokud je něco špatně, detail bude obsahovat chybovou poznámku — jinak malý fingerprint/timestamp.
            $note = [
                'note' => 'gopay_payload_cached',
                'cached_at' => (int)time(),
                'gw_id' => $this->extractGatewayPaymentId($gopayResponse),
            ];
            $detailsJson = $this->jsonEncodeSafe($note) ?? '{}';

            $d->prepareAndRun(
                'UPDATE payments SET transaction_id = :tx, status = :st, details = :det, updated_at = NOW() WHERE id = :id',
                [
                    ':tx' => $gwId,
                    ':st' => 'pending',
                    ':det' => $detailsJson,
                    ':id' => $provisionPaymentId
                ]
            );
            // persist idempotency key in DB (best-effort)
            try {
                $d->prepareAndRun(
                    'INSERT INTO idempotency_keys (key_hash, payment_id, ttl_seconds, created_at)
                    VALUES (:k, :pid, :ttl, NOW(6))
                    ON DUPLICATE KEY UPDATE payment_id = VALUES(payment_id), ttl_seconds = VALUES(ttl_seconds)',
                    [':k' => $idempHash, ':pid' => $provisionPaymentId, ':ttl' => 86400]
                );
            } catch (\Throwable $_) {
                // ignore duplicate key / DB issues
            }

            // DO NOT write FileCache inside DB transaction — write cache after commit using persistIdempotency()
            });

            // AFTER COMMIT: best-effort persist to FileCache (store structured array)
            try {
                $gopayForCache = $this->normalizeGopayResponseToArray($gopayResponse);
                if (empty($gopayForCache)) $gopayForCache = null;

                $payloadArr = [
                    'payment_id'   => $provisionPaymentId,
                    'redirect_url' => $this->extractRedirectUrl($gopayResponse),
                    'gopay'        => $gopayForCache,
                    'order_id'     => $orderId,
                ];

                // persist both DB (already done) and FileCache (best-effort)
                if (!empty($provisionPaymentId) && (int)$provisionPaymentId > 0) {
                    $this->persistIdempotency($idempotencyKey, $payloadArr, $provisionPaymentId);
                } else {
                    $this->logSafe('warning', 'persistIdempotency skipped: invalid provisionPaymentId', [
                        'provisionPaymentId' => $provisionPaymentId,
                        'order_id' => $orderId,
                    ]);
                }

            } catch (\Throwable $e) {
                $this->logSafe('warning', 'persistIdempotency after commit failed', ['exception' => $e]);
            }

        // 5) Return structured response
        $gwId = $this->extractGatewayPaymentId($gopayResponse);
        $paymentId = $this->findPaymentIdByGatewayId($gwId);
        $redirectUrl = $this->extractRedirectUrl($gopayResponse);

        // fallback: pokud nelze najít row podle gateway id, vrať provision id (alespoň něco pro reconciliaci)
        if ($paymentId === null && isset($provisionPaymentId) && $provisionPaymentId !== null) {
            $this->logSafe('warning', 'Could not find payment by gateway id, returning provisional payment id as fallback', ['gw_id'=>$gwId,'provision_id'=>$provisionPaymentId]);
            $paymentId = $provisionPaymentId;
        }

        return [
            'payment_id' => $paymentId,
            'redirect_url' => $redirectUrl,
            'gopay' => $gopayResponse
        ];
    }

    /**
     * Handle GoPay notification by gateway transaction id.
     */
    public function handleNotify(string $gwId, ?bool $allowCreate = null): array
    {
        $lastError = null;
        $allowCreate = $allowCreate ?? $this->allowCreate;
        $gwId = trim((string)$gwId);

        if ($gwId === '') {
            $this->logSafe('warning', 'Notify called without gateway id', ['gwId' => $gwId]);
            throw new \RuntimeException('Webhook missing gateway payment id');
        }

        $status = null;
        $fromCache = false;
        $cacheKey = 'gopay_status_' . substr(hash('sha256', $gwId), 0, 32);

        try {
            $resp = $this->gopayClient->getStatus($gwId);

            if (is_array($resp) && array_key_exists('status', $resp) && is_array($resp['status'])) {
                $status = $resp['status'];
                $fromCache = !empty($resp['from_cache']);
            } else {
                $status = $resp;
                $fromCache = false;
            }
        } catch (\Throwable $e) {
            $lastError = $e;
            $this->logSafe('error', 'gopay.getStatus failed', ['phase' => 'gopay.getStatus', 'gopay_id' => $gwId, 'exception'=>$e]);
        }

        // compute state from the current status
        $gwState = is_array($status) ? ($status['state'] ?? null) : null;
        $statusEnum = GoPayStatus::tryFrom($gwState);

        // If cached and non-permanent -> delete cache and refresh
        if ($fromCache && $statusEnum !== null && $statusEnum->isNonPermanent()) {
            $this->logSafe('info', 'Cached non-permanent status detected, refreshing from GoPay', ['gopay_id'=>$gwId, 'cache_key'=>$cacheKey, 'status'=>$status]);
            try {
                if (isset($this->cache) && $this->cache instanceof \Psr\SimpleCache\CacheInterface) {
                    $this->cache->delete($cacheKey);
                    $this->logSafe('info', 'Deleted non-permanent cached status and will refresh from GoPay', ['gopay_id'=>$gwId, 'cache_key'=>$cacheKey]);
                } else {
                    $this->logSafe('info', 'Wrapper returned from_cache but local cache instance missing - refreshing from GoPay anyway', ['gopay_id'=>$gwId]);
                }
            } catch (\Throwable $e) {
                $lastError = $e;
                try { $this->logSafe('warning', 'Failed to delete status cache', ['cache_key'=>$cacheKey, 'exception'=>$e]); } catch (\Throwable $_) {}
            }

            try {
                $resp2 = $this->gopayClient->getStatus($gwId);
                if (is_array($resp2) && array_key_exists('status', $resp2) && is_array($resp2['status'])) {
                    $status = $resp2['status'];
                    $fromCache = !empty($resp2['from_cache']);
                } else {
                    $status = $resp2;
                    $fromCache = false;
                }
            } catch (\Throwable $e) {
                $lastError = $e;
                $this->logSafe('error', 'gopay.getStatus.refresh failed', ['phase' => 'gopay.getStatus.refresh', 'gopay_id' => $gwId, 'exception'=>$e]);
            }
        }

        $this->logSafe('info', 'GoPay status fetched for notify', ['gopay_id' => $gwId, 'from_cache' => $fromCache, 'status' => $status]);

        // final fallback: if still null, attempt one more time and cache
        if ($status === null) {
            try {
                $status = $this->gopayClient->getStatus($gwId);
            } catch (\Throwable $e) {
                $lastError = $e;
                $this->logSafe('error', 'gopay.getStatus failed', ['phase' => 'gopay.getStatus', 'gopay_id' => $gwId, 'exception'=>$e]);
            }
            if (isset($this->cache) && $this->cache instanceof \Psr\SimpleCache\CacheInterface) {
                try { $this->cache->set($cacheKey, $status, 3600); } catch (\Throwable $_) {}
            }
        }

        // IMPORTANT: recompute gwState/statusEnum from the final authoritative $status
        $gwState = is_array($status) ? ($status['state'] ?? null) : null;
        $statusEnum = GoPayStatus::tryFrom($gwState);

        // safe JSON encode for dedupe hash (avoid warnings if $status is not encodable)
        $jsonForHash = $this->jsonEncodeSafe($status) ?? '';
        $payloadHash = hash('sha256', $jsonForHash);

        // dedupe check — kontrola existujícího webhooku v payment_webhooks
        try {
            $exists = $this->db->fetch(
                'SELECT id FROM payment_webhooks WHERE payload_hash = :h LIMIT 1',
                [':h' => $payloadHash]
            );
        } catch (\Throwable $e) {
            $lastError = $e;
            $this->logSafe('error', 'db.dedupe_check failed', [
                'phase' => 'db.dedupe_check',
                'exception' => $e,
                'payload_hash' => $payloadHash,
            ]);
        }

        if ($exists !== null) {
            $this->logSafe('info', 'Duplicate webhook ignored', [
                'hash' => $payloadHash,
                'gopay_id' => $gwId
            ]);

            // vyhodnotit action podle stavu
            if (!empty($lastError)) {
                $action = 'fail';
            } elseif ($statusEnum?->isNonPermanent() === true) {
                $action = 'delete';
            } else {
                $action = 'done';
            }

            return ['action' => $action];
        }

        // best-effort persist webhook record for audit / debugging
        $paymentId = $this->findPaymentIdByGatewayId($gwId); // may be null
        $this->persistWebhookRecord($gwId, $payloadHash, $status, $fromCache, $paymentId);

        $this->logSafe('info', 'Processing GoPay notify for gateway id: ' . $gwId . ' with new payload hash: ' . $payloadHash);

        // mapovaní statusu (tvoje handling branche nechávam na tebe)
        if ($statusEnum === null) {
            $this->logSafe('warning', 'Unhandled GoPay status', ['gw_state' => $gwState]);
        } else {
            switch ($statusEnum) {
                case GoPayStatus::CREATED: break;
                case GoPayStatus::PAYMENT_METHOD_CHOSEN: break;
                case GoPayStatus::PAID: break;
                case GoPayStatus::AUTHORIZED: break;
                case GoPayStatus::CANCELED: break;
                case GoPayStatus::TIMEOUTED: break;
                case GoPayStatus::REFUNDED: break;
                case GoPayStatus::PARTIALLY_REFUNDED: break;
            }
        }

        $action = 'done';
        if ($statusEnum !== null && $statusEnum->isNonPermanent()) {
            $action = 'delete';
        } elseif ($statusEnum !== null && !$statusEnum->isNonPermanent()) {
            $action = 'done';
        } elseif (!empty($lastError)) {
            $action = 'fail';
        }

        return ['action' => $action];
    }

    public function fetchStatus(string $gopayPaymentId): array
    {
        $statusCacheKey = 'gopay_status_' . substr(hash('sha256', $gopayPaymentId), 0, 32);

        if (!isset($this->cache) || !($this->cache instanceof \Psr\SimpleCache\CacheInterface)) {
            try { $this->logSafe('warning', 'fetchStatus: no cache instance available', ['id'=>$gopayPaymentId]); } catch (\Throwable $_) {}
            return [
                'state' => 'CREATED',
                '_pseudo' => true,
                '_cached' => false,
                '_message' => 'No cache instance available; returning pseudo CREATED.',
            ];
        }

        try {
            $cached = $this->cache->get($statusCacheKey);
        } catch (\Throwable $e) {
            try { $this->logSafe('warning', 'fetchStatus: cache read failed', ['id'=>$gopayPaymentId, 'exception'=>$e]); } catch (\Throwable $_) {}
            $cached = null;
        }

        // fallback pseudo CREATED
        if (!is_array($cached)) {
            try { $this->logSafe('info', 'fetchStatus: cache empty or invalid, returning pseudo CREATED', ['id'=>$gopayPaymentId]); } catch (\Throwable $_) {}
            return [
                'state' => 'CREATED',
                '_pseudo' => true,
                '_cached' => false,
                '_message' => 'No cached gateway status available or invalid format.'
            ];
        }

        // zkus najít top-level state, nebo ve 'status'
        $state = $cached['state'] ?? ($cached['status']['state'] ?? 'CREATED');

        $out = $cached; // vezmi celou strukturu
        $out['_cached'] = true;
        $out['state'] = (string)$state;

        try { $this->logSafe('info', 'fetchStatus: returning cached status', ['cache_key'=>$statusCacheKey, 'id'=>$gopayPaymentId]); } catch (\Throwable $_) {}

        return $out;
    }

    public function refundPayment(string $gopayPaymentId, float $amount): array
    {
        try {
            $amt = (int)round($amount * 100);
            return $this->gopayClient->refundPayment($gopayPaymentId, ['amount' => $amt]);
        } catch (\Throwable $e) {
            $this->logSafe('error', 'gopay_refund failed', ['phase' => 'gopay.refund', 'id' => $gopayPaymentId, 'exception'=>$e]);
            throw $e;
        }
    }

    /* ---------------- helper methods ---------------- */
    
    /**
     * Best-effort persist incoming webhook (audit & dedupe helper).
     * Non-fatal — swallow any DB errors.
     */
    private function persistWebhookRecord(string $gwId, string $payloadHash, $status, bool $fromCache, ?int $paymentId = null): void
    {
        try {
            $payloadJson = $this->jsonEncodeSafe($status);
        } catch (\Throwable $_) {
            $payloadJson = null;
        }

        try {
            $this->db->prepareAndRun(
                'INSERT INTO payment_webhooks (payment_id, gw_id, payload_hash, payload, from_cache, created_at)
                 VALUES (:pid, :gw, :ph, :pl, :fc, UTC_TIMESTAMP(6))',
                [
                    ':pid' => $paymentId,
                    ':gw'  => $gwId,
                    ':ph'  => $payloadHash,
                    ':pl'  => $payloadJson,
                    ':fc'  => $fromCache ? 1 : 0
                ]
            );
        } catch (\Throwable $_) {
            // silent
        }
    }

    private function normalizeGopayResponseToArray(mixed $resp): array
    {
        if (is_array($resp)) return $resp;
        if (is_object($resp)) {
            try {
                $json = $this->jsonEncodeSafe($resp);
                if (!is_string($json) || $json === '') {
                    return [];
                }
                $decoded = $this->jsonDecodeSafe($json);
                return is_array($decoded) ? $decoded : [];
            } catch (\Throwable $_) {
                return [];
            }
        }
        // scalar/fallback
        return ['value' => $resp];
    }

    private function jsonEncodeSafe(mixed $v): ?string
    {
        try {
            return json_encode($v, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
        } catch (\JsonException $e) {
            $this->logSafe('error', 'jsonEncodeSafe failed', ['exception' => (string)$e]);
            return null;
        }
    }

    private function jsonDecodeSafe(string $s): mixed
    {
        try {
            return json_decode($s, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            $this->logSafe('warn', 'jsonDecodeSafe failed', ['exception'=>(string)$e]);
            return null;
        }
    }

    private function logSafe(string $level, string $message, array $context = []): void
    {
        try {
            if (!isset($this->logger)) return;

            // normalize common aliases to PSR names
            $map = [
                'warn' => 'warning',
                'err'  => 'error',
                'crit' => 'critical',
            ];
            $level = $map[$level] ?? $level;

            // PSR-3 expects method names: emergency, alert, critical, error, warning, notice, info, debug
            if (method_exists($this->logger, $level)) {
                $this->logger->{$level}($message, $context);
            } else {
                // fallback: try info()
                if (method_exists($this->logger, 'info')) {
                    $this->logger->info($message, $context);
                }
            }
        } catch (\Throwable $_) {
            // swallow
        }
    }

    private function cacheGetSafe(string $key): mixed
    {
        if (empty($this->cache) || !method_exists($this->cache, 'get')) return null;
        try { return $this->cache->get($key); } catch (\Throwable $_) { return null; }
    }

    private function cacheSetSafe(string $key, mixed $value, int $ttl): void
    {
        if (empty($this->cache) || !method_exists($this->cache, 'set')) return;
        try { $this->cache->set($key, $value, $ttl); } catch (\Throwable $_) {}
    }

    private function cacheDeleteSafe(string $key): void
    {
        if (empty($this->cache) || !method_exists($this->cache, 'delete')) return;
        try { $this->cache->delete($key); } catch (\Throwable $_) {}
    }

    /**
     * Safe cache key builder (PSR-16 safe: žádné ":" atd.)
     */
    private function makeCacheKey(string $idempHash): string
    {
        // používáme md5 pro krátký, PSR-16-safe prefix bez zakázaných znaků
        return 'gopay_idemp_' . md5(($this->notificationUrl ?? '') . '|' . ($this->returnUrl ?? '') . '|' . $idempHash);
    }

    /**
     * Lookup idempotency key (FileCache first, DB fallback).
     * Returns: ['payment_id', 'redirect_url', 'gopay', 'order_id'] or null if miss.
     *
     * Read-only. Never writes to payments table.
     */
    public function lookupIdempotency(string $idempotencyKey): ?array
    {
        $idempotencyKey = trim((string)$idempotencyKey);
        if ($idempotencyKey === '') {
            throw new \InvalidArgumentException('lookupIdempotency: non-empty idempotencyKey required');
        }

        // Optional: only safe chars
        if (!preg_match('/^[A-Za-z0-9._:-]{6,128}$/', $idempotencyKey)) {
            $this->logSafe('warning', 'lookupIdempotency: invalid key format', ['key' => $idempotencyKey]);
            return null;
        }

        $idempHash = hash('sha256', $idempotencyKey);
        $cacheKey  = $this->makeCacheKey($idempHash);

        // ---- 1) Try FileCache
        if (!empty($this->cache) && method_exists($this->cache, 'get')) {
            try {
                $cached = $this->cache->get($cacheKey);
                if (is_array($cached) && isset($cached['payment_id'])) {
                    return $cached;
                }
            } catch (\Throwable $e) {
                $this->logSafe('warning', 'lookupIdempotency: cache read error', ['exception' => $e]);
            }
        }

        // ---- 2) DB fallback
        try {
            $row = $this->db->fetch(
                'SELECT payment_id, order_id, redirect_url, gateway_payload, created_at, ttl_seconds
                FROM idempotency_keys
                WHERE key_hash = :h AND payment_id IS NOT NULL
                LIMIT 1',
                [':h' => $idempHash]
            );

            if (empty($row)) {
                return null;
            } else {
            $this->logSafe('info', 'lookupIdempotency: DB fallback flow', ['row' => $row]);
            }
            $gopay = null;
            if (!empty($row['gateway_payload'])) {
                $gopay = $this->jsonDecodeSafe((string)$row['gateway_payload']);
            }

            $out = [
                'payment_id'   => (int)$row['payment_id'],
                'redirect_url' => $row['redirect_url'] ?? null,
                'gopay'        => $gopay,
                'order_id'     => isset($row['order_id']) ? (int)$row['order_id'] : null,
            ];

            // ---- Cache for next time
            if (!empty($this->cache) && method_exists($this->cache, 'set')) {
                try {
                    $ttl = 86400;
                    if (isset($row['created_at'], $row['ttl_seconds'])) {
                        $expires = strtotime($row['created_at']) + (int)$row['ttl_seconds'];
                        if ($expires > time()) {
                            $ttl = $expires - time();
                        }
                    }
                    $this->cache->set($cacheKey, $out, $ttl);
                } catch (\Throwable $_) {}
            }

            return $out;
        } catch (\Throwable $e) {
            $this->logSafe('error', 'lookupIdempotency: DB read failed', ['exception' => $e]);
            return null;
        }
    }

    /**
     * Persist idempotency: write DB (best-effort) and set FileCache (best-effort).
     * $payload should be an array with payment_id, redirect_url, gopay, etc.
     */
    public function persistIdempotency(string $idempotencyKey, array $payload, int $paymentId): void
    {
        $idempotencyKey = trim((string)$idempotencyKey);
        if ($idempotencyKey === '') {
            throw new \InvalidArgumentException('persistIdempotency: non-empty idempotencyKey required');
        }

        $hash = hash('sha256', $idempotencyKey);
        $redirectUrl = $payload['gw_url'] ?? $payload['payment_redirect'] ?? $payload['redirect_url'] ?? null;
        $payloadJson = $this->jsonEncodeSafe($payload);
        $orderId = isset($payload['order_id']) ? (int)$payload['order_id'] : null;

        try {
            $this->db->prepareAndRun(
                'INSERT INTO idempotency_keys (key_hash, payment_id, order_id, gateway_payload, redirect_url, created_at, ttl_seconds)
                VALUES (:h, :pid, :oid, :payload, :redirect, NOW(6), :ttl)
                ON DUPLICATE KEY UPDATE
                    payment_id = VALUES(payment_id),
                    order_id = VALUES(order_id),
                    gateway_payload = VALUES(gateway_payload),
                    redirect_url = VALUES(redirect_url)',
                [
                    ':h'        => $hash,
                    ':pid'      => $paymentId,
                    ':oid'      => $orderId,
                    ':payload'  => $payloadJson,
                    ':redirect' => $redirectUrl,
                    ':ttl'      => 86400,
                ]
            );
        } catch (\Throwable $e) {
            $this->logSafe('warning', 'persistIdempotency failed', ['exception' => $e]);
        }

        // FileCache best-effort
        if (!empty($this->cache) && method_exists($this->cache, 'set')) {
            try {
                $this->cache->set(
                    $this->makeCacheKey($hash),
                    [
                        'payment_id'   => $paymentId,
                        'order_id'     => $orderId,
                        'redirect_url' => $redirectUrl,
                        'gopay'        => $payload,
                    ],
                    86400
                );
            } catch (\Throwable $_) {}
        }
    }

    private function sanitizeForLog(array $a): array
    {
        // remove sensitive fields if present
        unset($a['card_number'], $a['cvv'], $a['payment_method_token']);
        return $a;
    }

    private function extractGatewayPaymentId($gopayResponse): string
    {
        $arr = [];
        if (is_array($gopayResponse)) {
            $arr = $gopayResponse;
        } elseif (is_object($gopayResponse)) {
            try {
                $arr = json_decode(json_encode($gopayResponse), true, 512, JSON_THROW_ON_ERROR);
            } catch (\Throwable $_) {
                $arr = [];
            }
        } else {
            return (string)$gopayResponse;
        }

        // bezpečné čtení různých cest bez risku notice
        $candidates = [];

        if (isset($arr['id']) && $arr['id'] !== '') $candidates[] = $arr['id'];
        if (isset($arr['paymentId']) && $arr['paymentId'] !== '') $candidates[] = $arr['paymentId'];

        if (isset($arr['payment']) && is_array($arr['payment']) && !empty($arr['payment']['id'])) {
            $candidates[] = $arr['payment']['id'];
        }

        if (isset($arr['data']) && is_array($arr['data']) && !empty($arr['data']['id'])) {
            $candidates[] = $arr['data']['id'];
        }

        foreach ($candidates as $c) {
            if (!empty($c)) return (string)$c;
        }
        return '';
    }

    private function extractRedirectUrl($gopayResponse): ?string
    {
        $arr = [];
        if (is_array($gopayResponse)) {
            $arr = $gopayResponse;
        } elseif (is_object($gopayResponse)) {
            try {
                $arr = json_decode(json_encode($gopayResponse), true, 512, JSON_THROW_ON_ERROR);
            } catch (\Throwable $_) {
                $arr = [];
            }
        } else {
            return null;
        }

        // bezpečné kontroly (bez notice)
        if (isset($arr[0]) && is_array($arr[0]) && !empty($arr[0]['gw_url'])) {
            return (string)$arr[0]['gw_url'];
        }
        if (!empty($arr['gw_url'])) return (string)$arr['gw_url'];
        if (!empty($arr['payment_redirect'])) return (string)$arr['payment_redirect'];
        if (!empty($arr['redirect_url'])) return (string)$arr['redirect_url'];
        if (isset($arr['links']) && is_array($arr['links']) && !empty($arr['links']['redirect'])) return (string)$arr['links']['redirect'];

        return null;
    }

    private function findPaymentIdByGatewayId(string $gwId): ?int
    {
        $row = $this->db->fetch('SELECT id FROM payments WHERE transaction_id = :tx AND gateway = :gw LIMIT 1', [':tx' => $gwId, ':gw' => 'gopay']);
        if (is_array($row) && isset($row['id'])) {
            return (int)$row['id'];
        }
        return null;
    }

    private function safeDecimal($v): string
    {
        return number_format((float)$v, 2, '.', '');
    }
}