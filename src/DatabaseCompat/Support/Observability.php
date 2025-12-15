<?php
declare(strict_types=1);

namespace BlackCat\Database\Support;

use BlackCat\Core\Database;

/**
 * Observability – safe, lightweight, and practical telemetry for SQL and logging.
 *
 * Key features:
 * - Bounded, safe SQL comments (no injection vectors).
 * - Stable generation/propagation of correlation IDs (corr) and TX IDs.
 * - Masking for sensitive parameters (flat and recursive).
 * - Deterministic and random sampling.
 * - Utility helpers for error fields and latency measurements.
 * - Lightweight OpenTelemetry hooks (best-effort, no hard dependency).
 */
final class Observability
{
    /** Maximum SQL comment length (short enough for various engines). */
    private const COMMENT_MAX_LEN = 180;
    /** Maximum individual value length inside the comment (readability/safety). */
    private const COMMENT_VAL_MAX = 64;
    /** Maximum value length in the normalized meta map. */
    private const META_VAL_MAX = 128;

    /** Default list of sensitive keys (lowercase). */
    private static array $defaultSensitiveKeys = [
        'password','pass','secret','token','apikey','api_key','authorization','auth','pin','salt',
        'client_secret','private_key','credit_card','cc','cvv',
    ];

    /**
     * Builds a short SQL comment (safe, trimmed) – useful for pg_stat_activity, etc.
     * Example: "/*app:svc=api,op=list,req=GET,/orders,corr=abcd123.../ "
     */
    public static function sqlComment(array $meta): string
    {
        $meta  = self::normalizeMeta($meta);

        // Preferred order for readability
        $order = ['svc','op','actor','req','corr','db','driver'];
        $pairs = [];

        foreach ($order as $k) {
            if (isset($meta[$k]) && \is_scalar($meta[$k]) && $meta[$k] !== '') {
                $pairs[] = $k . '=' . self::clip(self::cleanVal((string)$meta[$k]), self::COMMENT_VAL_MAX);
                unset($meta[$k]);
            }
        }
        // Remaining keys (alphabetical, deterministic)
        if ($meta) {
            \ksort($meta);
            foreach ($meta as $k => $v) {
                if (\is_scalar($v) && $v !== '') {
                    $pairs[] = self::cleanKey((string)$k) . '=' . self::clip(self::cleanVal((string)$v), self::COMMENT_VAL_MAX);
                }
            }
        }

        if (!$pairs) {
            return '';
        }
        $body = self::clip(\implode(',', $pairs), self::COMMENT_MAX_LEN);
        return '/*app:' . $body . '*/ ';
    }

    /** Returns only the parameter "shape" (without values) for logging. */
    public static function paramsShape(array $params): array
    {
        $shape = [];
        foreach ($params as $k => $v) {
            if (\is_array($v)) {
                $shape[$k] = 'array(' . \count($v) . ')';
            } elseif (\is_object($v)) {
                $shape[$k] = 'object(' . \get_debug_type($v) . ')';
            } elseif ($v === null) {
                $shape[$k] = 'null';
            } else {
                $shape[$k] = \gettype($v);
            }
        }
        return $shape;
    }

    /** Adds implicit metadata (corr, db id/driver, optional env tag) and sanitises keys/values. */
    public static function withDefaults(array $meta, Database $db): array
    {
        // Preserve user-provided corr if already present
        $meta = self::ensureCorr($meta) + $meta;
        $meta += [
            'db'     => $db->id(),
            'driver' => (string)($db->driver() ?? ''),
        ];
        if ($tag = \getenv('BC_SQL_TAG')) {
            $meta['tag'] = self::clip($tag, self::COMMENT_VAL_MAX);
        }
        return self::normalizeMeta($meta);
    }

    /** Simple timing helper in ms relative to t0 (microtime(true)). */
    public static function ms(float $t0): int
    {
        return (int)\round((\microtime(true) - $t0) * 1000);
    }

    /** Extracts safe error fields (SQLSTATE/code + class + short message). */
    public static function errorFields(\Throwable $e): array
    {
        $pdo = $e instanceof \PDOException
            ? $e
            : (($e->getPrevious() instanceof \PDOException) ? $e->getPrevious() : null);

        $sqlstate = $pdo?->errorInfo[0] ?? null;
        $code     = $pdo?->errorInfo[1] ?? ($pdo?->getCode() ?: null);

        return [
            'class'    => \get_debug_type($e),
            'sqlstate' => $sqlstate,
            'code'     => $code,
            'message'  => self::clip(self::singleLine((string)$e->getMessage()), 200),
        ];
    }

    /**
     * Sampling:
     * - meta['sample'] (0..1) or env BC_OBS_SAMPLE
     * - optionally meta['sampleKey'] → deterministic hashing-based sampling
     */
    public static function shouldSample(array $meta): bool
    {
        $rateSource = $meta['sample'] ?? null;
        if ($rateSource === null || $rateSource === '') {
            $env = \getenv('BC_OBS_SAMPLE');
            $rateSource = ($env === false || $env === '') ? 1.0 : $env;
        }
        $rate = \max(0.0, \min(1.0, (float)$rateSource));
        if ($rate <= 0.0) return false;
        if ($rate >= 1.0) return true;

        $key = (string)($meta['sampleKey'] ?? $meta['corr'] ?? '');
        if ($key !== '') {
            // Deterministic: first 8 hex chars of sha1 → [0,1)
            $h = \substr(\sha1($key), 0, 8);
            $bucket = \hexdec($h) / 0xFFFFFFFF;
            return $bucket < $rate;
        }
        // Fallback: random (cryptographically secure, but best-effort)
        try {
            $rnd = \random_int(0, 10_000_000) / 10_000_000;
        } catch (\Throwable) {
            $rnd = \mt_rand() / \mt_getrandmax();
        }
        return $rnd < $rate;
    }

    /* --------------------------- Meta & hygiene --------------------------- */

    /** Sanitizes keys/values, clips lengths, and converts structures to concise type descriptors. */
    private static function normalizeMeta(array $meta): array
    {
        $out = [];
        foreach ($meta as $k => $v) {
            $k = self::cleanKey((string)$k);
            if ($k === '') {
                continue;
            }
            if (\is_scalar($v) || $v === null) {
                $out[$k] = self::clip((string)$v, self::META_VAL_MAX);
            } elseif (\is_array($v)) {
                $out[$k] = 'array(' . \count($v) . ')';
            } else { // object/resource…
                $out[$k] = 'object(' . \get_debug_type($v) . ')';
            }
        }
        return $out;
    }

    /** Only allows [A-Za-z0-9_] in keys (drops everything else). */
    private static function cleanKey(string $k): string
    {
        return \preg_replace('~[^a-z0-9_]+~i', '', $k) ?? '';
    }

    /** Single-line variant – collapses whitespace and removes control characters. */
    private static function singleLine(string $s): string
    {
        // Remove control characters except standard spaces (CR/LF → space)
        $s = \str_replace(["\r", "\n", "\t"], ' ', $s);
        $s = \preg_replace('/[\x00-\x1F\x7F]+/u', '', $s) ?? $s;
        // Compress whitespace
        $s = \preg_replace('/\s+/u', ' ', $s) ?? $s;
        return \trim($s);
    }

    /** Cleans a value destined for SQL comments (drops comment tokens, control chars, compresses). */
    private static function cleanVal(string $s): string
    {
        // Prevent "/* ... */" injection or premature comment termination
        $s = \str_replace(['/*', '*/', '--'], '', $s);
        return self::singleLine($s);
    }

    /** Multibyte-safe clipping to a maximum length. */
    public static function clip(string $s, int $max): string
    {
        if (\function_exists('mb_strlen')) {
            return \mb_strlen($s) > $max ? \mb_substr($s, 0, $max) : $s;
        }
        return \strlen($s) > $max ? \substr($s, 0, $max) : $s;
    }

    /* --------------------------- IDs & correlation --------------------------- */

    /** Short URL/log-friendly hex ID. */
    public static function newId(int $bytes = 8): string
    {
        $bytes = \max(4, $bytes);
        try {
            return \bin2hex(\random_bytes($bytes));
        } catch (\Throwable) {
            // Fallback – deterministic shorter hash of a unique prefix
            $h = \hash('sha256', \uniqid('', true), true);
            return \bin2hex(\substr($h, 0, $bytes));
        }
    }

    /** Ensures a corr (correlation ID). Uses meta['corr'], env BC_CORR, or generates one. */
    public static function ensureCorr(array $meta): array
    {
        if (empty($meta['corr'])) {
            $env = \getenv('BC_CORR');
            $meta['corr'] = ($env && $env !== '') ? self::clip($env, self::COMMENT_VAL_MAX) : self::newId(10);
        }
        return $meta;
    }

    /** Derives child meta from parent (keeps corr, adds extra tags). */
    public static function child(array $parent, array $extra = []): array
    {
        $m = $parent + ['corr' => null];
        $m = self::ensureCorr($m);
        foreach ($extra as $k => $v) {
            $m[$k] = $v;
        }
        return $m;
    }

    /** Short hex TX ID. */
    public static function newTxId(): string
    {
        return self::newId(6);
    }

    /* ------------------- Sensitive keys & masking ------------------- */

    /** Extends the sensitive key list. Call during bootstrap. */
    public static function addSensitiveKeys(string ...$keys): void
    {
        foreach ($keys as $k) {
            $k = \strtolower(\trim($k));
            if ($k !== '') {
                self::$defaultSensitiveKeys[] = $k;
            }
        }
        self::$defaultSensitiveKeys = \array_values(\array_unique(self::$defaultSensitiveKeys));
    }

    /** Returns parameters with masked values (shape/type information preserved). */
    public static function maskParams(array $params, ?array $extra = null): array
    {
        $list = $extra ? \array_merge(self::$defaultSensitiveKeys, \array_map('strtolower', $extra)) : self::$defaultSensitiveKeys;
        $keys = \array_flip(\array_map('strtolower', $list));

        $out  = [];
        foreach ($params as $k => $v) {
            $kk = \ltrim(\is_string($k) ? $k : (string)$k, ':');
            $isSensitive = isset($keys[\strtolower($kk)]);
            if ($isSensitive) {
                $out[$k] = \is_array($v) ? '[array:masked]' : '[masked]';
                continue;
            }
            if (\is_scalar($v) || $v === null) {
                $out[$k] = $v;
            } elseif (\is_array($v)) {
                $out[$k] = 'array(' . \count($v) . ')';
            } else {
                $out[$k] = 'object(' . \get_debug_type($v) . ')';
            }
        }
        return $out;
    }

    /**
     * Recursively masks nested structures based on keys (e.g. JSON payloads).
     */
    public static function maskParamsDeep(array $params, ?array $extra = null): array
    {
        $list = $extra ? \array_merge(self::$defaultSensitiveKeys, \array_map('strtolower', $extra)) : self::$defaultSensitiveKeys;
        $keys = \array_flip(\array_map('strtolower', $list));

        $mask = function ($value, $key) use (&$mask, $keys) {
            $keyNorm = \strtolower(\ltrim((string)$key, ':'));
            if (isset($keys[$keyNorm])) {
                return \is_array($value) ? '[array:masked]' : '[masked]';
            }
            if (\is_array($value)) {
                $out = [];
                foreach ($value as $k => $v) {
                    $out[$k] = $mask($v, (string)$k);
                }
                return $out;
            }
            if (\is_object($value)) {
                return 'object(' . \get_debug_type($value) . ')';
            }
            return \is_scalar($value) || $value === null ? $value : \gettype($value);
        };

        $out = [];
        foreach ($params as $k => $v) {
            $out[$k] = $mask($v, (string)$k);
        }
        return $out;
    }

    /** @var array<string,array{name:string,labels:array<string,string>,value:int}> */
    private static array $counters = [];

    /**
     * Lightweight counter helper for diagnostics.
     *
     * @param array<string,string> $labels
     */
    public static function incrementCounter(string $name, int $value = 1, array $labels = []): void
    {
        $name = self::cleanKey($name);
        if ($name === '') {
            return;
        }
        $normalized = [];
        foreach ($labels as $k => $v) {
            $ck = self::cleanKey((string)$k);
            if ($ck !== '') {
                $normalized[$ck] = (string)$v;
            }
        }
        \ksort($normalized);
        $key = $name . '|' . \json_encode($normalized, JSON_UNESCAPED_SLASHES);
        if (!isset(self::$counters[$key])) {
            self::$counters[$key] = [
                'name'   => $name,
                'labels' => $normalized,
                'value'  => 0,
            ];
        }
        self::$counters[$key]['value'] += $value;
    }

    /**
     * @return list<array{name:string,labels:array<string,string>,value:int}>
     */
    public static function counters(): array
    {
        return array_values(self::$counters);
    }

    /* --------------------------- OpenTelemetry --------------------------- */

    /** Best-effort span start (no hard dependency on a tracing package). */
    public static function startSpan(?string $name): ?object
    {
        try {
            $tracerProvider = 'OpenTelemetry\\\\API\\\\Trace\\\\TracerProvider';
            if (!\class_exists($tracerProvider)) {
                return null;
            }
            $tp = $tracerProvider::getDefaultTracerProvider();
            $tracer = $tp->getTracer('blackcat/db');
            return $tracer->spanBuilder($name ?? 'sql')->startSpan();
        } catch (\Throwable) {
            return null;
        }
    }

    /** Best-effort span end with attribute enrichment. */
    public static function endSpan(?object $span, array $attrs = []): void
    {
        try {
            if (!$span || !\method_exists($span, 'setAttribute') || !\method_exists($span, 'end')) {
                return;
            }
            foreach ($attrs as $k => $v) {
                if (\is_int($v) || \is_float($v) || \is_bool($v) || \is_string($v)) {
                    $span->setAttribute((string)$k, $v);
                } else {
                    $span->setAttribute((string)$k, (string)$v);
                }
            }
            $span->end();
        } catch (\Throwable) {
            // best-effort
        }
    }
}
