<?php
declare(strict_types=1);

final class CSRF
{
    private const DEFAULT_TTL = 3600; // 1 hour
    private const DEFAULT_MAX_TOKENS = 16;

    /** @var array|null Reference to session array (nullable until init) */
    private static ?array $session = null;
    private static int $ttl = self::DEFAULT_TTL;
    private static int $maxTokens = self::DEFAULT_MAX_TOKENS;

    /**
     * Inject reference to session array for testability / explicit init.
     * If $sessionRef is null, will attempt to use global $_SESSION (requires session_start()).
     *
     * Call this AFTER session_start() in production bootstrap.
     *
     * @param array|null $sessionRef  Reference to the session array (usually $_SESSION)
     */
    public static function init(?array &$sessionRef = null, ?int $ttl = null, ?int $maxTokens = null): void
    {
        if ($sessionRef === null) {
            if (session_status() !== PHP_SESSION_ACTIVE) {
                throw new RuntimeException('Session not active — call bootstrap (session_start) first.');
            }
            $sessionRef = &$_SESSION;
        }

        // assign property as a reference to provided session array
        self::$session = &$sessionRef;

        if ($ttl !== null) {
            self::$ttl = $ttl;
        }
        if ($maxTokens !== null) {
            self::$maxTokens = $maxTokens;
        }

        if (!isset(self::$session['csrf_tokens']) || !is_array(self::$session['csrf_tokens'])) {
            self::$session['csrf_tokens'] = [];
        }
    }

    public static function getKeyVersion(): ?string
    {
        try {
            $candidates = Crypto::hmac('probe', 'CSRF_KEY', 'csrf_key', null, true);
            if (!empty($candidates) && is_array($candidates[0]) && isset($candidates[0]['version'])) {
                return $candidates[0]['version'];
            }
        } catch (\Throwable $e) {
            if (class_exists('Logger')) {
                try { Logger::systemError($e); } catch (\Throwable $_) {}
            }
        }
        return null;
    }

    private static function ensureInitialized(): void
    {
        if (self::$session === null) {
            // attempt auto-init from real session if started
            if (session_status() === PHP_SESSION_ACTIVE) {
                $ref = &$_SESSION;
                self::init($ref);
                return;
            }
            throw new RuntimeException('CSRF not initialized. Call CSRF::init() after session_start().');
        }
    }

    public static function token(): string
    {
        self::ensureInitialized();

        $now = time();
        // cleanup expired tokens
        foreach (self::$session['csrf_tokens'] as $k => $meta) {
            if (!isset($meta['exp']) || $meta['exp'] < $now) {
                unset(self::$session['csrf_tokens'][$k]);
            }
        }

        // ensure max tokens - remove oldest by smallest exp
        while (count(self::$session['csrf_tokens']) >= self::$maxTokens) {
            $oldestKey = null;
            $oldestExp = PHP_INT_MAX;
            foreach (self::$session['csrf_tokens'] as $k => $meta) {
                $exp = $meta['exp'] ?? 0;
                if ($exp < $oldestExp) {
                    $oldestExp = $exp;
                    $oldestKey = $k;
                }
            }
            if ($oldestKey !== null) {
                unset(self::$session['csrf_tokens'][$oldestKey]);
            } else {
                break;
            }
        }

        $id = bin2hex(random_bytes(16)); // 32 hex chars
        $val = bin2hex(random_bytes(32)); // 64 hex chars
        self::$session['csrf_tokens'][$id] = ['v' => $val, 'exp' => $now + self::$ttl];

        $mac = bin2hex(Crypto::hmac($id . ':' . $val, 'CSRF_KEY', 'csrf_key'));
        return $id . ':' . $val . ':' . $mac;
    }

    public static function validate(?string $token): bool
    {
        self::ensureInitialized();

        if (!is_string($token)) {
            return false;
        }
        $parts = explode(':', $token, 3);
        if (count($parts) !== 3) {
            return false;
        }
        [$id, $val, $mac] = $parts;

        // validate ID (16 random bytes -> 32 hex chars) and value (32 random bytes -> 64 hex chars)
        if (!ctype_xdigit($id) || strlen($id) !== 32) {
            return false;
        }
        if (!ctype_xdigit($val) || strlen($val) !== 64) {
            return false;
        }

        // --- KEY ROTATION AWARE CHECK ---
        $candidates = Crypto::hmac($id . ':' . $val, 'CSRF_KEY', 'csrf_key', null, true);
        
        // token() vytváří mac jako bin2hex(...), převést zpět na binary
        $macBin = @hex2bin($mac);
        if ($macBin === false || strlen($macBin) !== 32) {
            return false;
        }

        $ok = false;
        foreach ($candidates as $cand) {
            // očekáváme $cand = ['version'=>'vN','hash'=>binary]
            if (is_array($cand) && isset($cand['hash']) && is_string($cand['hash'])) {
                if (hash_equals($cand['hash'], $macBin)) {
                    $ok = true;
                    break;
                }
            } elseif (is_string($cand)) {
                // fallback pro případ, že candidate je přímo binární string
                if (hash_equals($cand, $macBin)) {
                    $ok = true;
                    break;
                }
            }
        }
        if (!$ok) {
            return false;
        }

        // --- CHECK SESSION STATE ---
        if (!isset(self::$session['csrf_tokens'][$id])) {
            return false;
        }

        $stored = self::$session['csrf_tokens'][$id];
        // consume immediately
        unset(self::$session['csrf_tokens'][$id]);

        if (!isset($stored['v']) || !hash_equals($stored['v'], (string)$val)) {
            return false;
        }
        if (!isset($stored['exp']) || $stored['exp'] < time()) {
            return false;
        }
        return true;
    }

    /**
     * Returns a safe hidden input HTML string (escaped).
     */
    public static function hiddenInput(string $name = 'csrf'): string
    {
        $token = self::token();
        return '<input type="hidden" name="' .
            htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'utf-8') .
            '" value="' .
            htmlspecialchars($token, ENT_QUOTES | ENT_SUBSTITUTE, 'utf-8') .
            '">';
    }

    /**
     * Cleanup expired tokens (call at bootstrap if needed).
     */
    public static function cleanup(): void
    {
        self::ensureInitialized();
        $now = time();
        foreach (self::$session['csrf_tokens'] as $k => $meta) {
            if (!isset($meta['exp']) || $meta['exp'] < $now) {
                unset(self::$session['csrf_tokens'][$k]);
            }
        }
    }
}