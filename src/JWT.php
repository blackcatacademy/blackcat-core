<?php
declare(strict_types=1);

final class JWT
{
    private const ALG = 'HS256';
    private const TYP = 'JWT';
    private const ACCESS_TTL = 900; // 15m default
    private const REFRESH_TTL = 1209600; // 14 days default

    private static function keysDir(): ?string {
        return defined('KEYS_DIR') ? KEYS_DIR : ($_ENV['KEYS_DIR'] ?? null);
    }

    private static function base64url_encode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64url_decode(string $b64u): ?string {
        $remainder = strlen($b64u) % 4;
        if ($remainder) $b64u .= str_repeat('=', 4 - $remainder);
        $decoded = base64_decode(strtr($b64u, '-_', '+/'), true);
        return $decoded === false ? null : $decoded;
    }

    private static function now(): int {
        return time();
    }

    private static function generateJti(): string {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b),4));
    }

    /**
     * Issue access token (JWT compact) — returns string.
     */
    public static function issueAccessToken(int $userId, array $extraClaims = [], ?int $ttl = null, ?string $keysDir = null): string
    {
        $ttl = $ttl ?? self::ACCESS_TTL;
        $now = self::now();
        $payload = array_merge([
            'iss' => $_ENV['APP_ISSUER'] ?? 'app',
            'sub' => (string)$userId,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $ttl,
            'jti' => self::generateJti()
        ], $extraClaims);

        $hdr = ['alg' => self::ALG, 'typ' => self::TYP];

        $keysDir = $keysDir ?? self::keysDir();

        // get latest raw key + version
        $info = KeyManager::getRawKeyBytes('JWT_KEY', $keysDir, 'jwt_key', false, KeyManager::keyByteLen());
        $rawKey = $info['raw'];
        $ver = $info['version'] ?? 'v1';
        $hdr['kid'] = $ver;

        $hjson = json_encode($hdr);
        $pjson = json_encode($payload);
        $hb64 = self::base64url_encode($hjson);
        $pb64 = self::base64url_encode($pjson);
        $sigInput = $hb64 . '.' . $pb64;

        $sig = hash_hmac('sha256', $sigInput, $rawKey, true);
        // best-effort memzero of copy
        try { KeyManager::memzero($rawKey); } catch (\Throwable $_) {}

        $sb64 = self::base64url_encode($sig);
        return $hb64 . '.' . $pb64 . '.' . $sb64;
    }

    /**
     * Verify compact JWT. If $checkJtiInDb = true, requires $db (Database/PDO) to check revocation.
     * Returns payload array on success, null on failure.
     */
    public static function verify(string $jwt, ?string $keysDir = null, bool $checkJtiInDb = false, $db = null): ?array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) return null;
        [$hb64, $pb64, $sb64] = $parts;

        $hjson = self::base64url_decode($hb64); if ($hjson === null) return null;
        $pjson = self::base64url_decode($pb64); if ($pjson === null) return null;
        $sig = self::base64url_decode($sb64); if ($sig === null) return null;

        $hdr = json_decode($hjson, true);
        $payload = json_decode($pjson, true);
        if (!is_array($hdr) || !is_array($payload)) return null;

        $sigInput = $hb64 . '.' . $pb64;

        $keysDir = $keysDir ?? self::keysDir();

        // If kid present: try that version first
        $kid = $hdr['kid'] ?? null;
        if (is_string($kid) && $kid !== '') {
            try {
                $info = KeyManager::getRawKeyBytesByVersion('JWT_KEY', $keysDir, 'jwt_key', $kid, KeyManager::keyByteLen());
                $key = $info['raw'];
                $h = hash_hmac('sha256', $sigInput, $key, true);
                try { KeyManager::memzero($key); } catch (\Throwable $_) {}
                if (hash_equals($h, $sig)) {
                    return self::validateClaimsAndReturn($payload, $checkJtiInDb, $db);
                }
            } catch (\Throwable $_) {
                // fallthrough to candidates
            }
        }

        // Try all candidate keys (supports rotation)
        $candidates = KeyManager::deriveHmacCandidates('JWT_KEY', $keysDir, 'jwt_key', $sigInput);
        foreach ($candidates as $cand) {
            if (is_array($cand) && isset($cand['hash'])) {
                if (hash_equals($cand['hash'], $sig)) {
                    return self::validateClaimsAndReturn($payload, $checkJtiInDb, $db);
                }
            } elseif (is_string($cand)) {
                if (hash_equals($cand, $sig)) {
                    return self::validateClaimsAndReturn($payload, $checkJtiInDb, $db);
                }
            }
        }

        return null;
    }

    private static function validateClaimsAndReturn(array $payload, bool $checkDbJti, $db): ?array
    {
        $now = self::now();
        if (isset($payload['nbf']) && (int)$payload['nbf'] > $now) return null;
        if (isset($payload['exp']) && (int)$payload['exp'] < $now) return null;

        if ($checkDbJti) {
            if (!isset($payload['jti'])) return null;
            if ($db === null) return null;

            // Safe DB check: expect $db to be Database or PDO
            $sql = 'SELECT revoked, expires_at FROM jwt_tokens WHERE jti = :jti LIMIT 1';
            try {
                if ($db instanceof \PDO) {
                    $stmt = $db->prepare($sql);
                    $stmt->execute([':jti' => $payload['jti']]);
                    $row = $stmt->fetch(\PDO::FETCH_ASSOC);
                } else {
                    // assume Database wrapper with fetch()
                    $row = $db->fetch($sql, [':jti' => $payload['jti']]);
                }
            } catch (\Throwable $_) {
                return null;
            }
            if (empty($row)) return null;
            if ((int)($row['revoked'] ?? 0) === 1) return null;
            if (!empty($row['expires_at'])) {
                try {
                    $exp = new \DateTimeImmutable($row['expires_at'], new \DateTimeZone('UTC'));
                    if ($exp < new \DateTimeImmutable('now', new \DateTimeZone('UTC'))) return null;
                } catch (\Throwable $_) {
                    return null;
                }
            }
        }

        return $payload;
    }

    /**
     * Issue refresh token (random string) and return array:
     * ['raw' => $refreshTokenRaw, 'hash' => binary32_hash_to_store, 'jti' => jti, 'expires_at' => datetime string]
     *
     * - You must store returned ['hash','jti','expires_at','user_id'] into jwt_tokens table.
     * - Hashing uses PASSWORD_PEPPER via KeyManager HMAC (binary 32).
     */
    public static function generateRefreshToken(int $userId, ?int $ttl = null, ?string $keysDir = null): array
    {
        $ttl = $ttl ?? self::REFRESH_TTL;
        $raw = bin2hex(random_bytes(48)); // 96 hex chars -> treat as opaque
        $jti = self::generateJti();
        $expiresAt = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->modify('+' . $ttl . ' seconds')->format('Y-m-d H:i:s.u');

        $keysDir = $keysDir ?? self::keysDir();

        // Use dedicated refresh token key (recommended) rather than PASSWORD_PEPPER
        // env var name: REFRESH_TOKEN_KEY, basename: 'refresh_token'
        $pepRes = KeyManager::deriveHmacWithLatest('REFRESH_TOKEN_KEY', $keysDir, 'refresh_token', $raw);
        $hash = $pepRes['hash']; // binary 32
        $pepver = $pepRes['version'] ?? null;

        return ['raw' => $raw, 'hash' => $hash, 'pepver' => $pepver, 'jti' => $jti, 'expires_at' => $expiresAt];
    }

    /**
     * Validate refresh token (raw from client) against stored token hash (binary) in DB.
     * Returns bool.
     */
    public static function validateRefreshTokenRaw(string $rawToken, string $storedHashBin, ?string $keysDir = null): bool
    {
        $keysDir = $keysDir ?? self::keysDir();
        // Compute HMAC-SHA256 using latest pepper (and fallback by trying candidates if needed)
        // deriveHmacCandidates for pepper: produce candidate hashes for rotation support
        $cands = KeyManager::deriveHmacCandidates('REFRESH_TOKEN_KEY', $keysDir, 'refresh_token', $rawToken);
        foreach ($cands as $c) {
            if (is_array($c) && isset($c['hash'])) {
                if (hash_equals($c['hash'], $storedHashBin)) return true;
            } elseif (is_string($c)) {
                if (hash_equals($c, $storedHashBin)) return true;
            }
        }
        return false;
    }
}