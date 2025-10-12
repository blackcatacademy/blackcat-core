<?php
declare(strict_types=1);

namespace BlackCat\Core\Helpers;

use BlackCat\Core\Security\KeyManager;
use BlackCat\Core\Security\Crypto;
use BlackCat\Core\Log\Logger;

final class MailHelper
{
    /**
     * Prepare email crypto & HMAC info.
     *
     * opts:
     *   - email: string (required)
     *   - keysDir: string|null
     *
     * returns [
     *   'email_hash_bin' => binary|null,
     *   'email_hash_version' => string|null,
     *   'email_enc' => binary|null,
     *   'email_enc_key_version' => string|null,
     * ]
     */
    public static function prepareEmailCrypto(array $opts): array
    {
        $email = (string)($opts['email'] ?? '');
        $keysDir = $opts['keysDir'] ?? (defined('KEYS_DIR') ? KEYS_DIR : null);

        $emailHashBin = null;
        $emailHashVer = null;
        $emailEnc = null;
        $emailEncKeyVer = null;

        // derive latest HMAC (best-effort)
        try {
            if (class_exists(KeyManager::class, true) &&
                method_exists(KeyManager::class, 'deriveHmacWithLatest')) {
                $hinfo = KeyManager::deriveHmacWithLatest('EMAIL_HASH_KEY', $keysDir, 'email_hash_key', $email);
                $emailHashBin = $hinfo['hash'] ?? null;
                $emailHashVer = $hinfo['version'] ?? null;
            }
        } catch (\Throwable $e) {
            // log by caller
        }

        // email encryption (best-effort)
        try {
            if (class_exists(Crypto::class, true) &&
                method_exists(Crypto::class, 'initFromKeyManager')) {
                Crypto::initFromKeyManager($keysDir);
                $enc = Crypto::encrypt($email, 'binary');
                if (is_string($enc) && $enc !== '') {
                    $emailEnc = $enc;
                }
                if (method_exists(KeyManager::class, 'locateLatestKeyFile')) {
                    $info = KeyManager::locateLatestKeyFile($keysDir, 'email_key');
                    $emailEncKeyVer = $info['version'] ?? null;
                }
                Crypto::clearKey();
            }
        } catch (\Throwable $e) {
            // log by caller
        }

        return [
            'email_hash_bin' => $emailHashBin,
            'email_hash_version' => $emailHashVer,
            'email_enc' => $emailEnc,
            'email_enc_key_version' => $emailEncKeyVer,
        ];
    }

    /**
     * Build a standardized notification payload for newsletter subscribe confirm.
     * Accepts similar structure to existing code and returns payload array ready for Mailer::enqueue.
     */
    public static function buildSubscribeNotificationPayload(array $opts): array
    {
        $to = $opts['to'] ?? null;
        $subject = $opts['subject'] ?? 'Potvrďte prihlásenie na odber noviniek';
        $template = $opts['template'] ?? 'newsletter_subscribe_confirm';
        $vars = $opts['vars'] ?? [];
        $attachments = $opts['attachments'] ?? [];
        $meta = $opts['meta'] ?? [];
        $subscriberId = $opts['subscriber_id'] ?? null;

        // sanitize recipient(s)
        $to = is_string($to) ? trim($to) : '';

        // sanitize template name (no path traversal)
        $template = preg_replace('/[^A-Za-z0-9_\-]/', '', (string)$template);
        if ($template === '') $template = 'newsletter_subscribe_confirm';

        // ensure attachments is array and sanitize inline_remote urls by whitelist (optional)
        $allowedHosts = $opts['attachment_whitelist'] ?? ['knihyodautorov.sk', 'www.knihyodautorov.sk', 'cdn.knihyodautorov.sk'];
        $outAttachments = [];
        foreach ($attachments as $att) {
            if (!is_array($att) || empty($att['src'])) continue;
            $parsed = @parse_url($att['src']);
            $host = $parsed['host'] ?? '';
            if (in_array($host, $allowedHosts, true)) {
                $outAttachments[] = $att;
            } else {
                // If host disallowed, either skip or convert to 'remote' fallback; skip for safety
                continue;
            }
        }

        $payload = [
            'user_id' => $meta['user_id'] ?? 1,
            'to' => $to,
            'subject' => $subject,
            'template' => $template,
            'vars' => $vars,
            'attachments' => $outAttachments,
            'meta' => $meta,
        ];

        return $payload;
    }

    /**
     * Připraví payload pro Mailer::enqueue z dat kontakt. Vrací pole payloadu.
     *
     * $opts:
     *   - keysDir: optional path to keys (falls back to KEYS_DIR constant if defined)
     */
    public static function buildContactPayload(array $opts): array
    {
        // expected keys: name, email, message, to, subject, user_id, attachments (optional), site, client_ip, user_agent, source
        $required = ['name', 'email', 'message', 'to', 'subject', 'user_id'];
        foreach ($required as $k) {
            if (!array_key_exists($k, $opts)) {
                throw new \InvalidArgumentException("Missing required option: {$k}");
            }
        }

        $keysDir = $opts['keysDir'] ?? (defined('KEYS_DIR') ? KEYS_DIR : null);

        $email = (string)$opts['email'];
        $emailHashBin = null;
        $emailHashVer = null;
        $emailEnc = null;
        $emailEncKeyVer = null;

        // HMAC derive (best-effort)
        try {
            if (class_exists(KeyManager::class, true) && method_exists(KeyManager::class, 'deriveHmacWithLatest')) {
                $hinfo = KeyManager::deriveHmacWithLatest('EMAIL_HASH_KEY', $keysDir, 'email_hash_key', $email);
                $emailHashBin = $hinfo['hash'] ?? null;
                $emailHashVer = $hinfo['version'] ?? null;
            }
        } catch (\Throwable $e) {
            if (class_exists(Logger::class, true)) {
                try { Logger::error('deriveHmacWithLatest failed in MailHelper', null, ['exception' => (string)$e]); } catch (\Throwable $_) {}
            }
            // continue — nonfatal
        }

        // Email encryption (best-effort)
        try {
            if (class_exists(Crypto::class, true) && method_exists(Crypto::class, 'initFromKeyManager')) {
                Crypto::initFromKeyManager($keysDir);
                // Crypto::encrypt returns binary by your code convention
                $enc = Crypto::encrypt($email, 'binary');
                if (is_string($enc) && $enc !== '') {
                    $emailEnc = $enc;
                }
                // locate version if KeyManager supports it
                if (class_exists(KeyManager::class, true) && method_exists(KeyManager::class, 'locateLatestKeyFile')) {
                    $info = KeyManager::locateLatestKeyFile($keysDir, 'email_key');
                    $emailEncKeyVer = $info['version'] ?? null;
                }
                Crypto::clearKey();
            }
        } catch (\Throwable $e) {
            if (class_exists(Logger::class, true)) {
                try { Logger::error('Email encryption failed in MailHelper', null, ['exception' => (string)$e]); } catch (\Throwable $_) {}
            }
            // continue — nonfatal
        }

        // build meta
        $meta = [
            'email_key_version' => $emailEncKeyVer ?? null,
            'email_hash_key_version' => $emailHashVer ?? null,
            'cipher_format' => $emailEnc !== null ? 'aead_xchacha20poly1305_v1_binary' : null,
            'source' => $opts['source'] ?? 'contact_form',
            'remote_ip' => $opts['client_ip'] ?? null,
            'user_agent' => $opts['user_agent'] ?? null,
        ];

        if ($emailEnc !== null) {
            $meta['email_enc_b64'] = base64_encode($emailEnc);
        }
        // memzero sensitive raw buffers
        try {
            if (is_string($emailEnc) && class_exists(KeyManager::class, true) && method_exists(KeyManager::class, 'memzero')) {
                KeyManager::memzero($emailEnc);
            }
            if (is_string($emailHashBin) && class_exists(KeyManager::class, true) && method_exists(KeyManager::class, 'memzero')) {
                KeyManager::memzero($emailHashBin);
            }
        } catch (\Throwable $_) {
            // ignore memzero failures
        }

        $vars = [
            'name' => $opts['name'],
            'email' => $email,
            'message' => $opts['message'],
            'ip' => $opts['client_ip'] ?? null,
            'site' => $opts['site'] ?? ($_SERVER['SERVER_NAME'] ?? ''),
        ];

        $payload = [
            'user_id' => (int)$opts['user_id'],
            'to' => $opts['to'],
            'subject' => $opts['subject'],
            'template' => $opts['template'] ?? 'contact_admin',
            'vars' => $vars,
            'attachments' => $opts['attachments'] ?? [],
            'meta' => $meta,
        ];

        return $payload;
    }
}