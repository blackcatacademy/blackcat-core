<?php
declare(strict_types=1);

/**
 * libs/Mailer.php
 *
 * Mailer WITHOUT DKIM. Minimal dependencies: KeyManager, Crypto, EmailTemplates, Validator, Logger.
 * No OpenSSL usage. No libsodium required.
 *
 * Config expectations:
 *  $config['smtp'] = [...];
 *  $config['paths']['keys'] = '/path/to/keys' (optional, used by Crypto/KeyManager)
 *  $config['app_domain'] = 'example.com' // used for Message-ID
 *
 * This Mailer:
 *  - enqueues encrypted notifications into `notifications` table
 *  - worker (processPendingNotifications) decrypts, validates, renders and sends via SMTP
 *  - implements retry/backoff and locking
 */

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as PHPMailerException;

final class Mailer
{
    private static ?array $config = null;
    private static ?PDO $pdo = null;
    private static bool $inited = false;

    /** @var ?string path to keys dir (optional) */
    private static ?string $keysDir = null;

    public static function init(array $config, PDO $pdo): void
    {
        if (!class_exists('KeyManager') || !class_exists('Crypto') || !class_exists('Validator') || !class_exists('EmailTemplates')) {
            throw new RuntimeException('Mailer init failed: required libs missing (KeyManager, Crypto, Validator, EmailTemplates).');
        }
        if (!class_exists('Logger')) {
            throw new RuntimeException('Mailer init failed: Logger missing.');
        }
        if (!class_exists('\PHPMailer\PHPMailer\PHPMailer')) {
            throw new RuntimeException('Mailer init failed: PHPMailer not available. Ensure bootstrap loads PHPMailer.');
        }
        self::$config = $config;
        self::$pdo = $pdo;

        // initialize Crypto if needed (KeyManager backed)
        $keysDir = $config['paths']['keys'] ?? null;
        try {
            Crypto::initFromKeyManager($keysDir);
            self::$keysDir = $keysDir;
        } catch (\Throwable $e) {
            Logger::systemError($e);
            throw new RuntimeException('Mailer init: Crypto initialization failed.');
        }

        // No DKIM required/handled here (host provider signs mail or not).
        self::$inited = true;
    }

    public static function enqueue(array $payloadArr, int $maxRetries = 0): int
    {
        if (!self::$inited) throw new RuntimeException('Mailer not initialized.');

        $configMax = (int)(self::$config['smtp']['max_retries'] ?? 0);
        if ($maxRetries <= 0) $maxRetries = $configMax > 0 ? $configMax : 6;

        $json = json_encode($payloadArr, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new RuntimeException('Failed to encode notification payload to JSON.');
        }
        $templateName = $payloadArr['template'] ?? '';
        if (!Validator::validateNotificationPayload($json, $templateName)) {
            throw new RuntimeException('Invalid notification payload.');
        }

        $keysDir = self::$keysDir ?? (self::$config['paths']['keys'] ?? null);
        $emailKeyInfo = KeyManager::getEmailKeyInfo($keysDir); // ['raw'=>binary,'version'=>'vN']
        $keyRaw = $emailKeyInfo['raw'] ?? null;
        if ($keyRaw === null) {
            throw new RuntimeException('Email key not available.');
        }

        $cipher = Crypto::encryptWithKeyBytes($json, $keyRaw, 'binary');

        try { KeyManager::memzero($keyRaw); } catch (\Throwable $_) {}
        unset($keyRaw);

        $payloadForDb = json_encode([
            'cipher' => base64_encode($cipher),
            'meta' => [
                'key_version' => $emailKeyInfo['version'] ?? null,
                'created_at'  => gmdate('c'),
            ],
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        // optional: protect against extremely large payloads
        if (strlen($payloadForDb) > 2000000) { // 2MB safe-guard (adjust as needed)
            Logger::systemMessage('error', 'Mailer enqueue failed: payload too large', null, ['size' => strlen($payloadForDb)]);
            throw new RuntimeException('Notification payload too large.');
        }

        // získat user_id z payloadu
        $userId = null;
        if (isset($payloadArr['user_id'])) {
            $userId = (int)$payloadArr['user_id'];
        } elseif (isset($payloadArr['userId'])) {
            $userId = (int)$payloadArr['userId'];
        }

        // --- SPEC. PŘÍPAD: newsletter_subscribe_confirm může mít user_id null ---
        $template = $payloadArr['template'] ?? '';
        $allowNoUserId = in_array($template, ['newsletter_subscribe_confirm', 'newsletter_welcome'], true);

        if (($userId === null || $userId <= 0) && !$allowNoUserId) {
            Logger::systemMessage('error', 'Mailer enqueue failed: missing/invalid user_id in payload', null, ['template' => $payloadArr['template'] ?? null]);
            throw new \InvalidArgumentException('Mailer::enqueue requires valid user_id in payload.');
        }

        // ověření existence uživatele jen pokud máme platné user_id
        if ($userId !== null && $userId > 0) {
            try {
                $chk = self::$pdo->prepare('SELECT 1 FROM pouzivatelia WHERE id = ? LIMIT 1');
                $chk->execute([$userId]);
                if (!$chk->fetchColumn()) {
                    Logger::systemMessage('error', 'Mailer enqueue failed: user_id does not exist', $userId, ['template' => $payloadArr['template'] ?? null]);
                    throw new \RuntimeException("Mailer::enqueue: user_id {$userId} does not exist.");
                }
            } catch (\Throwable $e) {
                Logger::systemMessage('error', 'Mailer enqueue DB check failed', $userId, ['exception' => $e->getMessage()]);
                throw $e;
            }
        }

        // vložení notifikace (UTC_TIMESTAMP pro konzistenci)
        try {
            $stmt = self::$pdo->prepare('INSERT INTO notifications (user_id, channel, template, payload, status, retries, max_retries, scheduled_at, created_at) VALUES (?, ?, ?, ?, ?, 0, ?, NULL, UTC_TIMESTAMP())');
            $ok = $stmt->execute([$userId, 'email', $templateName, $payloadForDb, 'pending', $maxRetries]);
            if (!$ok) {
                $err = self::$pdo->errorInfo();
                Logger::systemMessage('error', 'Mailer enqueue DB insert failed', $userId, ['error' => $err[2] ?? $err]);
                throw new RuntimeException('Failed to enqueue notification (DB).');
            }
            $id = (int) self::$pdo->lastInsertId();
            Logger::systemMessage('notice', 'Notification enqueued', $userId, ['id' => $id, 'template' => $templateName]);
            return $id;
        } catch (\Throwable $e) {
            Logger::systemMessage('error', 'Mailer enqueue failed (exception)', $userId, ['exception' => $e->getMessage()]);
            throw $e;
        }
    }

    public static function processPendingNotifications(int $limit = 100): array
    {
        if (!self::$inited) throw new RuntimeException('Mailer not initialized.');
        $report = ['processed' => 0, 'sent' => 0, 'failed' => 0, 'skipped' => 0, 'errors' => []];

        $pdo = self::$pdo;

        // SELECT includes pending/failed ready to send, OR processing with expired lock (stale)
        $fetchSql = '
            SELECT * FROM notifications
            WHERE (
                (status IN (\'pending\', \'failed\') AND (next_attempt_at IS NULL OR next_attempt_at <= NOW()))
                OR
                (status = \'processing\' AND locked_until IS NOT NULL AND locked_until <= NOW())
            )
            ORDER BY priority DESC, created_at ASC
            LIMIT :lim
        ';
        $fetchStmt = $pdo->prepare($fetchSql);
        $fetchStmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $fetchStmt->execute();
        $rows = $fetchStmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as $row) {
            $report['processed']++;
            $id = (int)$row['id'];
            $retries = (int)$row['retries'];
            $maxRetries = (int)$row['max_retries'];

            try {
                // Try to atomically claim (re-lock also stale 'processing' rows)
                $upd = $pdo->prepare('UPDATE notifications SET status = ?, locked_by = ?, locked_until = DATE_ADD(NOW(), INTERVAL 300 SECOND) WHERE id = ? AND (status IN (\'pending\', \'failed\') OR (status = \'processing\' AND (locked_until IS NULL OR locked_until <= NOW())))');
                $lockedBy = 'worker-http';
                $ok = $upd->execute(['processing', $lockedBy, $id]);
                if (!$ok || $upd->rowCount() === 0) {
                    $report['skipped']++;
                    continue;
                }

                // payload is JSON column with base64 cipher
                $payloadColRaw = $row['payload'];
                $payloadCol = null;
                if ($payloadColRaw !== null && $payloadColRaw !== '') {
                    $payloadCol = json_decode($payloadColRaw, true);
                }
                if (!is_array($payloadCol) || empty($payloadCol['cipher'])) {
                    self::markFailed($id, $retries, $maxRetries, 'payload_db_malformed');
                    $report['failed']++;
                    Logger::systemMessage('warning', 'Notification payload DB malformed', null, ['id' => $id]);
                    continue;
                }
                $cipher = base64_decode($payloadCol['cipher'], true);
                if ($cipher === false) {
                    self::markFailed($id, $retries, $maxRetries, 'payload_base64_invalid');
                    $report['failed']++;
                    Logger::systemMessage('warning', 'Notification payload base64 invalid', null, ['id' => $id]);
                    continue;
                }

                // get candidates using keysDir
                $keysDir = self::$keysDir ?? (self::$config['paths']['keys'] ?? null);
                $candidates = KeyManager::getAllRawKeys('EMAIL_KEY', $keysDir, 'email_key', KeyManager::keyByteLen());
                // If KeyManager returns structured array, normalize to raw bytes expected by Crypto
                if (is_array($candidates) && !empty($candidates) && isset($candidates[0]) && is_array($candidates[0]) && isset($candidates[0]['raw'])) {
                    $raws = [];
                    foreach ($candidates as $c) {
                        if (isset($c['raw'])) $raws[] = $c['raw'];
                    }
                    $candidates = $raws;
                }

                $plain = Crypto::decryptWithKeyCandidates($cipher, $candidates);
                if ($plain === null) {
                    $errMsg = 'decrypt_failed';
                    self::markFailed($id, $retries, $maxRetries, $errMsg);
                    $report['failed']++;
                    Logger::systemMessage('warning', 'Notification decryption failed', null, ['id' => $id]);
                    continue;
                }

                if (!Validator::validateJson($plain)) {
                    self::markFailed($id, $retries, $maxRetries, 'invalid_json');
                    $report['failed']++;
                    Logger::systemMessage('warning', 'Notification payload JSON invalid', null, ['id' => $id]);
                    continue;
                }

                $payload = json_decode($plain, true);
                $templateName = $payload['template'] ?? '';
                if (!Validator::validateNotificationPayload(json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), $templateName)) {
                    self::markFailed($id, $retries, $maxRetries, 'payload_validation_failed');
                    $report['failed']++;
                    Logger::systemMessage('warning', 'Notification payload validation failed', null, ['id' => $id, 'template' => $templateName]);
                    continue;
                }
                // ensure vars is array so template assignments won't throw notices
                if (!isset($payload['vars']) || !is_array($payload['vars'])) {
                    $payload['vars'] = [];
                }
                // --- attachments processing: download inline_remote and prepare cids before rendering ---
                $attachmentsDownloads = [];
                $totalBytes = 0;
                $maxPerFile = (int)(self::$config['smtp']['max_attachment_bytes'] ?? 2 * 1024 * 1024);     // 2MB default
                $maxTotal   = (int)(self::$config['smtp']['max_total_attachments_bytes'] ?? 8 * 1024 * 1024); // 8MB default

                if (!empty($payload['attachments']) && is_array($payload['attachments'])) {
                    foreach ($payload['attachments'] as $att) {
                        if (!is_array($att) || empty($att['type']) || empty($att['src'])) continue;
                        $type = $att['type'];
                        $src  = $att['src'];
                        $name = $att['name'] ?? basename(parse_url($src, PHP_URL_PATH) ?: 'file.bin');
                        if (!empty($att['cid'])) {
                            $cid = $att['cid'];
                        } else {
                            try {
                                $cid = 'img_' . bin2hex(random_bytes(6));
                            } catch (\Throwable $_) {
                                $cid = 'img_' . uniqid('', true);
                            }
                        }
                // Only handle inline_remote (download & embed) here
                if ($type === 'inline_remote') {
                        $parsed = @parse_url($src);
                        if ($parsed === false) {
                            Logger::systemMessage('warning', 'attachment_invalid_url', null, ['src' => $src]);
                            continue;
                        }
                        $scheme = strtolower($parsed['scheme'] ?? '');
                        if (!in_array($scheme, ['http', 'https'], true)) {
                            Logger::systemMessage('warning', 'attachment_invalid_scheme', null, ['src' => $src]);
                            continue;
                        }
                        // build stream context for TLS verification using smtp config
                        // pokud je allow_url_fopen zakázáno, nezkoušej fopen na https — fallback na remote URL
                        if (!ini_get('allow_url_fopen')) {
                            Logger::systemMessage('warning', 'allow_url_fopen_disabled', null, ['src' => $src]);
                            $varBase = '__img_' . preg_replace('/[^A-Za-z0-9_]/', '_', pathinfo($name, PATHINFO_FILENAME));
                            $payload['vars'][$varBase . '_url'] = $src;
                            continue;
                        }

                        $smtpCfg = self::$config['smtp'] ?? [];
                        $verifyTls = isset($smtpCfg['tls_verify']) ? (bool)$smtpCfg['tls_verify'] : true;
                        $cafile = $smtpCfg['cafile'] ?? null;
                        $ctxOpts = [
                            'ssl' => [
                                'verify_peer' => $verifyTls,
                                'verify_peer_name' => $verifyTls,
                                'allow_self_signed' => !$verifyTls,
                            ]
                        ];
                        if (!empty($cafile)) $ctxOpts['ssl']['cafile'] = $cafile;
                        $ctx = stream_context_create($ctxOpts);

                        $fh = @fopen($src, 'rb', false, $ctx);
                        if ($fh === false) {
                            Logger::systemMessage('warning', 'attachment_remote_fetch_failed', null, ['src' => $src]);
                            continue;
                        }

                        // nastav timeout pro čtení (v sekundách)
                        $readTimeout = (int)(self::$config['smtp']['attachment_fetch_timeout'] ?? 5);
                        stream_set_timeout($fh, max(1, $readTimeout));
                        $bin = stream_get_contents($fh, $maxPerFile + 1);
                        $meta = stream_get_meta_data($fh);
                        fclose($fh);

                        if (!empty($meta['timed_out']) && $meta['timed_out'] === true) {
                            Logger::systemMessage('warning', 'attachment_fetch_timeout', null, ['src' => $src]);
                        }

                        if ($bin === false || $bin === '') {
                            Logger::systemMessage('warning', 'attachment_fetch_failed', null, ['src' => $src]);
                            continue;
                        }
                        if (strlen($bin) > $maxPerFile) {
                            Logger::systemMessage('warning', 'attachment_too_large', null, ['src' => $src, 'size' => strlen($bin)]);
                            continue;
                        }

                        $totalBytes += strlen($bin);
                        if ($totalBytes > $maxTotal) {
                            Logger::systemMessage('warning', 'attachments_total_too_large', null, ['total' => $totalBytes]);
                            break;
                        }

                        $mime = 'application/octet-stream';
                        if (class_exists('finfo')) {
                            try {
                                $finfo = new finfo(FILEINFO_MIME_TYPE);
                                $m = $finfo->buffer($bin);
                                if (is_string($m) && $m !== '') $mime = $m;
                            } catch (\Throwable $_) {
                                // leave $mime fallback
                            }
                        }
                        // (doporučuji whitelistovat: png/jpg/gif/webp)
                        $allowed = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
                        if (!in_array($mime, $allowed, true)) {
                            Logger::systemMessage('warning', 'attachment_not_allowed_mime', null, ['src'=>$src,'mime'=>$mime]);
                            continue;
                        }
                        $attachmentsDownloads[] = [
                            'type' => 'inline',
                            'cid'  => $cid,
                            'bin'  => $bin,
                            'mime' => $mime,
                            'name' => $name,
                        ];

                        // expose cid + fallback url to template vars (use predictable keys)
                        $varBase = '__img_' . preg_replace('/[^A-Za-z0-9_]/', '_', pathinfo($name, PATHINFO_FILENAME));
                        $payload['vars'][$varBase . '_cid'] = $cid;
                        $payload['vars'][$varBase . '_url'] = $src;
                        } else {
                            // for remote usage, expose url to template as fallback
                            if ($type === 'remote') {
                                $varBase = '__img_' . preg_replace('/[^A-Za-z0-9_]/', '_', pathinfo($name, PATHINFO_FILENAME));
                                $payload['vars'][$varBase . '_url'] = $src;
                            }
                            // attach/local 'attach'/'inline' will be handled in sendSmtpEmail() if needed
                        }
                    } // foreach attachments
                }

                // attach downloads to payload for send stage
                if (!empty($attachmentsDownloads)) {
                    $payload['__attachments_downloaded'] = $attachmentsDownloads;
                } else {
                    $payload['__attachments_downloaded'] = [];
                }
                // Ensure template has .php extension (EmailTemplates::render expects .php)
                if ($templateName !== '' && pathinfo($templateName, PATHINFO_EXTENSION) === '') {
                    $templateName .= '.php';
                }
                $rendered = EmailTemplates::renderWithText($templateName, $payload['vars'] ?? []);
                $to = (string)$payload['to'];
                $subject = (string)$payload['subject'];
                $htmlBody = $rendered['html'];
                $textBody = $rendered['text'];

                $sendMeta = self::sendSmtpEmail($to, $subject, $htmlBody, $textBody, $payload);
                if ($sendMeta['ok']) {
                    $stmt = $pdo->prepare('UPDATE notifications SET status = ?, sent_at = NOW(), error = NULL, last_attempt_at = NOW(), retries = ?, updated_at = NOW() WHERE id = ?');
                    $stmt->execute(['sent', $retries + 1, $id]);
                    $report['sent']++;
                    Logger::systemMessage('notice', 'Notification sent', null, ['id' => $id]);
                    // optional: free large memory buffers explicitly
                    if (isset($payload['__attachments_downloaded'])) {
                        unset($payload['__attachments_downloaded']);
                    }
                } else {
                    $err = $sendMeta['error'] ?? 'send_failed';
                    self::markFailed($id, $retries, $maxRetries, $err);
                    $report['failed']++;
                    Logger::systemMessage('warning', 'Notification send failed', null, ['id' => $id, 'error' => $err]);
                }

            } catch (\Throwable $e) {
                try { self::markFailed($id, $retries, $maxRetries, 'exception: ' . $e->getMessage()); } catch (\Throwable $_) {}
                $report['failed']++;
                Logger::systemError($e);
            } finally {
                // clear lock regardless
                $pdo->prepare('UPDATE notifications SET locked_until = NULL, locked_by = NULL WHERE id = ?')->execute([$id]);
            }
        }

        return $report;
    }

    private static function markFailed(int $id, int $retries, int $maxRetries, string $error): void
    {
        $pdo = self::$pdo;
        $retriesNew = $retries + 1;
        $status = $retriesNew >= $maxRetries ? 'failed' : 'pending';
        $delaySeconds = (int) pow(2, min($retries, 6)) * 60;
        if ($delaySeconds < 60) $delaySeconds = 60;
        $nextAttempt = date('Y-m-d H:i:s', time() + $delaySeconds);

        $stmt = $pdo->prepare('UPDATE notifications SET status = ?, retries = ?, error = ?, next_attempt_at = ?, last_attempt_at = NOW(), updated_at = NOW() WHERE id = ?');
        $stmt->execute([$status, $retriesNew, $error, $nextAttempt, $id]);
    }

    /**
     * Send email using PHPMailer.
     *
     * Returns ['ok'=>bool,'error'=>null|string]
     */
    private static function sendSmtpEmail(string $to, string $subject, string $htmlBody, string $textBody, array $payload): array
    {
        if (!self::$config || !isset(self::$config['smtp'])) {
            throw new RuntimeException('SMTP config missing.');
        }
        $smtp = self::$config['smtp'];
        $host = trim((string)($smtp['host'] ?? ''));
        $port = (int)($smtp['port'] ?? 0);
        $user = (string)($smtp['user'] ?? '');
        $pass = (string)($smtp['pass'] ?? '');
        $fromEmail = trim((string)($smtp['from_email'] ?? ($smtp['user'] ?? '')));
        $fromName = (string)($smtp['from_name'] ?? '');
        $secure = strtolower(trim((string)($smtp['secure'] ?? ''))); // '', 'ssl', 'tls'
        $timeout = max(1, (int)($smtp['timeout'] ?? 10));

        $verifyTls = isset($smtp['tls_verify']) ? (bool)$smtp['tls_verify'] : true;
        $cafile = $smtp['cafile'] ?? null;
        $envelopeFrom = $smtp['envelope_from'] ?? $fromEmail;

        if ($host === '') {
            return ['ok' => false, 'error' => 'smtp_host_missing'];
        }
        if ($fromEmail === '' || !filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) {
            return ['ok' => false, 'error' => 'smtp_from_email_invalid'];
        }

        $fromName = preg_replace("/[\r\n]+/", ' ', $fromName);
        $subject = preg_replace("/[\r\n]+/", ' ', $subject);

        $rcpts = array_filter(array_map('trim', preg_split('/[,;]+/', $to)));
        if (empty($rcpts)) {
            return ['ok' => false, 'error' => 'no_recipients'];
        }
        foreach ($rcpts as $r) {
            if (!Validator::validateEmail($r)) {
                return ['ok' => false, 'error' => 'invalid_recipient: ' . $r];
            }
        }

        if ($port === 0) {
            if ($secure === 'ssl') $port = 465;
            elseif ($secure === 'tls') $port = 587;
            else $port = 25;
        }

        // create PHPMailer instance and configure SMTP
        $mail = new PHPMailer(true);
        try {
            $mail->CharSet = 'UTF-8';
            $mail->Encoding = '8bit';
            $mail->isSMTP();
            $mail->Host = $host;
            $mail->Port = $port;
            // secure handling
            if ($secure === 'ssl') {
                if (defined('PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS')) {
                    $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
                } else {
                    $mail->SMTPSecure = 'ssl';
                }
            } elseif ($secure === 'tls') {
                if (defined('PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS')) {
                    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
                } else {
                    $mail->SMTPSecure = 'tls';
                }
            } else {
                $mail->SMTPSecure = '';
            }

            $mail->SMTPAutoTLS = ($secure === 'tls'); // allow PHPMailer to attempt STARTTLS if requested
            $mail->SMTPAuth = $user !== '';
            if ($mail->SMTPAuth) {
                $mail->Username = $user;
                $mail->Password = $pass;
            }

            // TLS/SSL verification options + peer_name (works with PHP OpenSSL extension)
            $peerName = $smtp['peer_name'] ?? $host;
            $smtpOptions = [
                'ssl' => [
                    'verify_peer'      => $verifyTls,
                    'verify_peer_name' => $verifyTls,
                    'allow_self_signed'=> !$verifyTls,
                    'peer_name'        => $peerName,
                ],
            ];
            if (!empty($cafile)) {
                $smtpOptions['ssl']['cafile'] = $cafile;
            }
            $mail->SMTPOptions = $smtpOptions;

            // Timeout and debug
            $mail->Timeout = $timeout;
            // Debug disabled by default; enable >0 only temporarily for diagnostics
            $mail->SMTPDebug = 0;
            $mail->Debugoutput = function($str, $level) {
                // Temporarily log PHPMailer debug lines into your Logger (useful for TLS handshake troubleshooting)
                Logger::systemMessage('debug', 'PHPMailer debug', null, ['level' => $level, 'msg' => $str]);
            };

            // Envelope-from (bounces)
            $mail->Sender = $envelopeFrom;

            // From and recipients
            $mail->setFrom($fromEmail, $fromName !== '' ? $fromName : null);
            foreach ($rcpts as $r) {
                $mail->addAddress($r);
            }

            // Message-ID: try to generate strong random id
            try {
                $msgId = bin2hex(random_bytes(8)) . '@' . (self::$config['app_domain'] ?? 'localhost');
            } catch (\Throwable $e) {
                $msgId = uniqid(bin2hex(random_bytes(4)), true) . '@' . (self::$config['app_domain'] ?? 'localhost');
            }
            // PHPMailer exposes MessageID property
            $mail->MessageID = '<' . $msgId . '>';

            // content
            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body = $htmlBody;
            $mail->AltBody = $textBody;

            // headers
            $mail->addCustomHeader('X-Mailer', 'CustomMailer/1');
            // --- attach downloaded attachments (memory) if present ---
            if (!empty($payload['__attachments_downloaded']) && is_array($payload['__attachments_downloaded'])) {
                foreach ($payload['__attachments_downloaded'] as $d) {
                    $dname = 'file.bin';
                    try {
                        if (!is_array($d)) continue;
                        $dtype = $d['type'] ?? 'inline';
                        $dname = $d['name'] ?? ($d['cid'] ?? $dname);
                        $dmime = $d['mime'] ?? 'application/octet-stream';
                        $dbin  = $d['bin'] ?? null;
                        $dcid  = $d['cid'] ?? null;
                        if ($dbin === null) {
                            Logger::systemMessage('warning', 'attachment_missing_binary', null, ['name' => $dname]);
                            continue;
                        }
                        if ($dtype === 'inline') {
                            if ($dcid === null) {
                                Logger::systemMessage('warning', 'attachment_missing_cid', null, ['name' => $dname]);
                                continue;
                            }
                            // addStringEmbeddedImage(binary, cid, name, encoding, mime)
                            $mail->addStringEmbeddedImage($dbin, $dcid, $dname, 'base64', $dmime);
                        } else {
                            // fallback: attach as regular file in memory
                            $mail->addStringAttachment($dbin, $dname, 'base64', $dmime);
                        }
                    } catch (\Throwable $e) {
                        Logger::systemMessage('warning', 'attachment_add_failed', null, ['err' => $e->getMessage(), 'name' => $dname]);
                        // continue with next attachment
                    }
                }
            }
            // send
            $mail->send();

            // small cleanup to free memory (attachments might be large)
            try {
                $mail->clearAddresses();
                $mail->clearAllRecipients();
                $mail->clearAttachments();
                $mail->clearCustomHeaders();
            } catch (\Throwable $_) { /* ignore cleanup errors */ }

            return ['ok' => true, 'error' => null];
        } catch (PHPMailerException $e) {
            return ['ok' => false, 'error' => 'phpmailer: ' . $e->getMessage()];
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => 'send_exception: ' . $e->getMessage()];
        }
    }
}