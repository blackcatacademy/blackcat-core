<?php
declare(strict_types=1);

namespace BlackCat\Core\Validation;

use DateTime;

/**
 * Class Validator
 *
 * Centralizovaný statický helper pro validaci vstupních dat.
 * - PSR-12 kompatibilní
 * - Nepoužívá globální funkce mimo bezpečné PHP filtry
 * - Žádné side effects (čistě deterministické)
 */
final class Validator
{
    public static function email(string $email): bool
    {
        $email = trim($email);
        return (bool) filter_var($email, FILTER_VALIDATE_EMAIL);
    }

    public static function date(string $date, string $format = 'Y-m-d'): bool
    {
        $d = DateTime::createFromFormat($format, $date);
        return $d && $d->format($format) === $date;
    }

    public static function dateTime(string $dateTime, string $format = 'Y-m-d H:i:s'): bool
    {
        $d = DateTime::createFromFormat($format, $dateTime);
        return $d && $d->format($format) === $dateTime;
    }

    public static function numberInRange(float|int|string $value, float $min, float $max): bool
    {
        if (!is_numeric($value)) {
            return false;
        }
        $f = (float) $value;
        return $f >= $min && $f <= $max;
    }

    public static function currencyCode(string $code, array $allowed = []): bool
    {
        $code = strtoupper(trim($code));
        if (!preg_match('/^[A-Z]{3}$/', $code)) {
            return false;
        }
        if ($allowed && !in_array($code, $allowed, true)) {
            return false;
        }
        return true;
    }

    public static function json(string $json): bool
    {
        $json = trim($json);
        if ($json === '') {
            return false;
        }
        json_decode($json);
        return json_last_error() === JSON_ERROR_NONE;
    }

    public static function passwordStrong(string $pw, int $minLength = 12): bool
    {
        return (
            mb_strlen($pw) >= $minLength &&
            preg_match('/[a-z]/', $pw) &&
            preg_match('/[A-Z]/', $pw) &&
            preg_match('/[0-9]/', $pw) &&
            preg_match('/[\W_]/', $pw)
        );
    }

    public static function stringSanitized(string $s, int $maxLen = 0): string
    {
        $out = preg_replace('/[\x00-\x1F\x7F]/u', '', trim($s));
        return $maxLen > 0 ? mb_substr($out, 0, $maxLen) : $out;
    }

    public static function fileSize(int $sizeBytes, int $maxBytes): bool
    {
        return $sizeBytes > 0 && $sizeBytes <= $maxBytes;
    }

    public static function mimeType(string $mime, array $allowed): bool
    {
        return in_array($mime, $allowed, true);
    }

    /**
     * Validuje JSON payload pro notifikační systém.
     *
     * @param string $json     JSON obsahující notifikaci
     * @param string $template Očekávaný template (např. verify_email)
     */
    public static function notificationPayload(string $json, string $template): bool
    {
        if (!self::json($json)) {
            return false;
        }

        $data = json_decode($json, true);
        if (!is_array($data)) {
            return false;
        }

        $required = ['to', 'subject', 'template', 'vars'];
        foreach ($required as $key) {
            if (!array_key_exists($key, $data)) {
                return false;
            }
        }

        if (!self::email($data['to'])) {
            return false;
        }
        if (!is_string($data['subject']) || trim($data['subject']) === '') {
            return false;
        }
        if (!is_string($data['template']) || trim($data['template']) === '') {
            return false;
        }
        if (!is_array($data['vars'])) {
            return false;
        }

        switch ($template) {
            case 'verify_email':
                if (
                    !isset($data['vars']['verify_url']) ||
                    !filter_var($data['vars']['verify_url'], FILTER_VALIDATE_URL)
                ) {
                    return false;
                }
                if (
                    !isset($data['vars']['expires_at']) ||
                    !self::dateTime($data['vars']['expires_at'])
                ) {
                    return false;
                }
                break;
        }

        return true;
    }
}