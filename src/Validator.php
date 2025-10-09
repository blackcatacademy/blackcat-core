<?php
declare(strict_types=1);

/**
 * Validator - centralizované statické metódy pro validaci vstupů.
 * PSR-12, bezpečné filtry + regex, production ready.
 */
class Validator
{
    public static function validateEmail(string $email): bool
    {
        $email = trim($email);
        return (bool) filter_var($email, FILTER_VALIDATE_EMAIL);
    }

    public static function validateDate(string $date, string $format = 'Y-m-d'): bool
    {
        $d = DateTime::createFromFormat($format, $date);
        return $d && $d->format($format) === $date;
    }

    public static function validateDateTime(string $dateTime, string $format = 'Y-m-d H:i:s'): bool
    {
        $d = DateTime::createFromFormat($format, $dateTime);
        return $d && $d->format($format) === $dateTime;
    }

    public static function validateNumberInRange(float|int|string $value, float $min, float $max): bool
    {
        if (!is_numeric($value)) return false;
        $f = (float) $value;
        return $f >= $min && $f <= $max;
    }

    public static function validateCurrencyCode(string $code, array $allowed = []): bool
    {
        $code = strtoupper(trim($code));
        if (!preg_match('/^[A-Z]{3}$/', $code)) return false;
        if (!empty($allowed) && !in_array($code, $allowed, true)) return false;
        return true;
    }

    public static function validateJson(string $json): bool
    {
        $json = trim($json);
        if ($json === '') return false;
        json_decode($json);
        return json_last_error() === JSON_ERROR_NONE;
    }

    public static function validatePasswordStrength(string $pw, int $minLength = 12): bool
    {
        if (mb_strlen($pw) < $minLength) return false;
        if (!preg_match('/[a-z]/', $pw)) return false;        // malé písmeno
        if (!preg_match('/[A-Z]/', $pw)) return false;        // velké písmeno
        if (!preg_match('/[0-9]/', $pw)) return false;        // číslo
        if (!preg_match('/[\W_]/', $pw)) return false;        // speciální znak
        return true;
    }

    public static function sanitizeString(string $s, int $maxLen = 0): string
    {
        // odstraní bílé znaky a control characters
        $out = preg_replace('/[\x00-\x1F\x7F]/u', '', trim($s));
        if ($maxLen > 0) $out = mb_substr($out, 0, $maxLen);
        return $out;
    }

    public static function validateFileSize(int $sizeBytes, int $maxBytes): bool
    {
        return $sizeBytes > 0 && $sizeBytes <= $maxBytes;
    }

    public static function validateMimeType(string $mime, array $allowed): bool
    {
        return in_array($mime, $allowed, true);
    }
    public static function validateNotificationPayload(string $json, string $template): bool
    {
        if (!self::validateJson($json)) return false;

        $data = json_decode($json, true);

        // základní povinné klíče
        $requiredKeys = ['to', 'subject', 'template', 'vars'];
        foreach ($requiredKeys as $key) {
            if (!array_key_exists($key, $data)) return false;
        }

        if (!is_string($data['to']) || !self::validateEmail($data['to'])) return false;
        if (!is_string($data['subject']) || trim($data['subject']) === '') return false;
        if (!is_string($data['template']) || trim($data['template']) === '') return false;
        if (!is_array($data['vars'])) return false;

        // template-specifické kontroly
        switch ($template) {
            case 'verify_email':
                if (!array_key_exists('verify_url', $data['vars']) || !filter_var($data['vars']['verify_url'], FILTER_VALIDATE_URL)) return false;
                if (!array_key_exists('expires_at', $data['vars']) || !self::validateDateTime($data['vars']['expires_at'])) return false;
                break;
            // další šablony lze přidat sem
        }

        return true;
    }

}