<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class CanonicalJson
{
    public static function encode(mixed $value): string
    {
        $normalized = self::normalize($value);

        $json = json_encode($normalized, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            throw new \RuntimeException('Unable to encode canonical JSON.');
        }

        return $json;
    }

    public static function sha256Bytes32(mixed $value): string
    {
        return '0x' . hash('sha256', self::encode($value));
    }

    private static function normalize(mixed $value): mixed
    {
        if (is_array($value)) {
            if (array_is_list($value)) {
                $out = [];
                foreach ($value as $v) {
                    $out[] = self::normalize($v);
                }
                return $out;
            }

            $keys = array_keys($value);
            sort($keys, SORT_STRING);
            $out = [];
            foreach ($keys as $k) {
                $out[$k] = self::normalize($value[$k]);
            }
            return $out;
        }

        if (is_object($value)) {
            throw new \InvalidArgumentException('Objects are not supported in canonical JSON.');
        }

        return $value;
    }
}

