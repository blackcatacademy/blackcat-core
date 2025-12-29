<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

/**
 * Lightweight "anti-webshell" / threat scanner for kernel-only deployments.
 *
 * Important:
 * - This is NOT a sandbox and it cannot guarantee safety if an attacker can execute arbitrary PHP code.
 * - The goal is to block obvious malicious probes/payloads early and generate auditable incident signals.
 *
 * Design goals:
 * - keep false positives low by focusing on high-confidence patterns
 * - be cheap (limits + short-circuit) and resilient (never throw on hostile inputs)
 */
final class ThreatScanner
{
    public const CODE_PHP_TAG = 'php_tag';
    public const CODE_STREAM_WRAPPER = 'stream_wrapper';
    public const CODE_RCE_FUNCTION = 'rce_function';
    public const CODE_OBFUSCATION = 'obfuscation';
    public const CODE_NUL_BYTE = 'nul_byte';
    public const CODE_UPLOAD_EXECUTABLE_EXT = 'upload_executable_ext';
    public const CODE_UPLOAD_PHP_TAG = 'upload_php_tag';

    /**
     * @param array{
     *   max_fields?:int,
     *   max_value_len?:int,
     *   max_files?:int,
     *   max_file_bytes?:int,
     *   disallowed_upload_extensions?:list<string>
     * } $options
     * @return array{
     *   findings:list<array{severity:'warn'|'error',code:string,context:string}>,
     *   stats:array{strings_scanned:int,files_scanned:int,bytes_scanned:int}
     * }
     */
    public static function scanRequest(
        array $server,
        array $get,
        array $post,
        array $cookie,
        array $files,
        array $options = [],
    ): array {
        $maxFields = $options['max_fields'] ?? 200;
        $maxValueLen = $options['max_value_len'] ?? 4096;
        $maxFiles = $options['max_files'] ?? 25;
        $maxFileBytes = $options['max_file_bytes'] ?? 64 * 1024;
        $disallowed = $options['disallowed_upload_extensions'] ?? self::defaultDisallowedUploadExtensions();

        if (!is_int($maxFields) || $maxFields < 1) {
            $maxFields = 200;
        }
        if (!is_int($maxValueLen) || $maxValueLen < 256) {
            $maxValueLen = 4096;
        }
        if (!is_int($maxFiles) || $maxFiles < 0) {
            $maxFiles = 25;
        }
        if (!is_int($maxFileBytes) || $maxFileBytes < 1024) {
            $maxFileBytes = 64 * 1024;
        }

        $findings = [];
        $stringsScanned = 0;
        $filesScanned = 0;
        $bytesScanned = 0;

        $scanString = static function (mixed $v, string $context) use (&$findings, &$stringsScanned, $maxValueLen): void {
            if (!is_string($v) || $v === '') {
                return;
            }

            $stringsScanned++;

            // Cheap upper bound to reduce DoS / false positives on huge blobs.
            if (strlen($v) > $maxValueLen) {
                $v = substr($v, 0, $maxValueLen);
            }

            foreach (self::scanText($v, $context) as $f) {
                $findings[] = $f;
            }
        };

        // Headers are already sanitized by the web server, but include a few high-risk ones.
        $scanString($server['REQUEST_URI'] ?? null, 'server:REQUEST_URI');
        $scanString($server['QUERY_STRING'] ?? null, 'server:QUERY_STRING');
        $scanString($server['HTTP_USER_AGENT'] ?? null, 'server:HTTP_USER_AGENT');

        $fieldsBudget = $maxFields;
        foreach (['get' => $get, 'post' => $post, 'cookie' => $cookie] as $bucket => $arr) {
            if (!is_array($arr)) {
                continue;
            }
            foreach (self::flattenScalars($arr, $bucket) as $ctx => $val) {
                if ($fieldsBudget-- <= 0) {
                    break 2;
                }
                $scanString($val, $ctx);
            }
        }

        if (is_array($files) && $maxFiles > 0) {
            foreach (self::iterateFiles($files) as $f) {
                if ($filesScanned >= $maxFiles) {
                    break;
                }
                $filesScanned++;

                $field = $f['field'];
                $name = $f['name'];
                $tmp = $f['tmp_name'];
                $err = $f['error'];
                $size = $f['size'];

                if (!is_int($err) || $err !== UPLOAD_ERR_OK) {
                    continue;
                }

                if (is_string($name)) {
                    if (str_contains($name, "\0")) {
                        $findings[] = ['severity' => 'error', 'code' => self::CODE_NUL_BYTE, 'context' => 'files:' . $field . ':name'];
                        continue;
                    }

                    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
                    if ($ext !== '' && in_array($ext, $disallowed, true)) {
                        $findings[] = [
                            'severity' => 'error',
                            'code' => self::CODE_UPLOAD_EXECUTABLE_EXT,
                            'context' => 'files:' . $field . ':name',
                        ];
                        continue;
                    }
                }

                if (!is_string($tmp) || $tmp === '' || str_contains($tmp, "\0")) {
                    continue;
                }
                if (!is_file($tmp) || is_link($tmp) || !is_readable($tmp)) {
                    continue;
                }

                $limit = $maxFileBytes;
                if (is_int($size) && $size >= 0) {
                    $limit = min($limit, $size);
                }
                if ($limit <= 0) {
                    continue;
                }

                $fh = @fopen($tmp, 'rb');
                if ($fh === false) {
                    continue;
                }
                try {
                    $buf = @fread($fh, $limit);
                } finally {
                    fclose($fh);
                }
                if (!is_string($buf) || $buf === '') {
                    continue;
                }
                $bytesScanned += strlen($buf);

                // Only scan for the highest-confidence "webshell" primitive: PHP open tags.
                $lower = strtolower($buf);
                if (str_contains($lower, '<?php') || str_contains($lower, '<?=')) {
                    $findings[] = [
                        'severity' => 'error',
                        'code' => self::CODE_UPLOAD_PHP_TAG,
                        'context' => 'files:' . $field . ':content',
                    ];
                }
            }
        }

        return [
            'findings' => $findings,
            'stats' => [
                'strings_scanned' => $stringsScanned,
                'files_scanned' => $filesScanned,
                'bytes_scanned' => $bytesScanned,
            ],
        ];
    }

    /**
     * @return list<array{severity:'warn'|'error',code:string,context:string}>
     */
    public static function scanText(string $text, string $context): array
    {
        if ($text === '') {
            return [];
        }

        $out = [];

        if (str_contains($text, "\0")) {
            $out[] = ['severity' => 'error', 'code' => self::CODE_NUL_BYTE, 'context' => $context];
            return $out;
        }

        $lower = strtolower($text);

        // PHP tags should never appear in normal request inputs.
        if (str_contains($lower, '<?php') || str_contains($lower, '<?=')) {
            $out[] = ['severity' => 'error', 'code' => self::CODE_PHP_TAG, 'context' => $context];
        }

        foreach (['php://', 'data:', 'expect://', 'zip://', 'phar://'] as $needle) {
            if (str_contains($lower, $needle)) {
                $out[] = ['severity' => 'error', 'code' => self::CODE_STREAM_WRAPPER, 'context' => $context];
                break;
            }
        }

        // High-confidence RCE primitives.
        if (preg_match('/\\b(eval|assert|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\\s*\\(/i', $text) === 1) {
            $out[] = ['severity' => 'error', 'code' => self::CODE_RCE_FUNCTION, 'context' => $context];
        }

        // Obfuscation patterns are common in webshell payloads.
        $hasB64 = str_contains($lower, 'base64_decode');
        $hasInflate = str_contains($lower, 'gzinflate');
        $hasRot13 = str_contains($lower, 'str_rot13');
        $hasEval = str_contains($lower, 'eval');
        if (($hasB64 && $hasEval) || ($hasB64 && $hasInflate) || ($hasB64 && $hasRot13)) {
            $out[] = ['severity' => 'error', 'code' => self::CODE_OBFUSCATION, 'context' => $context];
        } elseif ($hasB64 || $hasInflate || $hasRot13) {
            $out[] = ['severity' => 'warn', 'code' => self::CODE_OBFUSCATION, 'context' => $context];
        }

        return $out;
    }

    /**
     * @return array<int,string>
     */
    private static function defaultDisallowedUploadExtensions(): array
    {
        // Prefer "deny by default" for anything that can be executed/interpreted on common stacks.
        return [
            'php',
            'phtml',
            'pht',
            'phar',
            'inc',
            'cgi',
            'pl',
            'py',
            'rb',
            'sh',
            'bash',
            'zsh',
            'exe',
            'dll',
            'so',
            'dylib',
            'bat',
            'cmd',
            'ps1',
        ];
    }

    /**
     * Flatten scalar values from an array with a context prefix.
     *
     * @return \Generator<string,string>
     */
    private static function flattenScalars(array $data, string $prefix): \Generator
    {
        $stack = [[$prefix, $data, 0]];

        while ($stack !== []) {
            /** @var array{0:string,1:mixed,2:int} $item */
            $item = array_pop($stack);
            [$ctx, $v, $depth] = $item;

            if ($depth > 6) {
                continue;
            }

            if (is_string($v)) {
                yield $ctx => $v;
                continue;
            }

            if (!is_array($v)) {
                continue;
            }

            foreach ($v as $k => $vv) {
                if (!is_string($k) && !is_int($k)) {
                    continue;
                }
                $key = is_int($k) ? (string) $k : $k;
                if ($key === '' || str_contains($key, "\0")) {
                    continue;
                }
                $stack[] = [$ctx . ':' . $key, $vv, $depth + 1];
            }
        }
    }

    /**
     * Iterate over PHP $_FILES in a tolerant way (single + multi upload).
     *
     * @return \Generator<int,array{field:string,name:?string,tmp_name:?string,error:?int,size:?int,type:?string}>
     */
    private static function iterateFiles(array $files): \Generator
    {
        foreach ($files as $field => $spec) {
            if (!is_string($field) || $field === '' || str_contains($field, "\0")) {
                continue;
            }
            if (!is_array($spec)) {
                continue;
            }

            $name = $spec['name'] ?? null;
            $tmp = $spec['tmp_name'] ?? null;
            $err = $spec['error'] ?? null;
            $size = $spec['size'] ?? null;
            $type = $spec['type'] ?? null;

            if (is_array($name) && is_array($tmp) && is_array($err) && is_array($size)) {
                foreach ($name as $i => $n) {
                    if (!array_key_exists($i, $tmp) || !array_key_exists($i, $err) || !array_key_exists($i, $size)) {
                        continue;
                    }
                    $t = $tmp[$i];
                    $e = $err[$i];
                    $s = $size[$i];

                    yield [
                        'field' => $field,
                        'name' => is_string($n) ? $n : null,
                        'tmp_name' => is_string($t) ? $t : null,
                        'error' => is_int($e) ? $e : (is_string($e) && ctype_digit(trim($e)) ? (int) trim($e) : null),
                        'size' => is_int($s) ? $s : (is_string($s) && ctype_digit(trim($s)) ? (int) trim($s) : null),
                        'type' => is_string($type) ? $type : null,
                    ];
                }
                continue;
            }

            yield [
                'field' => $field,
                'name' => is_string($name) ? $name : null,
                'tmp_name' => is_string($tmp) ? $tmp : null,
                'error' => is_int($err) ? $err : (is_string($err) && ctype_digit(trim($err)) ? (int) trim($err) : null),
                'size' => is_int($size) ? $size : (is_string($size) && ctype_digit(trim($size)) ? (int) trim($size) : null),
                'type' => is_string($type) ? $type : null,
            ];
        }
    }
}
