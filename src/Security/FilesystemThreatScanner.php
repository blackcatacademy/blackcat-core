<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

/**
 * Filesystem threat scanner for "kernel-only" deployments.
 *
 * This is NOT an antivirus. The goal is to detect high-confidence artifacts
 * typically created by real-world intrusions (webshells, droppers, backdoors),
 * primarily inside writable directories.
 *
 * Design goals:
 * - keep false positives low (focus on high-signal checks)
 * - be cheap (limits + short reads) and resilient (never throw on hostile FS)
 */
final class FilesystemThreatScanner
{
    public const CODE_ROOT_NOT_READABLE = 'root_not_readable';
    public const CODE_DIR_LIST_FAILED = 'dir_list_failed';
    public const CODE_SYMLINK_PRESENT = 'symlink_present';
    public const CODE_EXECUTABLE_EXT = 'executable_extension';
    public const CODE_EXECUTABLE_BIT = 'executable_bit';
    public const CODE_SHEBANG = 'shebang';
    public const CODE_BINARY_MAGIC = 'binary_magic';
    public const CODE_PHP_TAG = 'php_tag';
    public const CODE_DEPTH_LIMIT = 'depth_limit';
    public const CODE_BUDGET_EXHAUSTED = 'budget_exhausted';

    /**
     * @param list<string> $roots
     * @param array{
     *   max_depth?:int,
     *   max_dirs?:int,
     *   max_files?:int,
     *   max_findings?:int,
     *   max_file_bytes?:int,
     *   ignore_paths?:list<string>,
     *   ignore_dir_names?:list<string>,
     *   disallowed_extensions?:list<string>,
     *   scan_php_tags?:bool,
     *   scan_shebang?:bool,
     *   scan_binary_magic?:bool,
     *   scan_executable_bit?:bool
     * } $options
     * @return array{
     *   findings:list<array{severity:'warn'|'error',code:string,path:string}>,
     *   summary:array{by_code:array<string,int>,errors:int},
     *   stats:array{roots_scanned:int,dirs_scanned:int,files_scanned:int,bytes_scanned:int}
     * }
     */
    public static function scan(array $roots, array $options = []): array
    {
        $maxDepth = $options['max_depth'] ?? 12;
        $maxDirs = $options['max_dirs'] ?? 2500;
        $maxFiles = $options['max_files'] ?? 5000;
        $maxFindings = $options['max_findings'] ?? 200;
        $maxFileBytes = $options['max_file_bytes'] ?? 64 * 1024;
        $ignorePaths = $options['ignore_paths'] ?? [];
        $ignoreDirNames = $options['ignore_dir_names'] ?? [];
        $disallowed = $options['disallowed_extensions'] ?? self::defaultDisallowedExtensions();
        $scanPhpTags = $options['scan_php_tags'] ?? true;
        $scanShebang = $options['scan_shebang'] ?? true;
        $scanBinaryMagic = $options['scan_binary_magic'] ?? true;
        $scanExecutableBit = $options['scan_executable_bit'] ?? true;

        if (!is_int($maxDepth) || $maxDepth < 0) {
            $maxDepth = 12;
        }
        if (!is_int($maxDirs) || $maxDirs < 0) {
            $maxDirs = 2500;
        }
        if (!is_int($maxFiles) || $maxFiles < 0) {
            $maxFiles = 5000;
        }
        if (!is_int($maxFindings) || $maxFindings < 0) {
            $maxFindings = 200;
        }
        if (!is_int($maxFileBytes) || $maxFileBytes < 0) {
            $maxFileBytes = 64 * 1024;
        }
        if (!is_array($ignorePaths)) {
            $ignorePaths = [];
        }
        if (!is_array($ignoreDirNames)) {
            $ignoreDirNames = [];
        }
        if (!is_array($disallowed)) {
            $disallowed = self::defaultDisallowedExtensions();
        }
        if (!is_bool($scanPhpTags)) {
            $scanPhpTags = true;
        }
        if (!is_bool($scanShebang)) {
            $scanShebang = true;
        }
        if (!is_bool($scanBinaryMagic)) {
            $scanBinaryMagic = true;
        }
        if (!is_bool($scanExecutableBit)) {
            $scanExecutableBit = true;
        }

        $findings = [];
        $byCode = [];
        $errors = 0;

        $rootsScanned = 0;
        $dirsScanned = 0;
        $filesScanned = 0;
        $bytesScanned = 0;

        /** @var list<array{dir:string,depth:int}> $queue */
        $queue = [];

        /** @var list<string> $ignorePrefixes */
        $ignorePrefixes = [];
        foreach ($ignorePaths as $p) {
            if (!is_string($p)) {
                continue;
            }
            $p = rtrim(trim($p), "/\\");
            if ($p === '' || str_contains($p, "\0")) {
                continue;
            }
            $ignorePrefixes[] = $p;
        }

        /** @var array<string,true> $ignoreDirNameSet */
        $ignoreDirNameSet = [];
        foreach ($ignoreDirNames as $n) {
            if (!is_string($n)) {
                continue;
            }
            $n = strtolower(trim($n));
            if ($n === '' || str_contains($n, "\0")) {
                continue;
            }
            $ignoreDirNameSet[$n] = true;
        }

        $isIgnored = static function (string $path) use ($ignorePrefixes): bool {
            foreach ($ignorePrefixes as $prefix) {
                if (!str_starts_with($path, $prefix)) {
                    continue;
                }
                if (strlen($path) === strlen($prefix)) {
                    return true;
                }
                $next = $path[strlen($prefix)] ?? '';
                if ($next === '/' || $next === '\\') {
                    return true;
                }
            }
            return false;
        };

        foreach ($roots as $root) {
            if (!is_string($root) || trim($root) === '') {
                continue;
            }

            $root = rtrim($root, "/\\");
            if ($root === '') {
                continue;
            }

            if ($isIgnored($root)) {
                continue;
            }

            $rootsScanned++;

            if (!is_dir($root) || is_link($root) || !is_readable($root)) {
                self::addFinding($findings, $byCode, $maxFindings, 'warn', self::CODE_ROOT_NOT_READABLE, $root);
                $errors++;
                continue;
            }

            $queue[] = ['dir' => $root, 'depth' => 0];
        }

        $budgetExceeded = false;

        while ($queue !== []) {
            /** @var array{dir:string,depth:int} $next */
            $next = array_pop($queue);
            $dir = $next['dir'];
            $depth = $next['depth'];

            if ($dirsScanned >= $maxDirs) {
                $budgetExceeded = true;
                break;
            }

            $dirsScanned++;

            try {
                $it = new \DirectoryIterator($dir);
            } catch (\Throwable $e) {
                self::addFinding($findings, $byCode, $maxFindings, 'warn', self::CODE_DIR_LIST_FAILED, $dir);
                $errors++;
                continue;
            }

            foreach ($it as $entry) {
                if ($entry->isDot()) {
                    continue;
                }

                $path = $entry->getPathname();
                if ($isIgnored($path)) {
                    continue;
                }

                if ($entry->isLink()) {
                    self::addFinding($findings, $byCode, $maxFindings, 'error', self::CODE_SYMLINK_PRESENT, $path);
                    continue;
                }

                if ($entry->isDir()) {
                    $name = $entry->getFilename();
                    if (is_string($name) && isset($ignoreDirNameSet[strtolower($name)])) {
                        continue;
                    }
                    if ($depth >= $maxDepth) {
                        self::addFinding($findings, $byCode, $maxFindings, 'warn', self::CODE_DEPTH_LIMIT, $path);
                        continue;
                    }
                    $queue[] = ['dir' => $path, 'depth' => $depth + 1];
                    continue;
                }

                if (!$entry->isFile()) {
                    continue;
                }

                if ($filesScanned >= $maxFiles) {
                    $budgetExceeded = true;
                    break 2;
                }

                $filesScanned++;

                $fileFindings = [];

                $name = $entry->getFilename();
                $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
                if ($ext !== '' && in_array($ext, $disallowed, true)) {
                    $fileFindings[] = ['severity' => 'error', 'code' => self::CODE_EXECUTABLE_EXT, 'path' => $path];
                }

                if ($scanExecutableBit) {
                    $perms = 0;
                    try {
                        $perms = $entry->getPerms();
                    } catch (\Throwable $e) {
                        $perms = 0;
                    }
                    if (($perms & 0o111) !== 0) {
                        $fileFindings[] = ['severity' => 'warn', 'code' => self::CODE_EXECUTABLE_BIT, 'path' => $path];
                    }
                }

                if (($scanPhpTags || $scanShebang || $scanBinaryMagic) && $maxFileBytes > 0) {
                    if (!is_readable($path)) {
                        $errors++;
                    } else {
                        $fh = @fopen($path, 'rb');
                        if ($fh === false) {
                            $errors++;
                        } else {
                            try {
                                $buf = @fread($fh, $maxFileBytes);
                            } finally {
                                fclose($fh);
                            }

                            if (is_string($buf) && $buf !== '') {
                                $bytesScanned += strlen($buf);

                                if ($scanShebang && str_starts_with($buf, '#!')) {
                                    $fileFindings[] = ['severity' => 'error', 'code' => self::CODE_SHEBANG, 'path' => $path];
                                }

                                if ($scanBinaryMagic) {
                                    if (str_starts_with($buf, "\x7fELF") || str_starts_with($buf, 'MZ')) {
                                        $fileFindings[] = ['severity' => 'error', 'code' => self::CODE_BINARY_MAGIC, 'path' => $path];
                                    }
                                }

                                if ($scanPhpTags) {
                                    $lower = strtolower($buf);
                                    if (str_contains($lower, '<?php') || str_contains($lower, '<?=')) {
                                        $fileFindings[] = ['severity' => 'error', 'code' => self::CODE_PHP_TAG, 'path' => $path];
                                    }
                                }
                            }
                        }
                    }
                }

                foreach ($fileFindings as $f) {
                    self::addFinding($findings, $byCode, $maxFindings, $f['severity'], $f['code'], $f['path']);
                }
            }
        }

        if ($budgetExceeded) {
            self::addFinding($findings, $byCode, $maxFindings, 'warn', self::CODE_BUDGET_EXHAUSTED, '(scan budget exhausted)');
        }

        return [
            'findings' => $findings,
            'summary' => [
                'by_code' => $byCode,
                'errors' => $errors,
            ],
            'stats' => [
                'roots_scanned' => $rootsScanned,
                'dirs_scanned' => $dirsScanned,
                'files_scanned' => $filesScanned,
                'bytes_scanned' => $bytesScanned,
            ],
        ];
    }

    /**
     * @return list<string>
     */
    public static function defaultDisallowedExtensions(): array
    {
        // High-risk executable/script extensions commonly used in webshells / droppers.
        return [
            'php',
            'phtml',
            'pht',
            'phar',
            'php5',
            'php7',
            'php8',
            'pl',
            'py',
            'rb',
            'sh',
            'bash',
            'zsh',
            'ksh',
            'cgi',
            'exe',
            'dll',
            'so',
        ];
    }

    /**
     * @param list<array{severity:'warn'|'error',code:string,path:string}> $findings
     * @param array<string,int> $byCode
     */
    private static function addFinding(
        array &$findings,
        array &$byCode,
        int $maxFindings,
        string $severity,
        string $code,
        string $path,
    ): void {
        $byCode[$code] = ($byCode[$code] ?? 0) + 1;

        if ($maxFindings === 0) {
            return;
        }
        if (count($findings) >= $maxFindings) {
            return;
        }

        $findings[] = [
            'severity' => $severity === 'error' ? 'error' : 'warn',
            'code' => $code,
            'path' => $path,
        ];
    }
}
