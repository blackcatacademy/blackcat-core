<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\Security;

use BlackCat\Core\Security\FilesystemThreatScanner;
use PHPUnit\Framework\TestCase;

final class FilesystemThreatScannerTest extends TestCase
{
    public function test_scan_detects_high_signal_artifacts(): void
    {
        $root = sys_get_temp_dir() . '/blackcat_fs_scan_' . bin2hex(random_bytes(6));
        mkdir($root, 0700, true);
        mkdir($root . '/w', 0700, true);

        file_put_contents($root . '/w/shell.php', "<?php echo 'x';");
        file_put_contents($root . '/w/img.jpg', "GIF89a<?php echo 'pwn';");
        file_put_contents($root . '/w/run.sh', "#!/bin/sh\necho ok\n");
        chmod($root . '/w/run.sh', 0755);

        symlink($root . '/w/shell.php', $root . '/w/link.php');

        $res = FilesystemThreatScanner::scan([$root], [
            'max_depth' => 4,
            'max_dirs' => 100,
            'max_files' => 100,
            'max_file_bytes' => 4096,
            'max_findings' => 100,
        ]);

        $codes = array_map(static fn (array $f): string => $f['code'], $res['findings']);

        self::assertContains(FilesystemThreatScanner::CODE_EXECUTABLE_EXT, $codes);
        self::assertContains(FilesystemThreatScanner::CODE_PHP_TAG, $codes);
        self::assertContains(FilesystemThreatScanner::CODE_SHEBANG, $codes);
        self::assertContains(FilesystemThreatScanner::CODE_EXECUTABLE_BIT, $codes);
        self::assertContains(FilesystemThreatScanner::CODE_SYMLINK_PRESENT, $codes);
    }

    public function test_scan_budget_exhaustion_is_reported(): void
    {
        $root = sys_get_temp_dir() . '/blackcat_fs_scan_budget_' . bin2hex(random_bytes(6));
        mkdir($root, 0700, true);
        mkdir($root . '/w', 0700, true);

        for ($i = 0; $i < 50; $i++) {
            file_put_contents($root . '/w/file' . $i . '.txt', 'x');
        }

        $res = FilesystemThreatScanner::scan([$root], [
            'max_files' => 5,
            'max_findings' => 10,
        ]);

        $codes = array_map(static fn (array $f): string => $f['code'], $res['findings']);
        self::assertContains(FilesystemThreatScanner::CODE_BUDGET_EXHAUSTED, $codes);
    }
}

