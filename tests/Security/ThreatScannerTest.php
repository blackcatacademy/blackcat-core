<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\Security;

use BlackCat\Core\Security\ThreatScanner;
use PHPUnit\Framework\TestCase;

final class ThreatScannerTest extends TestCase
{
    public function testDetectsPhpTagInRequestPayload(): void
    {
        $report = ThreatScanner::scanRequest(
            ['REQUEST_URI' => '/'],
            ['q' => '<?php echo 1;'],
            [],
            [],
            [],
        );

        $codes = $this->codes($report);
        self::assertContains(ThreatScanner::CODE_PHP_TAG, $codes);
    }

    public function testDetectsStreamWrapperInRequestPayload(): void
    {
        $report = ThreatScanner::scanRequest(
            ['REQUEST_URI' => '/'],
            [],
            ['file' => 'php://filter'],
            [],
            [],
        );

        $codes = $this->codes($report);
        self::assertContains(ThreatScanner::CODE_STREAM_WRAPPER, $codes);
    }

    public function testDetectsObfuscationPattern(): void
    {
        $report = ThreatScanner::scanRequest(
            ['REQUEST_URI' => '/'],
            [],
            ['x' => 'base64_decode($a); eval($b);'],
            [],
            [],
        );

        $codes = $this->codes($report);
        self::assertContains(ThreatScanner::CODE_OBFUSCATION, $codes);
        self::assertContains(ThreatScanner::CODE_RCE_FUNCTION, $codes);
    }

    public function testDetectsExecutableExtensionUpload(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'blackcat-threat-');
        self::assertIsString($tmp);
        file_put_contents($tmp, "hello\n");

        $report = ThreatScanner::scanRequest(
            ['REQUEST_URI' => '/upload'],
            [],
            [],
            [],
            [
                'f' => [
                    'name' => 'shell.php',
                    'type' => 'text/plain',
                    'tmp_name' => $tmp,
                    'error' => UPLOAD_ERR_OK,
                    'size' => filesize($tmp),
                ],
            ],
        );

        @unlink($tmp);

        $codes = $this->codes($report);
        self::assertContains(ThreatScanner::CODE_UPLOAD_EXECUTABLE_EXT, $codes);
    }

    public function testDetectsPhpTagInsideUploadedFile(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'blackcat-threat-');
        self::assertIsString($tmp);
        file_put_contents($tmp, "<?php echo 'x';");

        $report = ThreatScanner::scanRequest(
            ['REQUEST_URI' => '/upload'],
            [],
            [],
            [],
            [
                'f' => [
                    'name' => 'note.txt',
                    'type' => 'text/plain',
                    'tmp_name' => $tmp,
                    'error' => UPLOAD_ERR_OK,
                    'size' => filesize($tmp),
                ],
            ],
        );

        @unlink($tmp);

        $codes = $this->codes($report);
        self::assertContains(ThreatScanner::CODE_UPLOAD_PHP_TAG, $codes);
    }

    /**
     * @param array<string,mixed> $report
     * @return list<string>
     */
    private function codes(array $report): array
    {
        $findings = $report['findings'] ?? null;
        self::assertIsArray($findings);

        $codes = [];
        foreach ($findings as $f) {
            if (!is_array($f)) {
                continue;
            }
            $code = $f['code'] ?? null;
            if (is_string($code)) {
                $codes[] = $code;
            }
        }

        return $codes;
    }
}

