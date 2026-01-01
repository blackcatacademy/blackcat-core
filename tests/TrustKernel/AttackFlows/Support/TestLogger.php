<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows\Support;

use Psr\Log\LoggerInterface;

final class TestLogger implements LoggerInterface
{
    /** @var list<array{level:string,message:string,context:array<string,mixed>}> */
    public array $records = [];

    public function emergency(string|\Stringable $message, array $context = []): void { $this->log('emergency', $message, $context); }
    public function alert(string|\Stringable $message, array $context = []): void { $this->log('alert', $message, $context); }
    public function critical(string|\Stringable $message, array $context = []): void { $this->log('critical', $message, $context); }
    public function error(string|\Stringable $message, array $context = []): void { $this->log('error', $message, $context); }
    public function warning(string|\Stringable $message, array $context = []): void { $this->log('warning', $message, $context); }
    public function notice(string|\Stringable $message, array $context = []): void { $this->log('notice', $message, $context); }
    public function info(string|\Stringable $message, array $context = []): void { $this->log('info', $message, $context); }
    public function debug(string|\Stringable $message, array $context = []): void { $this->log('debug', $message, $context); }

    public function log(mixed $level, string|\Stringable $message, array $context = []): void
    {
        $level = is_string($level) ? $level : 'unknown';
        $message = (string) $message;

        /** @var array<string,mixed> $context */
        $context = $context;

        $this->records[] = [
            'level' => $level,
            'message' => $message,
            'context' => $context,
        ];
    }
}
