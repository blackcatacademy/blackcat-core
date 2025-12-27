<?php

declare(strict_types=1);

namespace BlackCat\Core\Kernel;

final class HttpKernelResponse
{
    /**
     * @param array<string,string> $headers
     */
    public function __construct(
        public readonly int $statusCode,
        public readonly array $headers,
        public readonly string $body,
    ) {
    }

    public function send(): void
    {
        if (PHP_SAPI === 'cli') {
            return;
        }

        if (!headers_sent()) {
            http_response_code($this->statusCode);
            foreach ($this->headers as $name => $value) {
                if (!is_string($name) || $name === '' || str_contains($name, "\0")) {
                    continue;
                }
                if (!is_string($value) || str_contains($value, "\0")) {
                    continue;
                }
                header($name . ': ' . $value);
            }
        }

        echo $this->body;
    }
}

