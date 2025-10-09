<?php
declare(strict_types=1);

use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

final class LoggerPsrAdapter implements LoggerInterface
{
    public function log($level, string|Stringable $message, array $context = []): void
    {
        // pokud je Stringable, převedeme na string
        if ($message instanceof Stringable) {
            $message = (string)$message;
        }

        try {
            // throwable preferujeme
            if (!empty($context['exception']) && ($context['exception'] instanceof \Throwable || is_string($context['exception']))) {
                $ex = $context['exception'] instanceof \Throwable ? $context['exception'] : new \Exception((string)$context['exception']);
                if (in_array($level, [LogLevel::EMERGENCY, LogLevel::ALERT, LogLevel::CRITICAL, LogLevel::ERROR], true)) {
                    Logger::systemError($ex, $context['user_id'] ?? null, $context['token'] ?? null, $context);
                    return;
                }
            }

            switch ($level) {
                case LogLevel::EMERGENCY:
                case LogLevel::ALERT:
                case LogLevel::CRITICAL:
                    Logger::critical($message, $context['user_id'] ?? null, $context, $context['token'] ?? null);
                    break;

                case LogLevel::ERROR:
                    if (!empty($context['exception']) && $context['exception'] instanceof \Throwable) {
                        Logger::systemError($context['exception'], $context['user_id'] ?? null, $context['token'] ?? null, $context);
                    } else {
                        Logger::error($message, $context['user_id'] ?? null, $context, $context['token'] ?? null);
                    }
                    break;

                case LogLevel::WARNING:
                    Logger::warn($message, $context['user_id'] ?? null, $context);
                    break;

                case LogLevel::NOTICE:
                case LogLevel::INFO:
                    Logger::info($message, $context['user_id'] ?? null, $context);
                    break;

                case LogLevel::DEBUG:
                    Logger::systemMessage('debug', $message, $context['user_id'] ?? null, $context);
                    break;

                default:
                    Logger::systemMessage($level, $message, $context['user_id'] ?? null, $context);
            }
        } catch (\Throwable $_) {
            // adaptér nesmí vyvolat výjimku
        }
    }

    // PSR-3 shortcut methods
    public function emergency(string|Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::EMERGENCY, $message, $context);
    }

    public function alert(string|Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::ALERT, $message, $context);
    }

    public function critical(string|Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::CRITICAL, $message, $context);
    }

    public function error(string|Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::ERROR, $message, $context);
    }

    public function warning(string|Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::WARNING, $message, $context);
    }

    public function notice(string|Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::NOTICE, $message, $context);
    }

    public function info(string|Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::INFO, $message, $context);
    }

    public function debug(string|Stringable $message, array $context = []): void
    {
        $this->log(LogLevel::DEBUG, $message, $context);
    }
}