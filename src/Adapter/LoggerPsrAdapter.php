<?php
declare(strict_types=1);

namespace BlackCat\Core\Adapter;

use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use BlackCat\Core\Log\Logger;

/**
 * Adapter implementing PSR-3 on top of your static Logger.
 */
final class LoggerPsrAdapter implements LoggerInterface
{
    /**
     * @param string|Stringable $message
     * @param array $context
     */
    public function log($level, string|\Stringable $message, array $context = []): void
    {
        if ($message instanceof \Stringable) {
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
                    Logger::critical((string)$message, $context['user_id'] ?? null, $context, $context['token'] ?? null);
                    break;

                case LogLevel::ERROR:
                    if (!empty($context['exception']) && $context['exception'] instanceof \Throwable) {
                        Logger::systemError($context['exception'], $context['user_id'] ?? null, $context['token'] ?? null, $context);
                    } else {
                        Logger::error((string)$message, $context['user_id'] ?? null, $context, $context['token'] ?? null);
                    }
                    break;

                case LogLevel::WARNING:
                    Logger::warn((string)$message, $context['user_id'] ?? null, $context);
                    break;

                case LogLevel::NOTICE:
                case LogLevel::INFO:
                    Logger::info((string)$message, $context['user_id'] ?? null, $context);
                    break;

                case LogLevel::DEBUG:
                    Logger::systemMessage('debug', (string)$message, $context['user_id'] ?? null, $context);
                    break;

                default:
                    Logger::systemMessage((string)$level, (string)$message, $context['user_id'] ?? null, $context);
            }
        } catch (\Throwable $_) {
            // adaptér nesmí vyvolat výjimku
        }
    }

    public function emergency($message, array $context = []): void { $this->log(LogLevel::EMERGENCY, $message, $context); }
    public function alert($message, array $context = []): void     { $this->log(LogLevel::ALERT,     $message, $context); }
    public function critical($message, array $context = []): void  { $this->log(LogLevel::CRITICAL,  $message, $context); }
    public function error($message, array $context = []): void     { $this->log(LogLevel::ERROR,     $message, $context); }
    public function warning($message, array $context = []): void   { $this->log(LogLevel::WARNING,   $message, $context); }
    public function notice($message, array $context = []): void    { $this->log(LogLevel::NOTICE,    $message, $context); }
    public function info($message, array $context = []): void      { $this->log(LogLevel::INFO,      $message, $context); }
    public function debug($message, array $context = []): void     { $this->log(LogLevel::DEBUG,     $message, $context); }
}