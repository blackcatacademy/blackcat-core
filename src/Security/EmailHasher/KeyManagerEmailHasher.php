<?php
declare(strict_types=1);

namespace BlackCat\Core\Security\EmailHasher;

use BlackCat\Auth\Identity\EmailHashCandidate;
use BlackCat\Auth\Identity\EmailHasherInterface;
use BlackCat\Core\Security\KeyManager;

final class KeyManagerEmailHasher implements EmailHasherInterface
{
    public function __construct(
        private readonly ?string $keysDir = null,
        private readonly string $envName = 'EMAIL_HASH_KEY',
        private readonly string $basename = 'email_hash_key'
    ) {}

    public function normalize(string $email): string
    {
        $normalized = trim($email);
        if (class_exists(\Normalizer::class, true)) {
            $normalized = \Normalizer::normalize($normalized, \Normalizer::FORM_C) ?: $normalized;
        }
        return mb_strtolower($normalized, 'UTF-8');
    }

    public function candidates(string $normalizedEmail): array
    {
        try {
            $list = KeyManager::deriveHmacCandidates($this->envName, $this->keysDir, $this->basename, $normalizedEmail, 16);
        } catch (\Throwable) {
            $list = [];
        }
        $out = [];
        foreach ($list as $candidate) {
            if (!isset($candidate['hash'])) {
                continue;
            }
            $out[] = new EmailHashCandidate($candidate['hash'], $candidate['version'] ?? null);
        }
        return $out;
    }

    public function latest(string $normalizedEmail): ?EmailHashCandidate
    {
        try {
            $info = KeyManager::deriveHmacWithLatest($this->envName, $this->keysDir, $this->basename, $normalizedEmail);
            if (!isset($info['hash'])) {
                return null;
            }
            return new EmailHashCandidate($info['hash'], $info['version'] ?? null);
        } catch (\Throwable) {
            return null;
        }
    }
}
