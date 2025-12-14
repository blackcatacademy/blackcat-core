<?php
declare(strict_types=1);

namespace BlackCat\Core\Tests\Security;

use BlackCat\Core\Security\Crypto;
use BlackCat\Core\Security\KeyManager;
use PHPUnit\Framework\TestCase;

final class CryptoTest extends TestCase
{
    public function testEncryptDecryptRoundTripBinary(): void
    {
        $key = random_bytes(KeyManager::keyByteLen());
        $cipher = Crypto::encryptWithKeyBytes('hello', $key, 'binary');
        $plain = Crypto::decryptWithKeyCandidates($cipher, [$key]);

        self::assertSame('hello', $plain);
    }

    public function testEncryptDecryptRoundTripCompactBase64(): void
    {
        $key = random_bytes(KeyManager::keyByteLen());
        $cipher = Crypto::encryptWithKeyBytes('hello', $key, 'compact_base64');
        $plain = Crypto::decryptWithKeyCandidates($cipher, [$key]);

        self::assertSame('hello', $plain);
    }
}

