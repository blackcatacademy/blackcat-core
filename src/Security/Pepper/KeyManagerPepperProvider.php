<?php
declare(strict_types=1);

namespace BlackCat\Core\Security\Pepper;

use BlackCat\Auth\Password\Pepper;
use BlackCat\Auth\Password\PepperProviderInterface;
use BlackCat\Core\Security\KeyManager;

final class KeyManagerPepperProvider implements PepperProviderInterface
{
    public function __construct(private readonly ?string $keysDir = null) {}

    public function current(): Pepper
    {
        $info = KeyManager::getPasswordPepperInfo($this->keysDir);
        return new Pepper($info['raw'], $info['version'] ?? 'v1');
    }

    public function all(): array
    {
        $versions = KeyManager::listKeyVersions($this->keysDir, 'password_pepper');
        $peppers = [];
        foreach (array_keys($versions) as $version) {
            $pep = $this->byVersion($version);
            if ($pep !== null) {
                $peppers[] = $pep;
            }
        }
        if ($peppers === []) {
            $peppers[] = $this->current();
        }
        return $peppers;
    }

    public function byVersion(string $version): ?Pepper
    {
        try {
            $info = KeyManager::getRawKeyBytesByVersion('PASSWORD_PEPPER', $this->keysDir, 'password_pepper', $version, 32);
            if (!isset($info['raw'])) {
                return null;
            }
            return new Pepper($info['raw'], $version);
        } catch (\Throwable) {
            return null;
        }
    }
}
