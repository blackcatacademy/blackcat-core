<?php
declare(strict_types=1);

namespace BlackCat\Core\Tests\Database;

use BlackCat\Core\Database;
use BlackCat\Core\DatabaseException;
use PHPUnit\Framework\TestCase;

final class SqlFirewallTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->resetDatabaseSingleton();
    }

    public function testBlocksMultiStatement(): void
    {
        $db = $this->bootSqlite();

        $this->expectException(DatabaseException::class);
        $this->expectExceptionMessage('SQL firewall');
        $db->fetchValue('SELECT 1; SELECT 2');
    }

    public function testAllowsSemicolonInsideStringAndComment(): void
    {
        $db = $this->bootSqlite();

        $v1 = $db->fetchValue("SELECT ';' AS x");
        self::assertSame(';', $v1);

        $v2 = $db->fetchValue('SELECT 1 /* ; ; */');
        self::assertSame(1, (int) $v2);
    }

    public function testBlocksLoadFileAndOutfile(): void
    {
        $db = $this->bootSqlite();

        try {
            $db->fetchValue("SELECT LOAD_FILE('/etc/passwd')");
            self::fail('Expected SQL firewall to block LOAD_FILE().');
        } catch (DatabaseException $e) {
            self::assertStringContainsString('SQL firewall', $e->getMessage());
            self::assertStringContainsString('load_file', $e->getMessage());
        }

        try {
            $db->fetchValue("SELECT 1 INTO OUTFILE '/tmp/x'");
            self::fail('Expected SQL firewall to block INTO OUTFILE.');
        } catch (DatabaseException $e) {
            self::assertStringContainsString('SQL firewall', $e->getMessage());
            self::assertStringContainsString('into_outfile', $e->getMessage());
        }
    }

    public function testDoesNotTriggerOnKeywordsInsideStringsOrComments(): void
    {
        $db = $this->bootSqlite();

        $v1 = $db->fetchValue("SELECT 'LOAD_FILE' AS x");
        self::assertSame('LOAD_FILE', $v1);

        $v2 = $db->fetchValue('SELECT 1 /* INTO OUTFILE /etc/passwd */');
        self::assertSame(1, (int) $v2);
    }

    public function testMysqlDashDashRequiresWhitespaceForLineComment(): void
    {
        $db = $this->bootPretendMysql();

        // MySQL treats "--" as a line comment only when followed by whitespace/control.
        // "1--2" is parsed as "1 - -2", so the semicolon is real and must be blocked.
        $this->expectException(DatabaseException::class);
        $this->expectExceptionMessage('SQL firewall');
        $db->fetchValue('SELECT 1--2; SELECT 2');
    }

    public function testMysqlDashDashWithWhitespaceIsLineComment(): void
    {
        $db = $this->bootPretendMysql();

        // Here the second statement is inside the comment, so firewall should allow the query.
        $v = $db->fetchValue('SELECT 1-- 2; SELECT 2');
        self::assertSame(1, (int) $v);
    }

    public function testPgsqlTreatsDashDashAsLineCommentEvenWithoutWhitespace(): void
    {
        $db = $this->bootPretendPgsql();

        // Postgres treats any "--" as a line comment.
        $v = $db->fetchValue('SELECT 1--2; SELECT 2');
        self::assertSame(1, (int) $v);
    }

    public function testPgsqlDoesNotTreatHashAsLineComment(): void
    {
        $db = $this->bootPretendPgsql();

        $this->expectException(DatabaseException::class);
        $this->expectExceptionMessage('SQL firewall');
        $db->fetchValue('SELECT 1#2; SELECT 2');
    }

    private function bootSqlite(): Database
    {
        $pdo = new \PDO('sqlite::memory:');
        Database::initFromPdo($pdo, ['sqlFirewallMode' => 'strict']);
        return Database::getInstance();
    }

    private function bootPretendMysql(): Database
    {
        return $this->bootPretendDriver('mysql', '8.0.36');
    }

    private function bootPretendPgsql(): Database
    {
        return $this->bootPretendDriver('pgsql', null);
    }

    private function bootPretendDriver(string $driver, ?string $serverVersion): Database
    {
        $pdo = new class($driver, $serverVersion) extends \PDO {
            private string $driverName;
            private ?string $serverVersion;

            public function __construct(string $driverName, ?string $serverVersion)
            {
                $this->driverName = $driverName;
                $this->serverVersion = $serverVersion;
                parent::__construct('sqlite::memory:');
            }

            public function getAttribute(int $attribute): mixed
            {
                if ($attribute === \PDO::ATTR_DRIVER_NAME) {
                    return $this->driverName;
                }
                if ($attribute === \PDO::ATTR_SERVER_VERSION && $this->serverVersion !== null) {
                    return $this->serverVersion;
                }
                return parent::getAttribute($attribute);
            }
        };

        Database::initFromPdo($pdo, ['sqlFirewallMode' => 'strict']);
        return Database::getInstance();
    }

    private function resetDatabaseSingleton(): void
    {
        $ref = new \ReflectionClass(Database::class);
        foreach ([
            'instance' => null,
            'readGuardLocked' => false,
            'readGuard' => null,
            'writeGuardLocked' => false,
            'writeGuard' => null,
            'pdoAccessGuardLocked' => false,
            'pdoAccessGuard' => null,
            'trustKernelAutoBootAttempted' => false,
        ] as $prop => $val) {
            if (!$ref->hasProperty($prop)) {
                continue;
            }
            $p = $ref->getProperty($prop);
            $p->setAccessible(true);
            $p->setValue(null, $val);
        }
    }
}
