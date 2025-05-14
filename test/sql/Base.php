<?php

/**
 * @category   Horde
 * @package    Auth
 * @subpackage UnitTests
 */

namespace Horde\Auth\Test\Sql;

use Horde\Auth\Test\BaseTestCase;
use Horde_Db_Migration_Migrator;
use Horde_Auth_Sql;
use RuntimeException;
use PHPUnit\Framework\Attributes\CoversNothing;

#[CoversNothing]
class Base extends BaseTestCase
{
    public function __construct()
    {
        parent::__construct(static::class);
    }
    protected static $db;

    protected static $auth;

    protected static $migrator;

    protected static $reason;

    public static function setUpBeforeClass(): void
    {
        $dir = dirname(__FILE__, 4) . '/migration/Horde/Auth';
        if (!is_dir($dir)) {
            throw new RuntimeException("Did not find Horde Auth migration files in $dir");
        }
        self::$migrator = new Horde_Db_Migration_Migrator(
            self::$db,
            null,
            ['migrationsPath' => $dir,
                'schemaTableName' => 'horde_auth_schema_info']
        );
        self::$migrator->up();

        self::$auth = new Horde_Auth_Sql(['db' => self::$db, 'encryption' => 'plain']);
        // Don't rely on auth->addUser as this is the unit under test
        $row = "INSERT INTO horde_users VALUES ('mozilla', 'liketokyo', NULL, NULL);";
        self::$db->execute($row);
        $row = "INSERT INTO horde_users VALUES ('konqui', 'kde', NULL, NULL);";
        self::$db->execute($row);
        $row = "INSERT INTO horde_users VALUES ('tux', 'fish', NULL, NULL);";
        self::$db->execute($row);
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$migrator) {
            self::$migrator->down();
        }
        if (self::$db) {
            self::$db->disconnect();
            self::$db = null;
        }
        parent::tearDownAfterClass();
    }

    public function setUp(): void
    {
        if (!self::$db) {
            $this->markTestSkipped(self::$reason);
        }
    }

    public function testAuthenticate()
    {
        if (class_exists('Horde_Db_Adapter_Pdo_Sqlite')) {
            $this->assertTrue(self::$auth->authenticate('tux', ['password' => 'fish']));
        }
    }

    public function testListUsers()
    {
        $resultUnsorted = self::$auth->listUsers();
        sort($resultUnsorted);
        $this->assertEquals(['konqui', 'mozilla', 'tux'], $resultUnsorted);
    }
    public function testListUsersWithSorting()
    {
        $this->assertEquals(['konqui', 'mozilla', 'tux'], self::$auth->listUsers(true));
    }

    public function testLockCapability()
    {
        $this->assertFalse(self::$auth->hasCapability('lock'));
    }

    public function testExistsReturnsTrueForPresentUser()
    {
        $this->assertTrue(self::$auth->exists('konqui'));
    }

    public function testExistsReturnsFalseForMissingUser()
    {
        $this->assertFalse(self::$auth->exists('beasty'));
    }
}
