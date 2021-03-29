<?php
/**
 * @category   Horde
 * @package    Auth
 * @subpackage UnitTests
 */
namespace Horde\Auth\Unit\Sql;
use Horde\Auth\TestCase;
use \Horde_Db_Migration_Migrator;
use \Horde_Auth_Sql;

class Base extends TestCase
{
    protected static $db;

    protected static $auth;

    protected static $migrator;

    protected static $reason;

    public static function setUpBeforeClass(): void
    {
        $dir = __DIR__ . '/../../../../../migration/Horde/Auth';
        if (!is_dir($dir)) {
            error_reporting(E_ALL & ~E_DEPRECATED);
            $dir = PEAR_Config::singleton()
                ->get('data_dir', null, 'pear.horde.org')
                . '/Horde_Auth/migration';
            error_reporting(E_ALL | E_STRICT);
        }
        self::$migrator = new Horde_Db_Migration_Migrator(
            self::$db,
            null,
            array('migrationsPath' => $dir,
                  'schemaTableName' => 'horde_auth_schema_info'));
        self::$migrator->up();

        self::$auth = new Horde_Auth_Sql(array('db' => self::$db, 'encryption' => 'plain'));
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
            $this->assertTrue(self::$auth->authenticate('tux', array('password' => 'fish')));
        }
    }

    public function testListUsers()
    {
        $resultUnsorted = self::$auth->listUsers();
        sort($resultUnsorted);
        $this->assertEquals(array('konqui', 'mozilla', 'tux'), $resultUnsorted);
    }
    public function testListUsersWithSorting()
    {
        $this->assertEquals(array('konqui', 'mozilla', 'tux'), self::$auth->listUsers(true));
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
