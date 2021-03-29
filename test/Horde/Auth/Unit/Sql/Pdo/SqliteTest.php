<?php
/**
 * Prepare the test setup.
 */
namespace Horde\Auth\Unit\Sql\Pdo;
use Horde\Auth\Unit\Sql\Base;
use \Horde_Test_Factory_Db;
use \Horde_Db_Migration_Migrator;

/**
 * @category   Horde
 * @package    Auth
 * @subpackage UnitTests
 */

class SqliteTest extends Base
{
    public static function setUpBeforeClass(): void
    {
        $factory_db = new Horde_Test_Factory_Db();

        try {
            self::$db = $factory_db->create();
            parent::setUpBeforeClass();
        } catch (Horde_Test_Exception $e) {
            self::$reason = 'Sqlite not available.';
        }
    }

}
