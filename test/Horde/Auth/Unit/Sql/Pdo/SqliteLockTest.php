<?php
/**
 * Prepare the test setup.
 */
namespace Horde\Auth\Unit\Sql\Pdo;
use Horde_Auth_Unit_Sql_Locks as Locks;
use \Horde_Test_Factory_Db;

require_once __DIR__ . '/../Locks.php';

/**
 * @category   Horde
 * @package    Auth
 * @subpackage UnitTests
 */

class SqliteLockTest extends Locks
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
