<?php

/**
 * Prepare the test setup.
 */

namespace Horde\Auth\Test\Sql\Pdo;

use Horde\Auth\Test\Unit\Sql\Locks;
use Horde_Test_Factory_Db;

use PHPUnit\Framework\Attributes\CoversNothing;

#[CoversNothing]

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
