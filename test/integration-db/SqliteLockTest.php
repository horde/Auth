<?php

/**
 * SQLite integration tests for Horde_Auth_Sql with locking.
 *
 * Copyright 2010-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 */

namespace Horde\Auth\Test\IntegrationDb;

use SqlLockTestBase;
use Horde_Db_Adapter_Pdo_Sqlite;
use Exception;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Horde_Auth_Sql::class)]
class SqliteLockTest extends SqlLockTestBase
{
    public static function setUpBeforeClass(): void
    {
        self::$db = new Horde_Db_Adapter_Pdo_Sqlite([
            'dbname' => ':memory:',
            'charset' => 'utf-8',
        ]);
        parent::setUpBeforeClass();
    }
}
