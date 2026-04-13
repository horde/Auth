<?php

/**
 * Copyright 2010-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @category   Horde
 * @package    Auth
 * @subpackage UnitTests
 */

use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Horde_Auth_Sql::class)]
class SqlLockTestBase extends SqlTestBase
{
    protected static $locksMigrator;

    protected static $locks;

    protected static $skip = '';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        // Find Lock migration path
        $possiblePaths = [
            __DIR__ . '/../../vendor/horde/lock/migration',
            __DIR__ . '/../../../../../../Lock/migration',
            __DIR__ . '/../../../../../../deps/Lock/migration',
        ];

        $lockMigrationsPath = null;
        foreach ($possiblePaths as $path) {
            if (is_dir($path)) {
                $lockMigrationsPath = $path;
                break;
            }
        }

        if (!$lockMigrationsPath) {
            self::$skip = 'Could not determine path to Horde_Lock migration';
            return;
        }

        self::$locksMigrator = new Horde_Db_Migration_Migrator(
            self::$db,
            null,
            ['migrationsPath' => $lockMigrationsPath,
                'schemaTableName' => 'horde_lock_schema_info']
        );
        self::$locksMigrator->up();

        self::$locks = new Horde_Lock_Sql(['db' => self::$db]);

        self::$auth = new Horde_Auth_Sql(['db' => self::$db,
            'encryption' => 'plain',
            'lock_api'   => self::$locks,
        ]);
    }

    public function setUp(): void
    {
        if (self::$skip) {
            $this->markTestSkipped(self::$skip);
        }
        // portability: use DELETE because SQLite has no truncate
        $sql = "DELETE FROM horde_locks";
        self::$db->execute($sql);
    }


    public function testAuthenticate()
    {
        $this->assertTrue(self::$auth->authenticate('tux', ['password' => 'fish']));
    }


    public function testLockUserOnceWorks()
    {
        self::$auth->lockUser('konqui');
        $this->assertTrue(self::$auth->isLocked('konqui'));
    }

    public function testLockUserTwiceFails()
    {
        $this->expectException(Horde_Auth_Exception::class);
        self::$auth->lockUser('konqui');
        self::$auth->lockUser('konqui');
    }

    public function testLockCapability()
    {
        $this->assertTrue(self::$auth->hasCapability('lock'));
    }

    public function testLockedUserReportsAsLocked()
    {
        self::$auth->lockUser('konqui');
        $this->assertTrue(self::$auth->isLocked('konqui'));
    }

    public function testLockedUserCannotLogin()
    {
        self::$auth->lockUser('konqui');
        $this->assertFalse(self::$auth->authenticate('konqui', ['password' => 'kde']));
    }

    public function testUnlockUnlockedDoesNotThrowException()
    {
        self::$auth->unlockUser('konqui');
        self::$auth->unlockUser('konqui');
        self::$auth->unlockUser('konqui');
        $this->assertFalse(self::$auth->isLocked('konqui'));
    }

}
