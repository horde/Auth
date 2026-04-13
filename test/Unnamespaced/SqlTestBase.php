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

use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Horde_Auth_Sql::class)]
class SqlTestBase extends BaseTestCase
{
    protected static $db;

    protected static $auth;

    protected static $migrator;

    protected static $reason;

    public static function setUpBeforeClass(): void
    {
        $dir = dirname(__FILE__, 3) . '/migration/Horde/Auth';
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
        // No skip logic - integration tests are opt-in
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

    public function testAddUserCreatesNewUser()
    {
        self::$auth->addUser('newuser', ['password' => 'newpass']);
        $this->assertTrue(self::$auth->exists('newuser'));
    }

    public function testAddedUserCanAuthenticate()
    {
        self::$auth->addUser('alice', ['password' => 'alicepass']);
        $this->assertTrue(self::$auth->authenticate('alice', ['password' => 'alicepass']));
    }

    public function testRemoveUserDeletesUser()
    {
        self::$auth->addUser('tempuser', ['password' => 'temppass']);
        $this->assertTrue(self::$auth->exists('tempuser'));
        self::$auth->removeUser('tempuser');
        $this->assertFalse(self::$auth->exists('tempuser'));
    }

    public function testUpdateUserChangesUserId()
    {
        self::$auth->addUser('oldname', ['password' => 'pass123']);
        self::$auth->updateUser('oldname', 'newname', ['password' => 'pass123']);
        $this->assertFalse(self::$auth->exists('oldname'));
        $this->assertTrue(self::$auth->exists('newname'));
    }

    public function testUpdateUserChangesPassword()
    {
        self::$auth->addUser('bob', ['password' => 'oldpass']);
        self::$auth->updateUser('bob', 'bob', ['password' => 'newpass']);
        $this->assertFalse(self::$auth->authenticate('bob', ['password' => 'oldpass']));
        $this->assertTrue(self::$auth->authenticate('bob', ['password' => 'newpass']));
    }

    public function testResetPasswordReturnsNewPassword()
    {
        self::$auth->addUser('charlie', ['password' => 'oldpass']);
        $newPass = self::$auth->resetPassword('charlie');
        $this->assertIsString($newPass);
        $this->assertGreaterThan(0, strlen($newPass));
    }

    public function testResetPasswordChangesPassword()
    {
        self::$auth->addUser('david', ['password' => 'oldpass']);
        $newPass = self::$auth->resetPassword('david');
        $this->assertFalse(self::$auth->authenticate('david', ['password' => 'oldpass']));
        $this->assertTrue(self::$auth->authenticate('david', ['password' => $newPass]));
    }
}
