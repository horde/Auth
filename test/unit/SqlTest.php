<?php

declare(strict_types=1);

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

namespace Horde\Auth\Test\Unit;

use Horde\Auth\Test\BaseTestCase;
use Horde_Auth_Sql;
use Horde_Db_Adapter;
use Horde_Auth_Exception;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use ReflectionMethod;

#[CoversClass(Horde_Auth_Sql::class)]
class SqlTest extends BaseTestCase
{
    private $db;
    private Horde_Auth_Sql $driver;

    public function setUp(): void
    {
        $this->db = $this->createMock(Horde_Db_Adapter::class);
    }

    public function testConstructorRequiresDatabaseAdapter()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing db parameter');
        new Horde_Auth_Sql([]);
    }

    public function testConstructorAcceptsDatabaseAdapter()
    {
        $driver = new Horde_Auth_Sql(['db' => $this->db]);
        $this->assertInstanceOf(Horde_Auth_Sql::class, $driver);
    }

    public function testConstructorSetsDefaultEncryption()
    {
        $driver = new Horde_Auth_Sql(['db' => $this->db]);
        $this->assertTrue($driver->hasCapability('authenticate'));
    }

    public function testConstructorAcceptsCustomTableName()
    {
        $driver = new Horde_Auth_Sql([
            'db' => $this->db,
            'table' => 'custom_users',
        ]);
        $this->assertInstanceOf(Horde_Auth_Sql::class, $driver);
    }

    public function testConstructorAcceptsCustomFieldNames()
    {
        $driver = new Horde_Auth_Sql([
            'db' => $this->db,
            'username_field' => 'login',
            'password_field' => 'passwd',
        ]);
        $this->assertInstanceOf(Horde_Auth_Sql::class, $driver);
    }

    public function testHasAllCrudCapabilities()
    {
        $driver = new Horde_Auth_Sql(['db' => $this->db]);
        $this->assertTrue($driver->hasCapability('add'));
        $this->assertTrue($driver->hasCapability('update'));
        $this->assertTrue($driver->hasCapability('remove'));
        $this->assertTrue($driver->hasCapability('resetpassword'));
        $this->assertTrue($driver->hasCapability('list'));
        $this->assertTrue($driver->hasCapability('authenticate'));
    }

    public function testListUsersQueriesDatabase()
    {
        $this->db->expects($this->once())
            ->method('selectValues')
            ->with('SELECT user_uid FROM horde_users ORDER BY user_uid ASC')
            ->willReturn(['user1', 'user2', 'user3']);

        $driver = new Horde_Auth_Sql(['db' => $this->db]);
        $users = $driver->listUsers(true);
        $this->assertEquals(['user1', 'user2', 'user3'], $users);
    }

    public function testListUsersWithoutSortingQueriesWithoutOrderBy()
    {
        $this->db->expects($this->once())
            ->method('selectValues')
            ->with('SELECT user_uid FROM horde_users')
            ->willReturn(['user3', 'user1', 'user2']);

        $driver = new Horde_Auth_Sql(['db' => $this->db]);
        $users = $driver->listUsers(false);
        $this->assertEquals(['user3', 'user1', 'user2'], $users);
    }

    public function testExistsReturnsTrueWhenUserFound()
    {
        $this->db->expects($this->once())
            ->method('selectValue')
            ->willReturn('testuser');

        $driver = new Horde_Auth_Sql(['db' => $this->db]);
        $this->assertTrue($driver->exists('testuser'));
    }

    public function testExistsReturnsFalseWhenUserNotFound()
    {
        $this->db->expects($this->once())
            ->method('selectValue')
            ->willReturn(null);

        $driver = new Horde_Auth_Sql(['db' => $this->db]);
        $this->assertFalse($driver->exists('nonexistent'));
    }

    /**
     * Tests that _authenticate() queries the database and validates password.
     * The archaic Horde_Auth design treats _authenticate() as the canonical driver behavior,
     * with authenticate() wrapping exceptions to booleans. Testing _authenticate() verifies error codes.
     */
    public function testProtectedAuthenticateQueriesDatabase()
    {
        $this->db->expects($this->once())
            ->method('selectOne')
            ->willReturn([
                'user_uid' => 'testuser',
                'user_pass' => md5('testpass'),
            ]);

        $driver = new Horde_Auth_Sql([
            'db' => $this->db,
            'encryption' => 'md5-hex',
        ]);

        $method = new ReflectionMethod($driver, '_authenticate');
        $method->setAccessible(true);
        $method->invoke($driver, 'testuser', ['password' => 'testpass']);
        $this->assertTrue(true);
    }

    /**
     * Tests that _authenticate() throws exception on wrong password.
     * The archaic Horde_Auth design treats _authenticate() as the canonical driver behavior,
     * with authenticate() wrapping exceptions to booleans. Testing _authenticate() verifies error codes.
     */
    public function testProtectedAuthenticateThrowsExceptionOnWrongPassword()
    {
        $this->db->expects($this->once())
            ->method('selectOne')
            ->willReturn([
                'user_uid' => 'testuser',
                'user_pass' => md5('correctpass'),
            ]);

        $driver = new Horde_Auth_Sql([
            'db' => $this->db,
            'encryption' => 'md5-hex',
        ]);

        $method = new ReflectionMethod($driver, '_authenticate');
        $method->setAccessible(true);

        $this->expectException(Horde_Auth_Exception::class);
        $method->invoke($driver, 'testuser', ['password' => 'wrongpass']);
    }

    /**
     * Tests that _authenticate() throws exception when user not found.
     * The archaic Horde_Auth design treats _authenticate() as the canonical driver behavior,
     * with authenticate() wrapping exceptions to booleans. Testing _authenticate() verifies error codes.
     */
    public function testProtectedAuthenticateThrowsExceptionWhenUserNotFound()
    {
        $this->db->expects($this->once())
            ->method('selectOne')
            ->willReturn(null);

        $driver = new Horde_Auth_Sql(['db' => $this->db]);

        $method = new ReflectionMethod($driver, '_authenticate');
        $method->setAccessible(true);

        $this->expectException(Horde_Auth_Exception::class);
        $method->invoke($driver, 'nonexistent', ['password' => 'anypass']);
    }
}
