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
use Horde_Auth_Ldap;
use Horde_Ldap;
use Horde_Ldap_Entry;
use Horde_Ldap_Exception;
use Horde_Ldap_Filter;
use Horde_Ldap_Search;
use Horde_Auth_Exception;
use Horde_Exception_NotFound;
use Horde_Exception_Ldap;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Horde_Auth_Ldap::class)]
class LdapTest extends BaseTestCase
{
    private $ldap;
    private Horde_Auth_Ldap $driver;

    public function setUp(): void
    {
        $this->ldap = $this->createMock(Horde_Ldap::class);
    }

    public function testConstructorRequiresBaseDn()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing basedn parameter');
        new Horde_Auth_Ldap([]);
    }

    public function testConstructorRequiresLdapConnection()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing ldap parameter');
        new Horde_Auth_Ldap(['basedn' => 'dc=example,dc=com', 'uid' => 'uid']);
    }

    public function testConstructorRequiresUid()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing uid parameter');
        new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
        ]);
    }

    public function testConstructorStoresLdapConnection()
    {
        $driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
        ]);
        $this->assertInstanceOf(Horde_Auth_Ldap::class, $driver);
    }

    public function testAuthenticateWithEmptyPasswordReturnsFalse()
    {
        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'password_expiration' => 'no',
        ]);

        $this->assertFalse($this->driver->authenticate('testuser', ['password' => '']));
    }

    /**
     * Tests that _authenticate() throws proper exception codes for error handling.
     * The archaic Horde_Auth design treats _authenticate() as the canonical driver behavior,
     * with authenticate() wrapping exceptions to booleans. Testing _authenticate() verifies error codes.
     */
    public function testProtectedAuthenticateThrowsExceptionOnEmptyPassword()
    {
        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'password_expiration' => 'no',
        ]);

        $method = new \ReflectionMethod($this->driver, '_authenticate');
        $method->setAccessible(true);

        $this->expectException(Horde_Auth_Exception::class);
        $method->invoke($this->driver, 'testuser', ['password' => '']);
    }

    /**
     * Tests that _authenticate() throws proper exception with correct error code.
     * The archaic Horde_Auth design treats _authenticate() as the canonical driver behavior,
     * with authenticate() wrapping exceptions to booleans. Testing _authenticate() verifies error codes.
     */
    public function testProtectedAuthenticateThrowsExceptionWhenUserNotFound()
    {
        $this->ldap->expects($this->once())
            ->method('bind')
            ->willReturn(true);

        $this->ldap->expects($this->once())
            ->method('findUserDN')
            ->with('testuser')
            ->willThrowException(new Horde_Exception_NotFound());

        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'password_expiration' => 'no',
        ]);

        $method = new \ReflectionMethod($this->driver, '_authenticate');
        $method->setAccessible(true);

        $this->expectException(Horde_Auth_Exception::class);
        $method->invoke($this->driver, 'testuser', ['password' => 'testpass']);
    }

    public function testAuthenticateBindsAndFindsUserDn()
    {
        $this->ldap->expects($this->atLeastOnce())
            ->method('bind')
            ->willReturn(true);

        $this->ldap->expects($this->once())
            ->method('findUserDN')
            ->with('testuser')
            ->willReturn('uid=testuser,dc=example,dc=com');

        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'password_expiration' => 'no',
        ]);

        $this->driver->authenticate('testuser', ['password' => 'testpass']);
        $this->assertTrue(true);
    }

    public function testAuthenticateReturnsFalseWhenUserNotFound()
    {
        $this->ldap->expects($this->once())
            ->method('bind')
            ->willReturn(true);

        $this->ldap->expects($this->once())
            ->method('findUserDN')
            ->with('testuser')
            ->willThrowException(new Horde_Exception_NotFound());

        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'password_expiration' => 'no',
        ]);

        $this->assertFalse($this->driver->authenticate('testuser', ['password' => 'testpass']));
    }

    public function testListUsersReturnsUserArray()
    {
        $entry1 = $this->createMock(Horde_Ldap_Entry::class);
        $entry1->expects($this->once())->method('exists')->with('uid')->willReturn(true);
        $entry1->expects($this->once())->method('getValue')->with('uid', 'single')->willReturn('user1');

        $entry2 = $this->createMock(Horde_Ldap_Entry::class);
        $entry2->expects($this->once())->method('exists')->with('uid')->willReturn(true);
        $entry2->expects($this->once())->method('getValue')->with('uid', 'single')->willReturn('user2');

        $searchResult = new \ArrayIterator([$entry1, $entry2]);

        $this->ldap->expects($this->once())
            ->method('search')
            ->willReturn($searchResult);

        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'filter' => '(objectClass=person)',
            'scope' => 'sub',
        ]);

        $users = $this->driver->listUsers();
        $this->assertEquals(['user1', 'user2'], $users);
    }

    public function testExistsReturnsTrueForPresentUser()
    {
        $searchResult = $this->createMock(Horde_Ldap_Search::class);
        $searchResult->expects($this->atLeastOnce())
            ->method('count')
            ->willReturn(1);

        $this->ldap->expects($this->once())
            ->method('search')
            ->willReturn($searchResult);

        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'filter' => '(objectClass=person)',
            'scope' => 'sub',
        ]);

        $this->assertTrue($this->driver->exists('testuser'));
    }

    public function testExistsReturnsFalseForMissingUser()
    {
        $searchResult = $this->createMock(Horde_Ldap_Search::class);
        $searchResult->expects($this->once())
            ->method('count')
            ->willReturn(0);

        $this->ldap->expects($this->once())
            ->method('search')
            ->willReturn($searchResult);

        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'filter' => '(objectClass=person)',
            'scope' => 'sub',
        ]);

        $this->assertFalse($this->driver->exists('nonexistent'));
    }

    public function testAddUserThrowsExceptionForActiveDirectory()
    {
        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'ad' => true,
        ]);

        $this->expectException(Horde_Auth_Exception::class);
        $this->expectExceptionMessage('Adding users is not supported for Active Directory');
        $this->driver->addUser('testuser', ['password' => 'testpass']);
    }

    public function testRemoveUserThrowsExceptionForActiveDirectory()
    {
        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'ad' => true,
        ]);

        $this->expectException(Horde_Auth_Exception::class);
        $this->expectExceptionMessage('Removing users is not supported for Active Directory');
        $this->driver->removeUser('testuser');
    }

    public function testUpdateUserThrowsExceptionForActiveDirectory()
    {
        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'ad' => true,
        ]);

        $this->expectException(Horde_Auth_Exception::class);
        $this->expectExceptionMessage('Updating users is not supported for Active Directory');
        $this->driver->updateUser('old', 'new', ['password' => 'pass']);
    }

    public function testResetPasswordThrowsExceptionForActiveDirectory()
    {
        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'ad' => true,
        ]);

        $this->expectException(Horde_Auth_Exception::class);
        $this->expectExceptionMessage('Updating users is not supported for Active Directory');
        $this->driver->resetPassword('testuser');
    }

    public function testActiveDirectoryDisablesResetPasswordCapability()
    {
        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
            'ad' => true,
        ]);

        $this->assertFalse($this->driver->hasCapability('resetpassword'));
    }

    public function testNonActiveDirectoryEnablesAllCapabilities()
    {
        $this->driver = new Horde_Auth_Ldap([
            'basedn' => 'dc=example,dc=com',
            'ldap' => $this->ldap,
            'uid' => 'uid',
        ]);

        $this->assertTrue($this->driver->hasCapability('add'));
        $this->assertTrue($this->driver->hasCapability('update'));
        $this->assertTrue($this->driver->hasCapability('resetpassword'));
        $this->assertTrue($this->driver->hasCapability('remove'));
        $this->assertTrue($this->driver->hasCapability('list'));
        $this->assertTrue($this->driver->hasCapability('authenticate'));
    }
}
