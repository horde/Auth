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
use Horde_Auth_Composite;
use Horde_Auth_Base;
use Horde_Auth_Exception;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Horde_Auth_Composite::class)]
class CompositeTest extends BaseTestCase
{
    private $authDriver;
    private $adminDriver;

    public function setUp(): void
    {
        $this->authDriver = $this->createMock(Horde_Auth_Base::class);
        $this->adminDriver = $this->createMock(Horde_Auth_Base::class);
    }

    public function testConstructorRequiresAdminDriver()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing admin_driver parameter');
        new Horde_Auth_Composite([]);
    }

    public function testConstructorRequiresAuthDriver()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing auth_driver parameter');
        new Horde_Auth_Composite(['admin_driver' => $this->adminDriver]);
    }

    public function testConstructorAcceptsBothDrivers()
    {
        $driver = new Horde_Auth_Composite([
            'auth_driver' => $this->authDriver,
            'admin_driver' => $this->adminDriver,
        ]);
        $this->assertInstanceOf(Horde_Auth_Composite::class, $driver);
    }

    public function testAuthenticateDelegatesToAuthDriver()
    {
        $this->authDriver->expects($this->once())
            ->method('authenticate')
            ->with('testuser', ['password' => 'testpass'])
            ->willReturn(true);

        $driver = new Horde_Auth_Composite([
            'auth_driver' => $this->authDriver,
            'admin_driver' => $this->adminDriver,
        ]);

        $this->assertTrue($driver->authenticate('testuser', ['password' => 'testpass']));
    }

    public function testAuthenticateReturnsFalseWhenAuthDriverFails()
    {
        $this->authDriver->expects($this->once())
            ->method('authenticate')
            ->with('testuser', ['password' => 'wrongpass'])
            ->willReturn(false);

        $this->authDriver->expects($this->atLeastOnce())
            ->method('getError')
            ->willReturnOnConsecutiveCalls('Bad login', 1);

        $driver = new Horde_Auth_Composite([
            'auth_driver' => $this->authDriver,
            'admin_driver' => $this->adminDriver,
        ]);

        $this->assertFalse($driver->authenticate('testuser', ['password' => 'wrongpass']));
    }

    /**
     * Tests that _authenticate() properly delegates and throws when auth_driver fails.
     * The archaic Horde_Auth design treats _authenticate() as the canonical driver behavior,
     * with authenticate() wrapping exceptions to booleans. Testing _authenticate() verifies error codes.
     */
    public function testProtectedAuthenticateThrowsExceptionWhenAuthDriverFails()
    {
        $this->authDriver->expects($this->once())
            ->method('authenticate')
            ->with('testuser', ['password' => 'wrongpass'])
            ->willReturn(false);

        $this->authDriver->expects($this->atLeastOnce())
            ->method('getError')
            ->willReturnOnConsecutiveCalls('Bad login', 1);

        $driver = new Horde_Auth_Composite([
            'auth_driver' => $this->authDriver,
            'admin_driver' => $this->adminDriver,
        ]);

        $method = new \ReflectionMethod($driver, '_authenticate');
        $method->setAccessible(true);

        $this->expectException(Horde_Auth_Exception::class);
        $method->invoke($driver, 'testuser', ['password' => 'wrongpass']);
    }

    public function testTransparentDelegatesToAuthDriver()
    {
        $this->authDriver->expects($this->once())
            ->method('transparent')
            ->willReturn(true);

        $driver = new Horde_Auth_Composite([
            'auth_driver' => $this->authDriver,
            'admin_driver' => $this->adminDriver,
        ]);

        $this->assertTrue($driver->transparent());
    }

    public function testHasCapabilityDelegatesToAdminDriver()
    {
        $this->adminDriver->expects($this->once())
            ->method('hasCapability')
            ->with('add')
            ->willReturn(true);

        $driver = new Horde_Auth_Composite([
            'auth_driver' => $this->authDriver,
            'admin_driver' => $this->adminDriver,
        ]);

        $this->assertTrue($driver->hasCapability('add'));
    }

    public function testAddUserDelegatesToAdminDriver()
    {
        $this->adminDriver->expects($this->once())
            ->method('addUser')
            ->with('newuser', ['password' => 'newpass']);

        $driver = new Horde_Auth_Composite([
            'auth_driver' => $this->authDriver,
            'admin_driver' => $this->adminDriver,
        ]);

        $driver->addUser('newuser', ['password' => 'newpass']);
        $this->assertTrue(true);
    }

    public function testUpdateUserDelegatesToAdminDriver()
    {
        $this->adminDriver->expects($this->once())
            ->method('updateUser')
            ->with('olduser', 'newuser', ['password' => 'newpass']);

        $driver = new Horde_Auth_Composite([
            'auth_driver' => $this->authDriver,
            'admin_driver' => $this->adminDriver,
        ]);

        $driver->updateUser('olduser', 'newuser', ['password' => 'newpass']);
        $this->assertTrue(true);
    }

    public function testRemoveUserDelegatesToAdminDriver()
    {
        $this->adminDriver->expects($this->once())
            ->method('removeUser')
            ->with('testuser');

        $driver = new Horde_Auth_Composite([
            'auth_driver' => $this->authDriver,
            'admin_driver' => $this->adminDriver,
        ]);

        $driver->removeUser('testuser');
        $this->assertTrue(true);
    }

    public function testResetPasswordDelegatesToAdminDriver()
    {
        $this->adminDriver->expects($this->once())
            ->method('resetPassword')
            ->with('testuser')
            ->willReturn('newpass123');

        $driver = new Horde_Auth_Composite([
            'auth_driver' => $this->authDriver,
            'admin_driver' => $this->adminDriver,
        ]);

        $this->assertEquals('newpass123', $driver->resetPassword('testuser'));
    }

    public function testListUsersDelegatesToAdminDriver()
    {
        $this->adminDriver->expects($this->once())
            ->method('listUsers')
            ->with(false)
            ->willReturn(['user1', 'user2']);

        $driver = new Horde_Auth_Composite([
            'auth_driver' => $this->authDriver,
            'admin_driver' => $this->adminDriver,
        ]);

        $this->assertEquals(['user1', 'user2'], $driver->listUsers());
    }

    public function testExistsDelegatesToAdminDriver()
    {
        $this->adminDriver->expects($this->once())
            ->method('exists')
            ->with('testuser')
            ->willReturn(true);

        $driver = new Horde_Auth_Composite([
            'auth_driver' => $this->authDriver,
            'admin_driver' => $this->adminDriver,
        ]);

        $this->assertTrue($driver->exists('testuser'));
    }
}
