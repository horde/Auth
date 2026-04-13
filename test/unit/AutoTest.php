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
use Horde_Auth_Auto;
use Horde_Auth_Exception;
use PHPUnit\Framework\Attributes\CoversClass;
use ReflectionMethod;

#[CoversClass(Horde_Auth_Auto::class)]
class AutoTest extends BaseTestCase
{
    public function testConstructorSetsDefaultUsername()
    {
        $driver = new Horde_Auth_Auto();
        $this->assertInstanceOf(Horde_Auth_Auto::class, $driver);
    }

    public function testConstructorAcceptsCustomUsername()
    {
        $driver = new Horde_Auth_Auto(['username' => 'custom_user']);
        $this->assertInstanceOf(Horde_Auth_Auto::class, $driver);
    }

    public function testConstructorAcceptsPasswordParameter()
    {
        $driver = new Horde_Auth_Auto(['password' => 'secret123']);
        $this->assertInstanceOf(Horde_Auth_Auto::class, $driver);
    }

    public function testConstructorAcceptsRequestUserParameter()
    {
        $driver = new Horde_Auth_Auto(['requestuser' => true]);
        $this->assertInstanceOf(Horde_Auth_Auto::class, $driver);
    }

    public function testTransparentCapabilityEnabled()
    {
        $driver = new Horde_Auth_Auto();
        $this->assertTrue($driver->hasCapability('transparent'));
    }

    public function testTransparentReturnsTrue()
    {
        $driver = new Horde_Auth_Auto(['username' => 'test_auto_user']);
        $this->assertTrue($driver->transparent());
    }

    public function testTransparentUsesDefaultUsername()
    {
        $driver = new Horde_Auth_Auto(['username' => 'my_default_user']);
        $driver->transparent();
        $this->assertEquals('my_default_user', $driver->getCredential('userId'));
    }

    public function testTransparentUsesRequestUsernameWhenEnabled()
    {
        $_REQUEST['username'] = 'request_user';
        $driver = new Horde_Auth_Auto([
            'username' => 'default_user',
            'requestuser' => true,
        ]);
        $driver->transparent();
        $this->assertEquals('request_user', $driver->getCredential('userId'));
        unset($_REQUEST['username']);
    }

    public function testTransparentIgnoresRequestUsernameWhenDisabled()
    {
        $_REQUEST['username'] = 'request_user';
        $driver = new Horde_Auth_Auto([
            'username' => 'default_user',
            'requestuser' => false,
        ]);
        $driver->transparent();
        $this->assertEquals('default_user', $driver->getCredential('userId'));
        unset($_REQUEST['username']);
    }

    public function testTransparentSetsPasswordCredential()
    {
        $driver = new Horde_Auth_Auto([
            'username' => 'test_user',
            'password' => 'test_password',
        ]);
        $driver->transparent();
        $creds = $driver->getCredential('credentials');
        $this->assertEquals('test_password', $creds['password']);
    }

    public function testAuthenticateThrowsException()
    {
        $driver = new Horde_Auth_Auto();
        $this->assertFalse($driver->authenticate('anyuser', ['password' => 'anypass']));
    }

    /**
     * Tests that _authenticate() throws "Unsupported" exception.
     * The archaic Horde_Auth design treats _authenticate() as the canonical driver behavior,
     * with authenticate() wrapping exceptions to booleans. Testing _authenticate() verifies error codes.
     */
    public function testProtectedAuthenticateThrowsUnsupportedException()
    {
        $driver = new Horde_Auth_Auto();
        $method = new ReflectionMethod($driver, '_authenticate');
        $method->setAccessible(true);

        $this->expectException(Horde_Auth_Exception::class);
        $this->expectExceptionMessage('Unsupported');
        $method->invoke($driver, 'anyuser', ['password' => 'anypass']);
    }
}
