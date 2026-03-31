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
use Horde_Auth_Pam;
use Horde_Auth_Exception;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;

#[CoversClass(Horde_Auth_Pam::class)]
class PamTest extends BaseTestCase
{
    public function testConstructorThrowsExceptionWhenPamExtensionMissing()
    {
        if (extension_loaded('pam')) {
            $this->markTestSkipped('PAM extension is loaded, cannot test missing extension behavior');
        }

        $this->expectException(Horde_Auth_Exception::class);
        $this->expectExceptionMessage('PAM authentication is not available');
        new Horde_Auth_Pam();
    }

    #[RequiresPhpExtension('pam')]
    public function testConstructorSucceedsWithPamExtension()
    {
        $driver = new Horde_Auth_Pam();
        $this->assertInstanceOf(Horde_Auth_Pam::class, $driver);
    }

    #[RequiresPhpExtension('pam')]
    public function testConstructorAcceptsServiceParameter()
    {
        $driver = new Horde_Auth_Pam(['service' => 'myservice']);
        $this->assertInstanceOf(Horde_Auth_Pam::class, $driver);
        $this->assertEquals('myservice', ini_get('pam.servicename'));
    }

    #[RequiresPhpExtension('pam')]
    public function testAuthenticateReturnsFalseOnEmptyPassword()
    {
        $driver = new Horde_Auth_Pam();
        $this->assertFalse($driver->authenticate('testuser', ['password' => '']));
    }

    /**
     * Tests that _authenticate() throws proper exception for error handling.
     * The archaic Horde_Auth design treats _authenticate() as the canonical driver behavior,
     * with authenticate() wrapping exceptions to booleans. Testing _authenticate() verifies error codes.
     */
    public function testProtectedAuthenticateThrowsExceptionOnEmptyPassword()
    {
        if (!extension_loaded('pam')) {
            $this->markTestSkipped('PAM extension not available');
        }

        $driver = new Horde_Auth_Pam();
        $method = new \ReflectionMethod($driver, '_authenticate');
        $method->setAccessible(true);

        $this->expectException(Horde_Auth_Exception::class);
        $method->invoke($driver, 'testuser', ['password' => '']);
    }
}
