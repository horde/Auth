<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultFail;
use Horde\Auth\CredentialProvider;
use Horde\Auth\Login;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Login::class)]
class LoginDriverTest extends BaseTestCase
{
    public function testImplementsCredentialProvider(): void
    {
        $driver = new Login();

        $this->assertInstanceOf(CredentialProvider::class, $driver);
    }

    public function testRejectsEmptyPassword(): void
    {
        $driver = new Login();

        $result = $driver->validate('user', ['password' => '']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('empty_password', $result->get('reason'));
    }

    public function testRejectsPasswordTooLong(): void
    {
        $driver = new Login(passwordLengthLimit: 10);

        $result = $driver->validate('user', ['password' => str_repeat('a', 11)]);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('password_too_long', $result->get('reason'));
    }

    public function testRejectsInvalidUsername(): void
    {
        $driver = new Login();

        $result = $driver->validate('user; rm -rf /', ['password' => 'test']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('invalid_username', $result->get('reason'));
    }

    public function testAcceptsValidUsernameFormat(): void
    {
        $driver = new Login(suPath: '/bin/false');

        $result = $driver->validate('valid.user-name_1', ['password' => 'test']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertContains($result->get('reason'), ['bad_credentials', 'process_failed']);
    }
}
