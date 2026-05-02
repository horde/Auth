<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultFail;
use Horde\Auth\CredentialProvider;
use Horde\Auth\Peclsasl;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Peclsasl::class)]
class PeclsaslDriverTest extends BaseTestCase
{
    public function testImplementsCredentialProvider(): void
    {
        $driver = new Peclsasl();

        $this->assertInstanceOf(CredentialProvider::class, $driver);
    }

    public function testRejectsEmptyPassword(): void
    {
        $driver = new Peclsasl();

        $result = $driver->validate('user', ['password' => '']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('empty_password', $result->get('reason'));
    }
}
