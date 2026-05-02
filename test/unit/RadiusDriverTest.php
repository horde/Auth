<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultFail;
use Horde\Auth\CredentialProvider;
use Horde\Auth\Radius;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Radius::class)]
class RadiusDriverTest extends BaseTestCase
{
    public function testImplementsCredentialProvider(): void
    {
        $driver = new Radius(host: '127.0.0.1', secret: 'testing');

        $this->assertInstanceOf(CredentialProvider::class, $driver);
    }

    public function testRejectsEmptyPassword(): void
    {
        $driver = new Radius(host: '127.0.0.1', secret: 'testing');

        $result = $driver->validate('user', ['password' => '']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('empty_password', $result->get('reason'));
    }
}
