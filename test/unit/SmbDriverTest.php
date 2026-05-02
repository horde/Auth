<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultFail;
use Horde\Auth\CredentialProvider;
use Horde\Auth\Smb;
use Horde\Auth\Smbclient;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Smb::class)]
#[CoversClass(Smbclient::class)]
class SmbDriverTest extends BaseTestCase
{
    public function testSmbImplementsCredentialProvider(): void
    {
        $driver = new Smb(hostspec: '192.168.1.1', domain: 'WORKGROUP');

        $this->assertInstanceOf(CredentialProvider::class, $driver);
    }

    public function testSmbRejectsEmptyPassword(): void
    {
        $driver = new Smb(hostspec: '192.168.1.1', domain: 'WORKGROUP');

        $result = $driver->validate('user', ['password' => '']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('empty_password', $result->get('reason'));
    }

    public function testSmbclientImplementsCredentialProvider(): void
    {
        $driver = new Smbclient(hostspec: '192.168.1.1', domain: 'WORKGROUP');

        $this->assertInstanceOf(CredentialProvider::class, $driver);
    }

    public function testSmbclientRejectsEmptyPassword(): void
    {
        $driver = new Smbclient(hostspec: '192.168.1.1', domain: 'WORKGROUP');

        $result = $driver->validate('user', ['password' => '']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('empty_password', $result->get('reason'));
    }
}
