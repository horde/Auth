<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultFail;
use Horde\Auth\CredentialProvider;
use Horde\Auth\Ftp;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use ReflectionClass;

#[CoversClass(Ftp::class)]
class FtpDriverTest extends BaseTestCase
{
    public function testImplementsCredentialProvider(): void
    {
        $driver = new Ftp();

        $this->assertInstanceOf(CredentialProvider::class, $driver);
    }

    public function testValidateRejectsEmptyPassword(): void
    {
        $driver = new Ftp();

        $result = $driver->validate('user', ['password' => '']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('empty_password', $result->get('reason'));
    }

    #[RequiresPhpExtension('ftp')]
    public function testValidateFailsOnUnreachableHost(): void
    {
        $driver = new Ftp(host: '192.0.2.1', port: 21, timeout: 2);

        $result = $driver->validate('user', ['password' => 'pass']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('connection_failed', $result->get('reason'));
    }

    public function testConstructorDefaults(): void
    {
        $driver = new Ftp();
        $reflection = new ReflectionClass($driver);

        $host = $reflection->getProperty('host');
        $port = $reflection->getProperty('port');

        $this->assertSame('localhost', $host->getValue($driver));
        $this->assertSame(21, $port->getValue($driver));
    }

    public function testConstructorCustomParams(): void
    {
        $driver = new Ftp(host: 'ftp.example.com', port: 2121);
        $reflection = new ReflectionClass($driver);

        $host = $reflection->getProperty('host');
        $port = $reflection->getProperty('port');

        $this->assertSame('ftp.example.com', $host->getValue($driver));
        $this->assertSame(2121, $port->getValue($driver));
    }
}
