<?php

declare(strict_types=1);

namespace Horde\Auth\Test;

use Closure;
use DateTimeImmutable;
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Imap;
use Horde\Imap\Client\ConnectionConfig;
use Horde\Imap\Client\Exception\AuthenticationException;
use Horde\Imap\Client\Exception\MailboxProtocolException;
use Horde\Imap\Client\MailboxProtocol;
use Horde\Imap\Client\SecureMode;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;

#[CoversClass(Imap::class)]
class ImapTest extends TestCase
{
    private function makeDriver(MailboxProtocol $client): Imap
    {
        $factory = Closure::fromCallable(fn(ConnectionConfig $config): MailboxProtocol => $client);

        return new Imap(
            clientFactory: $factory,
            hostspec: 'imap.example.com',
            secure: SecureMode::Tls,
            port: 993,
        );
    }

    public function testValidateSuccess(): void
    {
        $client = $this->createMock(MailboxProtocol::class);
        $client->expects($this->once())->method('login');
        $client->expects($this->once())->method('logout');

        $driver = $this->makeDriver($client);
        $result = $driver->validate('alice', ['password' => 'secret']);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('alice', $result->getNativeKey());
    }

    public function testValidateFailOnBadPassword(): void
    {
        $client = $this->createMock(MailboxProtocol::class);
        $client->expects($this->once())
            ->method('login')
            ->willThrowException(new AuthenticationException('Login failed'));

        $driver = $this->makeDriver($client);
        $result = $driver->validate('alice', ['password' => 'wrong']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('bad_password', $result->get('reason'));
    }

    public function testValidateThrowsOnInfrastructureError(): void
    {
        $client = $this->createMock(MailboxProtocol::class);
        $client->expects($this->once())
            ->method('login')
            ->willThrowException(new MailboxProtocolException('Connection refused'));

        $driver = $this->makeDriver($client);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('IMAP server error');
        $driver->validate('alice', ['password' => 'secret']);
    }

    public function testValidateSucceedsEvenIfLogoutFails(): void
    {
        $client = $this->createMock(MailboxProtocol::class);
        $client->expects($this->once())->method('login');
        $client->expects($this->once())
            ->method('logout')
            ->willThrowException(new MailboxProtocolException('Timeout'));

        $driver = $this->makeDriver($client);
        $result = $driver->validate('bob', ['password' => 'pass']);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('bob', $result->getNativeKey());
    }

    public function testFactoryReceivesCorrectConfig(): void
    {
        $capturedConfig = null;
        $client = $this->createMock(MailboxProtocol::class);
        $client->method('login');
        $client->method('logout');

        $factory = function (ConnectionConfig $config) use (&$capturedConfig, $client): MailboxProtocol {
            $capturedConfig = $config;
            return $client;
        };

        $driver = new Imap(
            clientFactory: Closure::fromCallable($factory),
            hostspec: 'mail.test.org',
            secure: SecureMode::Ssl,
            port: 993,
        );

        $driver->validate('testuser', ['password' => 'testpass']);

        $this->assertNotNull($capturedConfig);
        $this->assertSame('testuser', $capturedConfig->username);
        $this->assertSame('testpass', $capturedConfig->password);
        $this->assertSame('mail.test.org', $capturedConfig->hostspec);
        $this->assertSame(993, $capturedConfig->port);
        $this->assertSame(SecureMode::Ssl, $capturedConfig->secure);
    }
}
