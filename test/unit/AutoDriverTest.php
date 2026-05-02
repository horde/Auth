<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\Auto;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Http\Message\ServerRequestInterface;

#[CoversClass(Auto::class)]
class AutoDriverTest extends BaseTestCase
{
    public function testExtractIdentityReturnsConfiguredUsername(): void
    {
        $driver = new Auto(username: 'testuser');
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn([]);
        $request->method('getParsedBody')->willReturn([]);
        $request->method('getCookieParams')->willReturn([]);

        $result = $driver->extractIdentity($request);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('testuser', $result->getNativeKey());
        $this->assertSame('auto', $result->getBackend());
    }

    public function testExtractIdentityFromQueryParam(): void
    {
        $driver = new Auto(username: 'default', allowRequestUser: true);
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn(['username' => 'fromquery']);
        $request->method('getParsedBody')->willReturn([]);
        $request->method('getCookieParams')->willReturn([]);

        $result = $driver->extractIdentity($request);

        $this->assertSame('fromquery', $result->getNativeKey());
    }

    public function testExtractIdentityFromPostBody(): void
    {
        $driver = new Auto(username: 'default', allowRequestUser: true);
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn([]);
        $request->method('getParsedBody')->willReturn(['username' => 'frompost']);
        $request->method('getCookieParams')->willReturn([]);

        $result = $driver->extractIdentity($request);

        $this->assertSame('frompost', $result->getNativeKey());
    }

    public function testExtractIdentityFromCookie(): void
    {
        $driver = new Auto(username: 'default', allowRequestUser: true);
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn([]);
        $request->method('getParsedBody')->willReturn([]);
        $request->method('getCookieParams')->willReturn(['username' => 'fromcookie']);

        $result = $driver->extractIdentity($request);

        $this->assertSame('fromcookie', $result->getNativeKey());
    }

    public function testIgnoresRequestUserWhenDisabled(): void
    {
        $driver = new Auto(username: 'hardcoded', allowRequestUser: false);
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn(['username' => 'ignored']);
        $request->method('getParsedBody')->willReturn([]);
        $request->method('getCookieParams')->willReturn([]);

        $result = $driver->extractIdentity($request);

        $this->assertSame('hardcoded', $result->getNativeKey());
    }
}
