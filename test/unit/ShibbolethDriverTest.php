<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Shibboleth;
use Horde\Auth\TransparentProvider;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Http\Message\ServerRequestInterface;

#[CoversClass(Shibboleth::class)]
class ShibbolethDriverTest extends BaseTestCase
{
    private function makeRequest(array $serverParams): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn($serverParams);
        return $request;
    }

    public function testImplementsTransparentProvider(): void
    {
        $driver = new Shibboleth();

        $this->assertInstanceOf(TransparentProvider::class, $driver);
    }

    public function testExtractsUsernameFromHeader(): void
    {
        $driver = new Shibboleth(usernameHeader: 'HTTP_EPPN');
        $request = $this->makeRequest(['HTTP_EPPN' => 'jsmith@university.edu']);

        $result = $driver->extractIdentity($request);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('jsmith', $result->getNativeKey());
        $this->assertSame('shibboleth', $result->getBackend());
    }

    public function testReturnsNullWhenHeaderMissing(): void
    {
        $driver = new Shibboleth(usernameHeader: 'HTTP_EPPN');
        $request = $this->makeRequest([]);

        $this->assertNull($driver->extractIdentity($request));
    }

    public function testReturnsNullWhenHeaderEmpty(): void
    {
        $driver = new Shibboleth(usernameHeader: 'HTTP_EPPN');
        $request = $this->makeRequest(['HTTP_EPPN' => '']);

        $this->assertNull($driver->extractIdentity($request));
    }

    public function testStripScopeRemovesAtDomain(): void
    {
        $driver = new Shibboleth(usernameHeader: 'HTTP_EPPN', stripScope: true);
        $request = $this->makeRequest(['HTTP_EPPN' => 'alice@example.org']);

        $result = $driver->extractIdentity($request);

        $this->assertSame('alice', $result->getNativeKey());
    }

    public function testPreservesScopeWhenDisabled(): void
    {
        $driver = new Shibboleth(usernameHeader: 'HTTP_EPPN', stripScope: false);
        $request = $this->makeRequest(['HTTP_EPPN' => 'alice@example.org']);

        $result = $driver->extractIdentity($request);

        $this->assertSame('alice@example.org', $result->getNativeKey());
    }

    public function testCustomHeader(): void
    {
        $driver = new Shibboleth(usernameHeader: 'HTTP_REMOTE_USER');
        $request = $this->makeRequest(['HTTP_REMOTE_USER' => 'bob']);

        $result = $driver->extractIdentity($request);

        $this->assertSame('bob', $result->getNativeKey());
    }

    public function testUsernameWithoutScopeUnchanged(): void
    {
        $driver = new Shibboleth(usernameHeader: 'HTTP_EPPN', stripScope: true);
        $request = $this->makeRequest(['HTTP_EPPN' => 'localuser']);

        $result = $driver->extractIdentity($request);

        $this->assertSame('localuser', $result->getNativeKey());
    }
}
