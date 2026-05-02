<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Ipbasic;
use Horde\Auth\TransparentProvider;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Http\Message\ServerRequestInterface;

#[CoversClass(Ipbasic::class)]
class IpbasicDriverTest extends BaseTestCase
{
    private function makeRequest(array $serverParams): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn($serverParams);
        return $request;
    }

    public function testImplementsTransparentProvider(): void
    {
        $driver = new Ipbasic();

        $this->assertInstanceOf(TransparentProvider::class, $driver);
    }

    public function testMatchesWithinCidr(): void
    {
        $driver = new Ipbasic(blocks: ['192.168.1.0/24']);
        $request = $this->makeRequest(['REMOTE_ADDR' => '192.168.1.42']);

        $result = $driver->extractIdentity($request);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('192.168.1.0/24', $result->getNativeKey());
        $this->assertSame('192.168.1.42', $result->get('remote_addr'));
    }

    public function testRejectsOutsideCidr(): void
    {
        $driver = new Ipbasic(blocks: ['192.168.1.0/24']);
        $request = $this->makeRequest(['REMOTE_ADDR' => '10.0.0.1']);

        $this->assertNull($driver->extractIdentity($request));
    }

    public function testReturnsNullWithNoRemoteAddr(): void
    {
        $driver = new Ipbasic(blocks: ['0.0.0.0/0']);
        $request = $this->makeRequest([]);

        $this->assertNull($driver->extractIdentity($request));
    }

    public function testMultipleBlocksFirstMatch(): void
    {
        $driver = new Ipbasic(blocks: ['10.0.0.0/8', '192.168.0.0/16']);
        $request = $this->makeRequest(['REMOTE_ADDR' => '192.168.5.10']);

        $result = $driver->extractIdentity($request);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('192.168.0.0/16', $result->getNativeKey());
    }

    public function testWideBlockMatchesAll(): void
    {
        $driver = new Ipbasic(blocks: ['0.0.0.0/0']);
        $request = $this->makeRequest(['REMOTE_ADDR' => '203.0.113.5']);

        $result = $driver->extractIdentity($request);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
    }

    public function testNarrowBlockExactMatch(): void
    {
        $driver = new Ipbasic(blocks: ['10.1.2.3/32']);
        $request = $this->makeRequest(['REMOTE_ADDR' => '10.1.2.3']);

        $this->assertInstanceOf(AuthResultSuccess::class, $driver->extractIdentity($request));

        $request2 = $this->makeRequest(['REMOTE_ADDR' => '10.1.2.4']);
        $this->assertNull($driver->extractIdentity($request2));
    }

    public function testEmptyBlocksRejectsAll(): void
    {
        $driver = new Ipbasic(blocks: []);
        $request = $this->makeRequest(['REMOTE_ADDR' => '127.0.0.1']);

        $this->assertNull($driver->extractIdentity($request));
    }

    public function testSingleIpWithoutMask(): void
    {
        $driver = new Ipbasic(blocks: ['192.168.1.100']);
        $request = $this->makeRequest(['REMOTE_ADDR' => '192.168.1.100']);

        $this->assertInstanceOf(AuthResultSuccess::class, $driver->extractIdentity($request));

        $request2 = $this->makeRequest(['REMOTE_ADDR' => '192.168.1.101']);
        $this->assertNull($driver->extractIdentity($request2));
    }
}
