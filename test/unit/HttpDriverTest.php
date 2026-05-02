<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\CredentialProvider;
use Horde\Auth\Http;
use Horde\Auth\TransparentProvider;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Http\Message\ServerRequestInterface;

#[CoversClass(Http::class)]
class HttpDriverTest extends BaseTestCase
{
    private function makeRequest(array $serverParams): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn($serverParams);
        return $request;
    }

    public function testImplementsInterfaces(): void
    {
        $driver = new Http();

        $this->assertInstanceOf(TransparentProvider::class, $driver);
        $this->assertInstanceOf(CredentialProvider::class, $driver);
    }

    public function testExtractIdentityFromAuthHeaders(): void
    {
        $driver = new Http();
        $request = $this->makeRequest([
            'PHP_AUTH_USER' => 'alice',
            'PHP_AUTH_PW' => 'secret',
        ]);

        $result = $driver->extractIdentity($request);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('alice', $result->getNativeKey());
        $this->assertSame('http', $result->getBackend());
    }

    public function testExtractIdentityReturnsNullWhenNoUser(): void
    {
        $driver = new Http();
        $request = $this->makeRequest([]);

        $this->assertNull($driver->extractIdentity($request));
    }

    public function testExtractIdentityReturnsNullWhenUserEmpty(): void
    {
        $driver = new Http();
        $request = $this->makeRequest(['PHP_AUTH_USER' => '']);

        $this->assertNull($driver->extractIdentity($request));
    }

    public function testExtractIdentityWithHtpasswdValidates(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'htpasswd_');
        $hash = crypt('correct', 'ab');
        file_put_contents($tmpFile, "alice:$hash\n");

        try {
            $driver = new Http(htpasswdFile: $tmpFile, encryption: 'crypt-des');
            $request = $this->makeRequest([
                'PHP_AUTH_USER' => 'alice',
                'PHP_AUTH_PW' => 'correct',
            ]);

            $result = $driver->extractIdentity($request);
            $this->assertInstanceOf(AuthResultSuccess::class, $result);

            $badRequest = $this->makeRequest([
                'PHP_AUTH_USER' => 'alice',
                'PHP_AUTH_PW' => 'wrong',
            ]);
            $this->assertNull($driver->extractIdentity($badRequest));
        } finally {
            unlink($tmpFile);
        }
    }

    public function testValidateSuccess(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'htpasswd_');
        $hash = crypt('secret', 'xy');
        file_put_contents($tmpFile, "bob:$hash\n");

        try {
            $driver = new Http(htpasswdFile: $tmpFile, encryption: 'crypt-des');

            $result = $driver->validate('bob', ['password' => 'secret']);
            $this->assertInstanceOf(AuthResultSuccess::class, $result);
        } finally {
            unlink($tmpFile);
        }
    }

    public function testValidateFailUnknownUser(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'htpasswd_');
        file_put_contents($tmpFile, "alice:hash\n");

        try {
            $driver = new Http(htpasswdFile: $tmpFile);

            $result = $driver->validate('nobody', ['password' => 'test']);
            $this->assertInstanceOf(AuthResultFail::class, $result);
            $this->assertSame('unknown_user', $result->get('reason'));
        } finally {
            unlink($tmpFile);
        }
    }

    public function testValidateFailEmptyPassword(): void
    {
        $driver = new Http();

        $result = $driver->validate('alice', ['password' => '']);
        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('empty_password', $result->get('reason'));
    }
}
