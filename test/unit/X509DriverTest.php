<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultSuccess;
use Horde\Auth\TransparentProvider;
use Horde\Auth\X509;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use Psr\Http\Message\ServerRequestInterface;

#[CoversClass(X509::class)]
class X509DriverTest extends BaseTestCase
{
    private function makeRequest(array $serverParams): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn($serverParams);
        return $request;
    }

    private function getSelfSignedCert(): string
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        $csr = openssl_csr_new(
            ['commonName' => 'testuser', 'organizationName' => 'Test Org'],
            $key,
        );
        openssl_csr_sign($csr, null, $key, 365);
        openssl_x509_export(openssl_csr_sign($csr, null, $key, 365), $certPem);
        return $certPem;
    }

    public function testImplementsTransparentProvider(): void
    {
        $driver = new X509();

        $this->assertInstanceOf(TransparentProvider::class, $driver);
    }

    public function testReturnsNullWhenUsernameFieldMissing(): void
    {
        $driver = new X509();
        $request = $this->makeRequest([
            'SSL_CLIENT_CERT' => 'some-cert',
        ]);

        $this->assertNull($driver->extractIdentity($request));
    }

    public function testReturnsNullWhenCertFieldMissing(): void
    {
        $driver = new X509();
        $request = $this->makeRequest([
            'SSL_CLIENT_S_DN_CN' => 'testuser',
        ]);

        $this->assertNull($driver->extractIdentity($request));
    }

    public function testReturnsNullWhenBothFieldsEmpty(): void
    {
        $driver = new X509();
        $request = $this->makeRequest([]);

        $this->assertNull($driver->extractIdentity($request));
    }

    #[RequiresPhpExtension('openssl')]
    public function testReturnsNullForInvalidCert(): void
    {
        $driver = new X509();
        $request = $this->makeRequest([
            'SSL_CLIENT_S_DN_CN' => 'testuser',
            'SSL_CLIENT_CERT' => 'not-a-valid-pem-cert',
        ]);

        $this->assertNull($driver->extractIdentity($request));
    }

    #[RequiresPhpExtension('openssl')]
    public function testExtractsIdentityFromValidCert(): void
    {
        $certPem = $this->getSelfSignedCert();
        $driver = new X509();
        $request = $this->makeRequest([
            'SSL_CLIENT_S_DN_CN' => 'testuser',
            'SSL_CLIENT_CERT' => $certPem,
        ]);

        $result = $driver->extractIdentity($request);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('testuser', $result->getNativeKey());
        $this->assertSame('x509', $result->getBackend());
        $this->assertNotEmpty($result->get('certificate_hash'));
    }

    #[RequiresPhpExtension('openssl')]
    public function testMetadataIncludesValidity(): void
    {
        $certPem = $this->getSelfSignedCert();
        $driver = new X509();
        $request = $this->makeRequest([
            'SSL_CLIENT_S_DN_CN' => 'testuser',
            'SSL_CLIENT_CERT' => $certPem,
        ]);

        $result = $driver->extractIdentity($request);

        $this->assertNotNull($result->get('valid_from'));
        $this->assertNotNull($result->get('valid_to'));
        $this->assertIsArray($result->get('issuer'));
    }

    #[RequiresPhpExtension('openssl')]
    public function testFilterRejectsNonMatchingCert(): void
    {
        $certPem = $this->getSelfSignedCert();
        $driver = new X509(filter: ['subject:O' => 'Wrong Org']);
        $request = $this->makeRequest([
            'SSL_CLIENT_S_DN_CN' => 'testuser',
            'SSL_CLIENT_CERT' => $certPem,
        ]);

        $this->assertNull($driver->extractIdentity($request));
    }

    #[RequiresPhpExtension('openssl')]
    public function testFilterAcceptsMatchingCert(): void
    {
        $certPem = $this->getSelfSignedCert();
        $driver = new X509(filter: ['subject:O' => 'Test Org']);
        $request = $this->makeRequest([
            'SSL_CLIENT_S_DN_CN' => 'testuser',
            'SSL_CLIENT_CERT' => $certPem,
        ]);

        $result = $driver->extractIdentity($request);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
    }

    #[RequiresPhpExtension('openssl')]
    public function testCustomFieldNames(): void
    {
        $certPem = $this->getSelfSignedCert();
        $driver = new X509(
            usernameField: 'SSL_CLIENT_S_DN_EMAILADDRESS',
            certificateField: 'MY_CERT',
        );
        $request = $this->makeRequest([
            'SSL_CLIENT_S_DN_EMAILADDRESS' => 'user@example.com',
            'MY_CERT' => $certPem,
        ]);

        $result = $driver->extractIdentity($request);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('user@example.com', $result->getNativeKey());
    }
}
