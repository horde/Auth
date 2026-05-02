<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\CredentialProvider;
use Horde\Auth\Passwd;
use Horde\Auth\UserDirectory;
use Horde\Auth\UserEntry;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use RuntimeException;

#[CoversClass(Passwd::class)]
class PasswdDriverTest extends BaseTestCase
{
    private function createDriver(): Passwd
    {
        return new Passwd(
            filename: __DIR__ . '/../fixtures/test.passwd',
            encryption: 'crypt-des',
        );
    }

    public function testImplementsInterfaces(): void
    {
        $driver = $this->createDriver();

        $this->assertInstanceOf(CredentialProvider::class, $driver);
        $this->assertInstanceOf(UserDirectory::class, $driver);
    }

    public function testValidateSuccess(): void
    {
        $driver = $this->createDriver();

        $result = $driver->validate('user', ['password' => 'password']);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('user', $result->getNativeKey());
        $this->assertSame('passwd', $result->getBackend());
    }

    public function testValidateFailBadPassword(): void
    {
        $driver = $this->createDriver();

        $result = $driver->validate('user', ['password' => 'wrong']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('bad_password', $result->get('reason'));
    }

    public function testValidateFailUnknownUser(): void
    {
        $driver = $this->createDriver();

        $result = $driver->validate('nonexistent', ['password' => 'test']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('unknown_user', $result->get('reason'));
    }

    public function testValidateFailEmptyPassword(): void
    {
        $driver = $this->createDriver();

        $result = $driver->validate('user', ['password' => '']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('empty_password', $result->get('reason'));
    }

    public function testExists(): void
    {
        $driver = $this->createDriver();

        $this->assertTrue($driver->exists('user'));
        $this->assertFalse($driver->exists('nonexistent'));
    }

    public function testList(): void
    {
        $driver = $this->createDriver();

        $entries = iterator_to_array($driver->list());

        $this->assertCount(1, $entries);
        $this->assertInstanceOf(UserEntry::class, $entries[0]);
        $this->assertSame('user', $entries[0]->getUserId());
        $this->assertSame('passwd', $entries[0]->getBackend());
    }

    public function testSearch(): void
    {
        $driver = $this->createDriver();

        $entries = iterator_to_array($driver->search('us'));
        $this->assertCount(1, $entries);
        $this->assertSame('user', $entries[0]->getUserId());

        $entries = iterator_to_array($driver->search('zzz'));
        $this->assertCount(0, $entries);
    }

    public function testExcludesSystemUsers(): void
    {
        $driver = $this->createDriver();

        $this->assertFalse($driver->exists('root'));
        $this->assertFalse($driver->exists('nobody'));
    }

    public function testUnreadableFileThrows(): void
    {
        $driver = new Passwd(
            filename: '/nonexistent/path/passwd',
            encryption: 'crypt-des',
        );

        $this->expectException(RuntimeException::class);
        $driver->exists('user');
    }

    public function testSuccessMetadataContainsPasswdFields(): void
    {
        $driver = $this->createDriver();

        $result = $driver->validate('user', ['password' => 'password']);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertArrayHasKey('uid', $result->getMetadata());
        $this->assertArrayHasKey('gid', $result->getMetadata());
        $this->assertArrayHasKey('home', $result->getMetadata());
        $this->assertArrayHasKey('shell', $result->getMetadata());
    }
}
