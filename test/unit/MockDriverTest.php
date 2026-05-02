<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Mock;
use Horde\Auth\CredentialProvider;
use Horde\Auth\PasswordManager;
use Horde\Auth\TransparentProvider;
use Horde\Auth\UserDirectory;
use Horde\Auth\UserEntry;
use Horde\Auth\UserLifecycleManager;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

#[CoversClass(Mock::class)]
class MockDriverTest extends BaseTestCase
{
    private function createDriver(array $users = [], ?string $autoLogin = null): Mock
    {
        return new Mock($users, $autoLogin);
    }

    public function testImplementsAllInterfaces(): void
    {
        $driver = $this->createDriver();

        $this->assertInstanceOf(CredentialProvider::class, $driver);
        $this->assertInstanceOf(TransparentProvider::class, $driver);
        $this->assertInstanceOf(UserDirectory::class, $driver);
        $this->assertInstanceOf(UserLifecycleManager::class, $driver);
        $this->assertInstanceOf(PasswordManager::class, $driver);
    }

    public function testValidateSuccess(): void
    {
        $driver = $this->createDriver(['alice' => ['password' => 'secret', 'attributes' => ['role' => 'admin']]]);

        $result = $driver->validate('alice', ['password' => 'secret']);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('alice', $result->getNativeKey());
        $this->assertSame('admin', $result->get('role'));
    }

    public function testValidateFailBadPassword(): void
    {
        $driver = $this->createDriver(['alice' => ['password' => 'secret']]);

        $result = $driver->validate('alice', ['password' => 'wrong']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('bad_password', $result->get('reason'));
    }

    public function testValidateFailUnknownUser(): void
    {
        $driver = $this->createDriver();

        $result = $driver->validate('nobody', ['password' => 'test']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('unknown_user', $result->get('reason'));
    }

    public function testExtractIdentityWithAutoLogin(): void
    {
        $driver = $this->createDriver(['bob' => ['password' => 'x']], autoLogin: 'bob');
        $request = $this->createStub(ServerRequestInterface::class);

        $result = $driver->extractIdentity($request);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('bob', $result->getNativeKey());
    }

    public function testExtractIdentityWithoutAutoLogin(): void
    {
        $driver = $this->createDriver(['bob' => ['password' => 'x']]);
        $request = $this->createStub(ServerRequestInterface::class);

        $this->assertNull($driver->extractIdentity($request));
    }

    public function testUserDirectoryExists(): void
    {
        $driver = $this->createDriver(['alice' => ['password' => 'x']]);

        $this->assertTrue($driver->exists('alice'));
        $this->assertFalse($driver->exists('bob'));
    }

    public function testUserDirectoryList(): void
    {
        $driver = $this->createDriver([
            'alice' => ['password' => 'x'],
            'bob' => ['password' => 'y'],
        ]);

        $entries = iterator_to_array($driver->list());

        $this->assertCount(2, $entries);
        $this->assertInstanceOf(UserEntry::class, $entries[0]);
    }

    public function testUserDirectorySearch(): void
    {
        $driver = $this->createDriver([
            'alice' => ['password' => 'x'],
            'bob' => ['password' => 'y'],
            'alicia' => ['password' => 'z'],
        ]);

        $entries = iterator_to_array($driver->search('ali'));

        $this->assertCount(2, $entries);
    }

    public function testAddUser(): void
    {
        $driver = $this->createDriver();

        $entry = $driver->addUser('newuser', ['password' => 'pw', 'email' => 'new@example.com']);

        $this->assertInstanceOf(UserEntry::class, $entry);
        $this->assertSame('newuser', $entry->getUserId());
        $this->assertTrue($driver->exists('newuser'));
        $this->assertSame('new@example.com', $entry->get('email'));
    }

    public function testAddUserDuplicateThrows(): void
    {
        $driver = $this->createDriver(['alice' => ['password' => 'x']]);

        $this->expectException(RuntimeException::class);
        $driver->addUser('alice', ['password' => 'y']);
    }

    public function testRemoveUser(): void
    {
        $driver = $this->createDriver(['alice' => ['password' => 'x']]);

        $driver->removeUser('alice');

        $this->assertFalse($driver->exists('alice'));
    }

    public function testRenameUser(): void
    {
        $driver = $this->createDriver(['alice' => ['password' => 'x']]);

        $driver->renameUser('alice', 'alicia');

        $this->assertFalse($driver->exists('alice'));
        $this->assertTrue($driver->exists('alicia'));
    }

    public function testChangePassword(): void
    {
        $driver = $this->createDriver(['alice' => ['password' => 'old']]);

        $driver->changePassword('alice', 'old', 'new');

        $result = $driver->validate('alice', ['password' => 'new']);
        $this->assertInstanceOf(AuthResultSuccess::class, $result);
    }

    public function testChangePasswordWrongOldThrows(): void
    {
        $driver = $this->createDriver(['alice' => ['password' => 'correct']]);

        $this->expectException(RuntimeException::class);
        $driver->changePassword('alice', 'wrong', 'new');
    }

    public function testResetPassword(): void
    {
        $driver = $this->createDriver(['alice' => ['password' => 'old']]);

        $newPw = $driver->resetPassword('alice');

        $this->assertNotEmpty($newPw);
        $result = $driver->validate('alice', ['password' => $newPw]);
        $this->assertInstanceOf(AuthResultSuccess::class, $result);
    }
}
