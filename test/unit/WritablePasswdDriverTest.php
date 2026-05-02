<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultSuccess;
use Horde\Auth\PasswordManager;
use Horde\Auth\UserEntry;
use Horde\Auth\UserLifecycleManager;
use Horde\Auth\WritablePasswd;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use RuntimeException;

#[CoversClass(WritablePasswd::class)]
class WritablePasswdDriverTest extends BaseTestCase
{
    private string $tempFile;

    protected function setUp(): void
    {
        $this->tempFile = tempnam(sys_get_temp_dir(), 'horde_auth_test_');
        copy(__DIR__ . '/../fixtures/test.passwd', $this->tempFile);
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempFile)) {
            unlink($this->tempFile);
        }
        $tmp = $this->tempFile . '.tmp.' . getmypid();
        if (file_exists($tmp)) {
            unlink($tmp);
        }
    }

    private function createDriver(): WritablePasswd
    {
        return new WritablePasswd(
            filename: $this->tempFile,
            encryption: 'crypt-des',
        );
    }

    public function testImplementsWriteInterfaces(): void
    {
        $driver = $this->createDriver();

        $this->assertInstanceOf(UserLifecycleManager::class, $driver);
        $this->assertInstanceOf(PasswordManager::class, $driver);
    }

    public function testAddUser(): void
    {
        $driver = $this->createDriver();

        $entry = $driver->addUser('newuser', [
            'password' => 'secret123',
            'uid' => '1001',
            'gid' => '1001',
            'info' => 'New User',
            'home' => '/home/newuser',
            'shell' => '/bin/bash',
        ]);

        $this->assertInstanceOf(UserEntry::class, $entry);
        $this->assertSame('newuser', $entry->getUserId());
        $this->assertSame('1001', $entry->get('uid'));
        $this->assertSame('/home/newuser', $entry->get('home'));

        $this->assertTrue($driver->exists('newuser'));

        $result = $driver->validate('newuser', ['password' => 'secret123']);
        $this->assertInstanceOf(AuthResultSuccess::class, $result);
    }

    public function testAddUserPersistsToFile(): void
    {
        $driver = $this->createDriver();
        $driver->addUser('persisted', ['password' => 'pw']);

        $driver2 = new WritablePasswd(
            filename: $this->tempFile,
            encryption: 'crypt-des',
        );
        $this->assertTrue($driver2->exists('persisted'));
    }

    public function testAddDuplicateUserThrows(): void
    {
        $driver = $this->createDriver();

        $this->expectException(RuntimeException::class);
        $driver->addUser('user', ['password' => 'x']);
    }

    public function testRemoveUser(): void
    {
        $driver = $this->createDriver();

        $this->assertTrue($driver->exists('user'));
        $driver->removeUser('user');
        $this->assertFalse($driver->exists('user'));
    }

    public function testRemoveUserPersistsToFile(): void
    {
        $driver = $this->createDriver();
        $driver->removeUser('user');

        $driver2 = new WritablePasswd(
            filename: $this->tempFile,
            encryption: 'crypt-des',
        );
        $this->assertFalse($driver2->exists('user'));
    }

    public function testRemoveNonexistentUserThrows(): void
    {
        $driver = $this->createDriver();

        $this->expectException(RuntimeException::class);
        $driver->removeUser('nobody');
    }

    public function testRenameUser(): void
    {
        $driver = $this->createDriver();

        $driver->renameUser('user', 'renamed');

        $this->assertFalse($driver->exists('user'));
        $this->assertTrue($driver->exists('renamed'));
    }

    public function testRenameUserPreservesPassword(): void
    {
        $driver = $this->createDriver();

        $driver->renameUser('user', 'renamed');

        $result = $driver->validate('renamed', ['password' => 'password']);
        $this->assertInstanceOf(AuthResultSuccess::class, $result);
    }

    public function testRenameToExistingThrows(): void
    {
        $driver = $this->createDriver();
        $driver->addUser('other', ['password' => 'x']);

        $this->expectException(RuntimeException::class);
        $driver->renameUser('user', 'other');
    }

    public function testUpdateUserAttributes(): void
    {
        $driver = $this->createDriver();
        $driver->addUser('alice', [
            'password' => 'pw',
            'home' => '/home/alice',
            'shell' => '/bin/sh',
        ]);

        $driver->updateUser('alice', ['shell' => '/bin/zsh', 'home' => '/opt/alice']);

        $driver2 = new WritablePasswd(
            filename: $this->tempFile,
            encryption: 'crypt-des',
        );
        $entries = iterator_to_array($driver2->search('alice'));
        $this->assertSame('/bin/zsh', $entries[0]->get('shell'));
        $this->assertSame('/opt/alice', $entries[0]->get('home'));
    }

    public function testChangePassword(): void
    {
        $driver = $this->createDriver();

        $driver->changePassword('user', 'password', 'newpass');

        $result = $driver->validate('user', ['password' => 'newpass']);
        $this->assertInstanceOf(AuthResultSuccess::class, $result);
    }

    public function testChangePasswordWrongOldThrows(): void
    {
        $driver = $this->createDriver();

        $this->expectException(RuntimeException::class);
        $driver->changePassword('user', 'wrong', 'newpass');
    }

    public function testResetPassword(): void
    {
        $driver = $this->createDriver();

        $newPw = $driver->resetPassword('user');

        $this->assertNotEmpty($newPw);
        $result = $driver->validate('user', ['password' => $newPw]);
        $this->assertInstanceOf(AuthResultSuccess::class, $result);
    }

    public function testResetPasswordNonexistentUserThrows(): void
    {
        $driver = $this->createDriver();

        $this->expectException(RuntimeException::class);
        $driver->resetPassword('nobody');
    }

    public function testFileFormatPreservesFields(): void
    {
        $driver = $this->createDriver();
        $driver->addUser('full', [
            'password' => 'test',
            'uid' => '5000',
            'gid' => '5000',
            'info' => 'Full User',
            'home' => '/home/full',
            'shell' => '/bin/bash',
        ]);

        $contents = file_get_contents($this->tempFile);
        $lines = explode("\n", trim($contents));
        $lastLine = end($lines);
        $parts = explode(':', $lastLine);

        $this->assertSame('full', $parts[0]);
        $this->assertNotEmpty($parts[1]);
        $this->assertSame('5000', $parts[2]);
        $this->assertSame('5000', $parts[3]);
        $this->assertSame('Full User', $parts[4]);
        $this->assertSame('/home/full', $parts[5]);
        $this->assertSame('/bin/bash', $parts[6]);
    }
}
