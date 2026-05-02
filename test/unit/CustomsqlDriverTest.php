<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\CredentialProvider;
use Horde\Auth\Customsql;
use Horde\Auth\PasswordManager;
use Horde\Auth\UserDirectory;
use Horde\Auth\UserEntry;
use Horde\Auth\UserLifecycleManager;
use Horde\Auth\Test\BaseTestCase;
use Horde\Db\Adapter as DbAdapter;
use PHPUnit\Framework\Attributes\CoversClass;
use RuntimeException;

#[CoversClass(Customsql::class)]
class CustomsqlDriverTest extends BaseTestCase
{
    private DbAdapter $db;

    protected function setUp(): void
    {
        $this->db = $this->createStub(DbAdapter::class);
        $this->db->method('quoteString')->willReturnCallback(fn(string $s) => "'" . addslashes($s) . "'");
        $this->db->method('quoteTableName')->willReturnCallback(fn(string $n) => '"' . $n . '"');
        $this->db->method('quoteColumnName')->willReturnCallback(fn(string $n) => '"' . $n . '"');
    }

    public function testImplementsAllInterfaces(): void
    {
        $driver = new Customsql(
            db: $this->db,
            queryAuth: "SELECT 1 FROM users WHERE login = \\L AND pass = \\P",
        );

        $this->assertInstanceOf(CredentialProvider::class, $driver);
        $this->assertInstanceOf(UserDirectory::class, $driver);
        $this->assertInstanceOf(UserLifecycleManager::class, $driver);
        $this->assertInstanceOf(PasswordManager::class, $driver);
    }

    public function testValidateSuccess(): void
    {
        $this->db->method('selectValue')->willReturn(1);

        $driver = new Customsql(
            db: $this->db,
            queryAuth: "SELECT 1 FROM users WHERE login = \\L AND pass = \\P",
            encryption: 'plain',
        );

        $result = $driver->validate('alice', ['password' => 'secret']);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('alice', $result->getNativeKey());
    }

    public function testValidateFailure(): void
    {
        $this->db->method('selectValue')->willReturn(null);

        $driver = new Customsql(
            db: $this->db,
            queryAuth: "SELECT 1 FROM users WHERE login = \\L AND pass = \\P",
            encryption: 'plain',
        );

        $result = $driver->validate('alice', ['password' => 'wrong']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('bad_credentials', $result->get('reason'));
    }

    public function testValidateEmptyPassword(): void
    {
        $driver = new Customsql(
            db: $this->db,
            queryAuth: "SELECT 1",
        );

        $result = $driver->validate('alice', ['password' => '']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('empty_password', $result->get('reason'));
    }

    public function testListUsers(): void
    {
        $this->db->method('selectValues')->willReturn(['alice', 'bob']);

        $driver = new Customsql(
            db: $this->db,
            queryAuth: "SELECT 1",
            queryList: "SELECT login FROM users",
        );

        $entries = iterator_to_array($driver->list());

        $this->assertCount(2, $entries);
        $this->assertInstanceOf(UserEntry::class, $entries[0]);
        $this->assertSame('alice', $entries[0]->getUserId());
    }

    public function testListThrowsWhenNotConfigured(): void
    {
        $driver = new Customsql(
            db: $this->db,
            queryAuth: "SELECT 1",
        );

        $this->expectException(RuntimeException::class);
        iterator_to_array($driver->list());
    }

    public function testExistsReturnsTrue(): void
    {
        $this->db->method('selectValue')->willReturn(1);

        $driver = new Customsql(
            db: $this->db,
            queryAuth: "SELECT 1",
            queryExists: "SELECT 1 FROM users WHERE login = \\L",
        );

        $this->assertTrue($driver->exists('alice'));
    }

    public function testExistsThrowsWhenNotConfigured(): void
    {
        $driver = new Customsql(
            db: $this->db,
            queryAuth: "SELECT 1",
        );

        $this->expectException(RuntimeException::class);
        $driver->exists('alice');
    }

    public function testAddUser(): void
    {
        $this->db->method('insert')->willReturn(1);

        $driver = new Customsql(
            db: $this->db,
            queryAuth: "SELECT 1",
            queryAdd: "INSERT INTO users (login, pass) VALUES (\\L, \\P)",
            encryption: 'plain',
        );

        $entry = $driver->addUser('newuser', ['password' => 'pw']);

        $this->assertInstanceOf(UserEntry::class, $entry);
        $this->assertSame('newuser', $entry->getUserId());
    }

    public function testRemoveUser(): void
    {
        $this->db->method('delete')->willReturn(1);

        $driver = new Customsql(
            db: $this->db,
            queryAuth: "SELECT 1",
            queryRemove: "DELETE FROM users WHERE login = \\L",
        );

        $driver->removeUser('alice');
        $this->assertTrue(true);
    }

    public function testResetPassword(): void
    {
        $this->db->method('update')->willReturn(1);

        $driver = new Customsql(
            db: $this->db,
            queryAuth: "SELECT 1",
            queryResetpassword: "UPDATE users SET pass = \\P WHERE login = \\L",
            encryption: 'plain',
        );

        $newPw = $driver->resetPassword('alice');
        $this->assertNotEmpty($newPw);
    }

    public function testResetPasswordThrowsWhenNotConfigured(): void
    {
        $driver = new Customsql(
            db: $this->db,
            queryAuth: "SELECT 1",
        );

        $this->expectException(RuntimeException::class);
        $driver->resetPassword('alice');
    }
}
