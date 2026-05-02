<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\CredentialProvider;
use Horde\Auth\PasswordManager;
use Horde\Auth\Sql;
use Horde\Auth\UserDirectory;
use Horde\Auth\UserEntry;
use Horde\Auth\UserLifecycleManager;
use Horde\Auth\Test\BaseTestCase;
use Horde\Db\Adapter as DbAdapter;
use PHPUnit\Framework\Attributes\CoversClass;
use RuntimeException;

#[CoversClass(Sql::class)]
class SqlDriverTest extends BaseTestCase
{
    private DbAdapter $db;

    protected function setUp(): void
    {
        $this->db = $this->createStub(DbAdapter::class);
        $this->db->method('quoteTableName')->willReturnCallback(fn(string $name) => '"' . $name . '"');
        $this->db->method('quoteColumnName')->willReturnCallback(fn(string $name) => '"' . $name . '"');
    }

    private function createDriver(string $encryption = 'md5-hex'): Sql
    {
        return new Sql(
            db: $this->db,
            table: 'horde_users',
            usernameField: 'user_uid',
            passwordField: 'user_pass',
            encryption: $encryption,
        );
    }

    public function testImplementsAllInterfaces(): void
    {
        $driver = $this->createDriver();

        $this->assertInstanceOf(CredentialProvider::class, $driver);
        $this->assertInstanceOf(UserDirectory::class, $driver);
        $this->assertInstanceOf(UserLifecycleManager::class, $driver);
        $this->assertInstanceOf(PasswordManager::class, $driver);
    }

    public function testValidateSuccess(): void
    {
        $this->db->method('selectOne')
            ->willReturn([
                'user_uid' => 'alice',
                'user_pass' => md5('secret'),
            ]);

        $driver = $this->createDriver();
        $result = $driver->validate('alice', ['password' => 'secret']);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('alice', $result->getNativeKey());
        $this->assertSame('sql', $result->getBackend());
    }

    public function testValidateFailBadPassword(): void
    {
        $this->db->method('selectOne')
            ->willReturn([
                'user_uid' => 'alice',
                'user_pass' => md5('secret'),
            ]);

        $driver = $this->createDriver();
        $result = $driver->validate('alice', ['password' => 'wrong']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('bad_password', $result->get('reason'));
    }

    public function testValidateFailUnknownUser(): void
    {
        $this->db->method('selectOne')
            ->willReturn(null);

        $driver = $this->createDriver();
        $result = $driver->validate('nobody', ['password' => 'test']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('unknown_user', $result->get('reason'));
    }

    public function testValidateFailEmptyPassword(): void
    {
        $driver = $this->createDriver();
        $result = $driver->validate('alice', ['password' => '']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('empty_password', $result->get('reason'));
    }

    public function testValidateReportsExpirationMetadata(): void
    {
        $this->db->method('selectOne')
            ->willReturn([
                'user_uid' => 'alice',
                'user_pass' => md5('secret'),
                'password_soft_expire' => 1717200000,
                'password_hard_expire' => 1719792000,
            ]);

        $driver = new Sql(
            db: $this->db,
            encryption: 'md5-hex',
            softExpirationField: 'password_soft_expire',
            hardExpirationField: 'password_hard_expire',
        );

        $result = $driver->validate('alice', ['password' => 'secret']);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame(1717200000, $result->get('soft_expiration'));
        $this->assertSame(1719792000, $result->get('hard_expiration'));
    }

    public function testExistsReturnsTrueWhenFound(): void
    {
        $this->db->method('selectValue')
            ->willReturn(1);

        $driver = $this->createDriver();
        $this->assertTrue($driver->exists('alice'));
    }

    public function testExistsReturnsFalseWhenNotFound(): void
    {
        $this->db->method('selectValue')
            ->willReturn(null);

        $driver = $this->createDriver();
        $this->assertFalse($driver->exists('nobody'));
    }

    public function testListReturnsUserEntries(): void
    {
        $this->db->method('selectAll')
            ->willReturn([
                ['user_uid' => 'alice', 'user_pass' => 'hash1'],
                ['user_uid' => 'bob', 'user_pass' => 'hash2'],
            ]);

        $driver = $this->createDriver();
        $entries = iterator_to_array($driver->list());

        $this->assertCount(2, $entries);
        $this->assertInstanceOf(UserEntry::class, $entries[0]);
        $this->assertSame('alice', $entries[0]->getUserId());
        $this->assertSame('sql', $entries[0]->getBackend());
        $this->assertSame('bob', $entries[1]->getUserId());
    }

    public function testListExcludesPasswordFromAttributes(): void
    {
        $this->db->method('selectAll')
            ->willReturn([
                ['user_uid' => 'alice', 'user_pass' => 'hash1', 'email' => 'alice@example.com'],
            ]);

        $driver = $this->createDriver();
        $entries = iterator_to_array($driver->list());

        $this->assertNull($entries[0]->get('user_pass'));
        $this->assertSame('alice@example.com', $entries[0]->get('email'));
    }

    public function testSearchFiltersUsers(): void
    {
        $this->db->method('selectAll')
            ->willReturn([
                ['user_uid' => 'alice', 'user_pass' => 'hash1'],
                ['user_uid' => 'alicia', 'user_pass' => 'hash2'],
            ]);

        $driver = $this->createDriver();
        $entries = iterator_to_array($driver->search('ali'));

        $this->assertCount(2, $entries);
        $this->assertSame('alice', $entries[0]->getUserId());
        $this->assertSame('alicia', $entries[1]->getUserId());
    }

    public function testAddUserInsertsRow(): void
    {
        $this->db->method('insert')
            ->willReturn(1);

        $driver = $this->createDriver();
        $entry = $driver->addUser('newuser', ['password' => 'pw123', 'email' => 'new@example.com']);

        $this->assertInstanceOf(UserEntry::class, $entry);
        $this->assertSame('newuser', $entry->getUserId());
        $this->assertSame('new@example.com', $entry->get('email'));
        $this->assertNull($entry->get('password'));
    }

    public function testRemoveUserDeletesRow(): void
    {
        $this->db->method('delete')
            ->willReturn(1);

        $driver = $this->createDriver();
        $driver->removeUser('alice');

        $this->assertTrue(true);
    }

    public function testRenameUserUpdatesRow(): void
    {
        $this->db->method('update')
            ->willReturn(1);

        $driver = $this->createDriver();
        $driver->renameUser('alice', 'alicia');

        $this->assertTrue(true);
    }

    public function testChangePasswordValidatesOldFirst(): void
    {
        $this->db->method('selectOne')
            ->willReturn([
                'user_uid' => 'alice',
                'user_pass' => md5('oldpw'),
            ]);

        $this->db->method('update')
            ->willReturn(1);

        $driver = $this->createDriver();
        $driver->changePassword('alice', 'oldpw', 'newpw');

        $this->assertTrue(true);
    }

    public function testChangePasswordThrowsOnWrongOld(): void
    {
        $this->db->method('selectOne')
            ->willReturn([
                'user_uid' => 'alice',
                'user_pass' => md5('correct'),
            ]);

        $driver = $this->createDriver();

        $this->expectException(RuntimeException::class);
        $driver->changePassword('alice', 'wrong', 'newpw');
    }

    public function testResetPasswordReturnsNewPassword(): void
    {
        $this->db->method('selectValue')
            ->willReturn(1);

        $this->db->method('update')
            ->willReturn(1);

        $driver = $this->createDriver();
        $newPw = $driver->resetPassword('alice');

        $this->assertNotEmpty($newPw);
        $this->assertGreaterThanOrEqual(4, strlen($newPw));
    }

    public function testResetPasswordThrowsForUnknownUser(): void
    {
        $this->db->method('selectValue')
            ->willReturn(null);

        $driver = $this->createDriver();

        $this->expectException(RuntimeException::class);
        $driver->resetPassword('nobody');
    }

    public function testCustomBackendName(): void
    {
        $this->db->method('selectOne')
            ->willReturn([
                'user_uid' => 'alice',
                'user_pass' => md5('secret'),
            ]);

        $driver = new Sql(
            db: $this->db,
            encryption: 'md5-hex',
            backend: 'sql:corporate',
        );

        $result = $driver->validate('alice', ['password' => 'secret']);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('sql:corporate', $result->getBackend());
    }
}
