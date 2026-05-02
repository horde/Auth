<?php

declare(strict_types=1);

namespace Horde\Auth\Test;

use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\PasswordManager;
use Horde\Auth\UserEntry;
use Horde\Auth\UserLifecycleManager;
use Horde\Auth\WritableLdap;
use Horde_Ldap;
use Horde_Ldap_Entry;
use Horde_Ldap_Exception;
use Horde_Ldap_Search;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;

#[CoversClass(WritableLdap::class)]
class WritableLdapTest extends TestCase
{
    private Horde_Ldap $ldapMock;

    protected function setUp(): void
    {
        $this->ldapMock = $this->createMock(Horde_Ldap::class);
    }

    private function makeDriver(array $overrides = []): WritableLdap
    {
        return new WritableLdap(
            ldap: $overrides['ldap'] ?? $this->ldapMock,
            baseDn: $overrides['baseDn'] ?? 'dc=example,dc=com',
            uidAttribute: $overrides['uidAttribute'] ?? 'uid',
            objectClass: $overrides['objectClass'] ?? ['posixAccount'],
            encryption: $overrides['encryption'] ?? 'ssha',
            activeDirectory: false,
            filter: $overrides['filter'] ?? null,
            backend: $overrides['backend'] ?? 'ldap',
        );
    }

    public function testImplementsCorrectInterfaces(): void
    {
        $driver = $this->makeDriver();
        $this->assertInstanceOf(UserLifecycleManager::class, $driver);
        $this->assertInstanceOf(PasswordManager::class, $driver);
    }

    public function testConstructorRejectsActiveDirectory(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Active Directory');

        new WritableLdap(
            ldap: $this->ldapMock,
            baseDn: 'dc=example,dc=com',
            activeDirectory: true,
        );
    }

    public function testAddUserCallsLdapAdd(): void
    {
        $this->ldapMock->expects($this->once())->method('add');

        $driver = $this->makeDriver();
        $entry = $driver->addUser('alice', ['password' => 'secret', 'cn' => 'Alice']);

        $this->assertInstanceOf(UserEntry::class, $entry);
        $this->assertSame('alice', $entry->getUserId());
        $this->assertSame('ldap', $entry->getBackend());
        $this->assertSame('Alice', $entry->get('cn'));
        $this->assertNull($entry->get('password'));
    }

    public function testRemoveUserCallsLdapDelete(): void
    {
        $entry = $this->createMock(Horde_Ldap_Entry::class);
        $entry->method('dn')->willReturn('uid=bob,dc=example,dc=com');

        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('count')->willReturn(1);
        $search->method('current')->willReturn($entry);

        $this->ldapMock->method('search')->willReturn($search);
        $this->ldapMock->expects($this->once())
            ->method('delete')
            ->with('uid=bob,dc=example,dc=com');

        $driver = $this->makeDriver();
        $driver->removeUser('bob');
    }

    public function testRemoveUserThrowsWhenNotFound(): void
    {
        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('count')->willReturn(0);

        $this->ldapMock->method('search')->willReturn($search);

        $driver = $this->makeDriver();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('not found');
        $driver->removeUser('ghost');
    }

    public function testRenameUserCallsLdapMove(): void
    {
        $entry = $this->createMock(Horde_Ldap_Entry::class);
        $entry->method('dn')->willReturn('uid=oldname,dc=example,dc=com');

        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('count')->willReturn(1);
        $search->method('current')->willReturn($entry);

        $this->ldapMock->method('search')->willReturn($search);
        $this->ldapMock->expects($this->once())
            ->method('move')
            ->with('uid=oldname,dc=example,dc=com', 'uid=newname,dc=example,dc=com');

        $driver = $this->makeDriver();
        $driver->renameUser('oldname', 'newname');
    }

    public function testUpdateUserModifiesAttributes(): void
    {
        $ldapEntry = $this->createMock(Horde_Ldap_Entry::class);
        $ldapEntry->method('dn')->willReturn('uid=alice,dc=example,dc=com');
        $ldapEntry->expects($this->atLeastOnce())->method('replace');
        $ldapEntry->expects($this->once())->method('update');

        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('count')->willReturn(1);
        $search->method('current')->willReturn($ldapEntry);

        $this->ldapMock->method('search')->willReturn($search);
        $this->ldapMock->method('getEntry')->willReturn($ldapEntry);

        $driver = $this->makeDriver();
        $driver->updateUser('alice', ['cn' => 'Alice Updated', 'mail' => 'new@test.com']);
    }

    public function testChangePasswordFailsWithWrongOldPassword(): void
    {
        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('count')->willReturn(0);

        $this->ldapMock->method('search')->willReturn($search);

        $driver = $this->makeDriver();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Old password is incorrect');
        $driver->changePassword('alice', 'wrong', 'newpass');
    }

    public function testResetPasswordReturnsNewPassword(): void
    {
        $entry = $this->createMock(Horde_Ldap_Entry::class);
        $entry->method('dn')->willReturn('uid=alice,dc=example,dc=com');
        $entry->method('replace');
        $entry->method('update');

        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('count')->willReturn(1);
        $search->method('current')->willReturn($entry);

        $this->ldapMock->method('search')->willReturn($search);
        $this->ldapMock->method('getEntry')->willReturn($entry);

        $driver = $this->makeDriver();
        $password = $driver->resetPassword('alice');

        $this->assertNotEmpty($password);
        $this->assertIsString($password);
    }

    public function testResetPasswordThrowsWhenNotFound(): void
    {
        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('count')->willReturn(0);

        $this->ldapMock->method('search')->willReturn($search);

        $driver = $this->makeDriver();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('not found');
        $driver->resetPassword('ghost');
    }
}
