<?php

declare(strict_types=1);

namespace Horde\Auth\Test;

use DateTimeImmutable;
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\CredentialProvider;
use Horde\Auth\Ldap;
use Horde\Auth\UserDirectory;
use Horde\Auth\UserEntry;
use Horde_Ldap;
use Horde_Ldap_Entry;
use Horde_Ldap_Exception;
use Horde_Ldap_Filter;
use Horde_Ldap_Search;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use ArrayIterator;

#[CoversClass(Ldap::class)]
class NewLdapTest extends TestCase
{
    private Horde_Ldap $ldapMock;

    protected function setUp(): void
    {
        $this->ldapMock = $this->createMock(Horde_Ldap::class);
    }

    private function makeDriver(array $overrides = []): Ldap
    {
        return new Ldap(
            ldap: $overrides['ldap'] ?? $this->ldapMock,
            baseDn: $overrides['baseDn'] ?? 'dc=example,dc=com',
            uidAttribute: $overrides['uidAttribute'] ?? 'uid',
            objectClass: $overrides['objectClass'] ?? ['posixAccount'],
            activeDirectory: $overrides['activeDirectory'] ?? false,
            filter: $overrides['filter'] ?? null,
            backend: $overrides['backend'] ?? 'ldap',
        );
    }

    public function testImplementsCorrectInterfaces(): void
    {
        $driver = $this->makeDriver();
        $this->assertInstanceOf(CredentialProvider::class, $driver);
        $this->assertInstanceOf(UserDirectory::class, $driver);
    }

    public function testValidateReturnsFailOnEmptyPassword(): void
    {
        $driver = $this->makeDriver();
        $result = $driver->validate('alice', ['password' => '']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('empty_password', $result->get('reason'));
    }

    public function testValidateReturnsFailWhenUserNotFound(): void
    {
        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('count')->willReturn(0);

        $this->ldapMock->method('search')->willReturn($search);

        $driver = $this->makeDriver();
        $result = $driver->validate('nobody', ['password' => 'secret']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('unknown_user', $result->get('reason'));
    }

    public function testValidateReturnsFailOnBadCredentials(): void
    {
        $entry = $this->createMock(Horde_Ldap_Entry::class);
        $entry->method('dn')->willReturn('uid=alice,dc=example,dc=com');

        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('count')->willReturn(1);
        $search->method('current')->willReturn($entry);

        $this->ldapMock->method('search')->willReturn($search);

        $bindCallCount = 0;
        $this->ldapMock->method('bind')->willReturnCallback(
            function (?string $dn = null, ?string $password = null) use (&$bindCallCount): bool {
                $bindCallCount++;
                if ($dn !== null && $password !== null) {
                    throw new Horde_Ldap_Exception('Invalid credentials');
                }
                return true;
            }
        );

        $driver = $this->makeDriver();
        $result = $driver->validate('alice', ['password' => 'wrong']);

        $this->assertInstanceOf(AuthResultFail::class, $result);
        $this->assertSame('bad_credentials', $result->get('reason'));
    }

    public function testValidateReturnsSuccessWithMetadata(): void
    {
        $entry = $this->createMock(Horde_Ldap_Entry::class);
        $entry->method('dn')->willReturn('uid=alice,dc=example,dc=com');
        $entry->method('getValues')->willReturn([
            'uid' => ['alice'],
            'mail' => ['alice@example.com'],
            'shadowLastChange' => '19000',
            'shadowMax' => '90',
        ]);

        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('count')->willReturn(1);
        $search->method('current')->willReturn($entry);

        $this->ldapMock->method('search')->willReturn($search);
        $this->ldapMock->method('bind')->willReturn(true);
        $this->ldapMock->method('getEntry')->willReturn($entry);

        $driver = $this->makeDriver();
        $result = $driver->validate('alice', ['password' => 'correct']);

        $this->assertInstanceOf(AuthResultSuccess::class, $result);
        $this->assertSame('uid=alice,dc=example,dc=com', $result->getNativeKey());
        $this->assertSame('alice@example.com', $result->get('mail'));
        $this->assertSame('19000', $result->get('shadowLastChange'));
        $this->assertSame('90', $result->get('shadowMax'));
    }

    public function testExistsReturnsTrueWhenFound(): void
    {
        $entry = $this->createMock(Horde_Ldap_Entry::class);
        $entry->method('dn')->willReturn('uid=alice,dc=example,dc=com');

        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('count')->willReturn(1);
        $search->method('current')->willReturn($entry);

        $this->ldapMock->method('search')->willReturn($search);

        $driver = $this->makeDriver();
        $this->assertTrue($driver->exists('alice'));
    }

    public function testExistsReturnsFalseWhenNotFound(): void
    {
        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('count')->willReturn(0);

        $this->ldapMock->method('search')->willReturn($search);

        $driver = $this->makeDriver();
        $this->assertFalse($driver->exists('nobody'));
    }

    public function testListYieldsUserEntries(): void
    {
        $entry1 = $this->createMock(Horde_Ldap_Entry::class);
        $entry1->method('getValues')->willReturn(['uid' => ['alice'], 'mail' => ['alice@test.com']]);

        $entry2 = $this->createMock(Horde_Ldap_Entry::class);
        $entry2->method('getValues')->willReturn(['uid' => ['bob'], 'cn' => ['Bob Smith']]);

        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('getIterator')->willReturn(new ArrayIterator([$entry1, $entry2]));

        $this->ldapMock->method('search')->willReturn($search);

        $driver = $this->makeDriver();
        $entries = iterator_to_array($driver->list());

        $this->assertCount(2, $entries);
        $this->assertSame('alice', $entries[0]->getUserId());
        $this->assertSame('bob', $entries[1]->getUserId());
        $this->assertSame('alice@test.com', $entries[0]->get('mail'));
    }

    public function testSearchFiltersResults(): void
    {
        $entry1 = $this->createMock(Horde_Ldap_Entry::class);
        $entry1->method('getValues')->willReturn(['uid' => ['alice']]);

        $search = $this->createMock(Horde_Ldap_Search::class);
        $search->method('getIterator')->willReturn(new ArrayIterator([$entry1]));

        $this->ldapMock->method('search')->willReturn($search);

        $driver = $this->makeDriver();
        $entries = iterator_to_array($driver->search('ali'));

        $this->assertCount(1, $entries);
        $this->assertSame('alice', $entries[0]->getUserId());
    }
}
