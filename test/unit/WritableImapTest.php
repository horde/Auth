<?php

declare(strict_types=1);

namespace Horde\Auth\Test;

use Closure;
use Horde\Auth\UserEntry;
use Horde\Auth\WritableImap;
use Horde\Imap\Client\ConnectionConfig;
use Horde\Imap\Client\Exception\MailboxProtocolException;
use Horde\Imap\Client\ImapAclAware;
use Horde\Imap\Client\ImapProtocol;
use Horde\Imap\Client\MailboxListMode;
use Horde\Imap\Client\SecureMode;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;

#[CoversClass(WritableImap::class)]
class WritableImapTest extends TestCase
{
    /** @return ImapProtocol&ImapAclAware */
    private function createImapMock(): ImapProtocol&ImapAclAware
    {
        return $this->createMock(ImapAndAclInterface::class);
    }

    private function makeDriver(ImapProtocol&ImapAclAware $client): WritableImap
    {
        $factory = Closure::fromCallable(fn(ConnectionConfig $config) => $client);

        return new WritableImap(
            clientFactory: $factory,
            hostspec: 'imap.example.com',
            secure: SecureMode::Tls,
            port: 993,
            adminUser: 'admin',
            adminPassword: 'adminpass',
            userHierarchy: 'user.',
        );
    }

    public function testConstructorRequiresAdminUser(): void
    {
        $factory = Closure::fromCallable(fn(ConnectionConfig $config) => $this->createImapMock());

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('adminUser and adminPassword');

        new WritableImap(
            clientFactory: $factory,
            adminUser: '',
            adminPassword: 'pass',
        );
    }

    public function testConstructorRequiresAdminPassword(): void
    {
        $factory = Closure::fromCallable(fn(ConnectionConfig $config) => $this->createImapMock());

        $this->expectException(RuntimeException::class);

        new WritableImap(
            clientFactory: $factory,
            adminUser: 'admin',
            adminPassword: '',
        );
    }

    public function testAddUserCreatesMailboxAndSetsAcl(): void
    {
        $client = $this->createImapMock();
        $client->expects($this->once())->method('login');
        $client->expects($this->once())
            ->method('createMailbox')
            ->with('user.alice');
        $client->expects($this->once())
            ->method('setACL')
            ->with('user.alice', 'admin', ['rights' => 'lrswipcda']);

        $driver = $this->makeDriver($client);
        $entry = $driver->addUser('alice');

        $this->assertInstanceOf(UserEntry::class, $entry);
        $this->assertSame('alice', $entry->getUserId());
        $this->assertSame('imap', $entry->getBackend());
    }

    public function testRemoveUserSetsAclThenDeletesMailbox(): void
    {
        $client = $this->createImapMock();
        $client->expects($this->once())->method('login');
        $client->expects($this->once())
            ->method('setACL')
            ->with('user.bob', 'admin', ['rights' => 'lrswipcda']);
        $client->expects($this->once())
            ->method('deleteMailbox')
            ->with('user.bob');

        $driver = $this->makeDriver($client);
        $driver->removeUser('bob');
    }

    public function testListUsersEnumeratesMailboxes(): void
    {
        $client = $this->createImapMock();
        $client->expects($this->once())->method('login');
        $client->expects($this->once())
            ->method('listMailboxes')
            ->with('user.*', MailboxListMode::All, ['flat' => true])
            ->willReturn(['user.alice', 'user.bob', 'user.charlie']);

        $driver = $this->makeDriver($client);
        $entries = $driver->list();

        $this->assertIsArray($entries);
        $this->assertCount(3, $entries);
        $this->assertSame('alice', $entries[0]->getUserId());
        $this->assertSame('bob', $entries[1]->getUserId());
        $this->assertSame('charlie', $entries[2]->getUserId());
    }

    public function testExistsReturnsTrueWhenMailboxFound(): void
    {
        $client = $this->createImapMock();
        $client->expects($this->once())->method('login');
        $client->expects($this->once())
            ->method('listMailboxes')
            ->with('user.alice', MailboxListMode::All, ['flat' => true])
            ->willReturn(['user.alice']);

        $driver = $this->makeDriver($client);
        $this->assertTrue($driver->exists('alice'));
    }

    public function testExistsReturnsFalseWhenMailboxNotFound(): void
    {
        $client = $this->createImapMock();
        $client->expects($this->once())->method('login');
        $client->expects($this->once())
            ->method('listMailboxes')
            ->willReturn([]);

        $driver = $this->makeDriver($client);
        $this->assertFalse($driver->exists('nobody'));
    }

    public function testSearchFiltersResults(): void
    {
        $client = $this->createImapMock();
        $client->method('login');
        $client->method('listMailboxes')
            ->willReturn(['user.alice', 'user.bob', 'user.albert']);

        $driver = $this->makeDriver($client);
        $results = $driver->search('al');

        $this->assertIsArray($results);
        $this->assertCount(2, $results);
        $this->assertSame('alice', $results[0]->getUserId());
        $this->assertSame('albert', $results[1]->getUserId());
    }

    public function testRenameUserCallsRenameMailbox(): void
    {
        $client = $this->createImapMock();
        $client->expects($this->once())->method('login');
        $client->expects($this->once())
            ->method('renameMailbox')
            ->with('user.oldname', 'user.newname');

        $driver = $this->makeDriver($client);
        $driver->renameUser('oldname', 'newname');
    }

    public function testAddUserThrowsOnMailboxError(): void
    {
        $client = $this->createImapMock();
        $client->method('login');
        $client->method('createMailbox')
            ->willThrowException(new MailboxProtocolException('Already exists'));

        $driver = $this->makeDriver($client);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Cannot create mailbox');
        $driver->addUser('alice');
    }

    public function testRemoveUserThrowsOnDeleteError(): void
    {
        $client = $this->createImapMock();
        $client->method('login');
        $client->method('setACL');
        $client->method('deleteMailbox')
            ->willThrowException(new MailboxProtocolException('Not found'));

        $driver = $this->makeDriver($client);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Cannot delete mailbox');
        $driver->removeUser('ghost');
    }
}

/**
 * Combined interface for mocking an IMAP client that supports both protocol and ACL.
 */
interface ImapAndAclInterface extends ImapProtocol, ImapAclAware {}
