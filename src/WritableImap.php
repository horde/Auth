<?php

declare(strict_types=1);

/**
 * Copyright 1999-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Chuck Hagenbuch <chuck@horde.org>
 * @author   Gaudenz Steinlin <gaudenz@soziologie.ch>
 * @author   Jan Schneider <jan@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use Closure;
use Horde\Imap\Client\ConnectionConfig;
use Horde\Imap\Client\Exception\MailboxProtocolException;
use Horde\Imap\Client\ImapAclAware;
use Horde\Imap\Client\ImapProtocol;
use Horde\Imap\Client\MailboxListMode;
use Horde\Imap\Client\SecureMode;
use RuntimeException;

/**
 * Writable IMAP authentication driver with mailbox-based user management.
 *
 * Extends the credential-only Imap driver with user lifecycle operations:
 * creating a user's personal mailbox, setting ACLs, removing mailboxes,
 * and listing users by enumerating mailboxes under a hierarchy prefix.
 *
 * Requires admin credentials and a server that supports ACL (RFC 4314).
 */
class WritableImap extends Imap implements UserDirectory, UserLifecycleManager
{
    private ?ImapProtocol $adminClient = null;

    /**
     * @param Closure(ConnectionConfig): ImapProtocol $clientFactory Factory returning an
     *        ImapProtocol (ideally also ImapAclAware) given a ConnectionConfig
     * @param string $hostspec IMAP server hostname or IP
     * @param SecureMode $secure Transport security mode
     * @param int|null $port Server port (null = auto based on SecureMode)
     * @param string $adminUser Administrator username for mailbox management
     * @param string $adminPassword Administrator password
     * @param string $userHierarchy Mailbox prefix for user namespace (e.g. 'user.')
     */
    public function __construct(
        Closure $clientFactory,
        string $hostspec = 'localhost',
        SecureMode $secure = SecureMode::None,
        ?int $port = null,
        private readonly string $adminUser = '',
        private readonly string $adminPassword = '',
        private readonly string $userHierarchy = 'user.',
    ) {
        if ($adminUser === '' || $adminPassword === '') {
            throw new RuntimeException(
                'WritableImap requires adminUser and adminPassword for user management'
            );
        }

        parent::__construct($clientFactory, $hostspec, $secure, $port);
    }

    public function exists(string $userId): bool
    {
        $admin = $this->getAdminClient();
        $pattern = $this->userHierarchy . $userId;

        try {
            $list = $admin->listMailboxes($pattern, MailboxListMode::All, ['flat' => true]);
        } catch (MailboxProtocolException $e) {
            throw new RuntimeException('IMAP error checking user existence: ' . $e->getMessage(), 0, $e);
        }

        return !empty($list);
    }

    /**
     * @return iterable<UserEntry>
     */
    public function list(): iterable
    {
        $admin = $this->getAdminClient();
        $pattern = $this->userHierarchy . '*';

        try {
            $list = $admin->listMailboxes($pattern, MailboxListMode::All, ['flat' => true]);
        } catch (MailboxProtocolException $e) {
            throw new RuntimeException('IMAP error listing users: ' . $e->getMessage(), 0, $e);
        }

        $prefixLen = strlen($this->userHierarchy);
        $entries = [];

        foreach ($list as $mailbox) {
            $name = is_object($mailbox) ? (string) $mailbox : $mailbox;
            $userId = substr($name, $prefixLen);
            if ($userId !== '' && $userId !== false) {
                $entries[] = new UserEntry($userId, 'imap');
            }
        }

        return $entries;
    }

    public function search(string $query): iterable
    {
        $entries = [];
        foreach ($this->list() as $entry) {
            if (str_contains($entry->getUserId(), $query)) {
                $entries[] = $entry;
            }
        }
        return $entries;
    }

    public function addUser(string $userId, array $attributes = []): UserEntry
    {
        $admin = $this->getAdminClient();
        $mailbox = $this->userHierarchy . $userId;

        try {
            $admin->createMailbox($mailbox);
        } catch (MailboxProtocolException $e) {
            throw new RuntimeException("Cannot create mailbox for user '$userId': " . $e->getMessage(), 0, $e);
        }

        if ($admin instanceof ImapAclAware) {
            try {
                $admin->setACL($mailbox, $this->adminUser, [
                    'rights' => 'lrswipcda',
                ]);
            } catch (MailboxProtocolException $e) {
                throw new RuntimeException("Cannot set ACL for user '$userId': " . $e->getMessage(), 0, $e);
            }
        }

        return new UserEntry($userId, 'imap');
    }

    public function removeUser(string $userId): void
    {
        $admin = $this->getAdminClient();
        $mailbox = $this->userHierarchy . $userId;

        if ($admin instanceof ImapAclAware) {
            try {
                $admin->setACL($mailbox, $this->adminUser, [
                    'rights' => 'lrswipcda',
                ]);
            } catch (MailboxProtocolException $e) {
                throw new RuntimeException("Cannot set ACL for removal of '$userId': " . $e->getMessage(), 0, $e);
            }
        }

        try {
            $admin->deleteMailbox($mailbox);
        } catch (MailboxProtocolException $e) {
            throw new RuntimeException("Cannot delete mailbox for user '$userId': " . $e->getMessage(), 0, $e);
        }
    }

    public function renameUser(string $oldId, string $newId): void
    {
        $admin = $this->getAdminClient();
        $oldMailbox = $this->userHierarchy . $oldId;
        $newMailbox = $this->userHierarchy . $newId;

        try {
            $admin->renameMailbox($oldMailbox, $newMailbox);
        } catch (MailboxProtocolException $e) {
            throw new RuntimeException(
                "Cannot rename mailbox from '$oldId' to '$newId': " . $e->getMessage(),
                0,
                $e,
            );
        }
    }

    public function updateUser(string $userId, array $attributes): void
    {
        if (!$this->exists($userId)) {
            throw new RuntimeException("User '$userId' not found");
        }
        // IMAP mailbox-based user management has no updateable attributes.
    }

    /**
     * Get or create the admin IMAP client (logged in as the admin user).
     */
    private function getAdminClient(): ImapProtocol
    {
        if ($this->adminClient !== null) {
            return $this->adminClient;
        }

        $config = new ConnectionConfig(
            username: $this->adminUser,
            password: $this->adminPassword,
            hostspec: $this->hostspec,
            port: $this->port,
            secure: $this->secure,
        );

        $client = ($this->clientFactory)($config);

        if (!$client instanceof ImapProtocol) {
            throw new RuntimeException(
                'WritableImap requires the clientFactory to return an ImapProtocol instance'
            );
        }

        try {
            $client->login();
        } catch (MailboxProtocolException $e) {
            throw new RuntimeException('Admin IMAP login failed: ' . $e->getMessage(), 0, $e);
        }

        $this->adminClient = $client;
        return $this->adminClient;
    }
}
