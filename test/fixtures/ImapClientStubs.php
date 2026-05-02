<?php

/**
 * Stubs for Horde\Imap\Client interfaces.
 *
 * These exist so unit tests can mock IMAP client types without requiring
 * horde/imap_client as a dev dependency. The Auth package only depends on
 * the interfaces (which are thin), not the socket implementation.
 */

declare(strict_types=1);

namespace Horde\Imap\Client;

if (!interface_exists(MailboxProtocol::class, false)) {
    interface MailboxProtocol
    {
        public function login(): void;
        public function logout(): void;
        public function noop(): void;
        public function status(string $mailbox, int $flags): object;
        public function fetch(string $mailbox, MessageIdSet $ids, object $query): \Generator;
        public function store(string $mailbox, array $options): MessageIdSet;
        public function expunge(string $mailbox, array $options): MessageIdSet;
        public function getIdsOb(mixed $ids = null, bool $sequence = false): MessageIdSet;
    }
}

if (!interface_exists(ImapProtocol::class, false)) {
    interface ImapProtocol extends MailboxProtocol
    {
        public function getCapability(): CapabilityInterface;
        public function openMailbox(string $mailbox, OpenMode $mode): void;
        public function createMailbox(string $mailbox): void;
        public function deleteMailbox(string $mailbox): void;
        public function renameMailbox(string $old, string $new): void;
        public function subscribeMailbox(string $mailbox, bool $subscribe = true): void;
        public function listMailboxes(string $pattern, MailboxListMode $mode, array $options = []): array;
        public function close(array $options = []): void;
        public function search(string $mailbox, object $query, array $options = []): object;
        public function thread(string $mailbox, array $options = []): object;
        public function copy(string $source, string $dest, array $options = []): MessageIdSet;
        public function move(string $source, string $dest, array $options = []): MessageIdSet;
        public function append(string $mailbox, array $data, array $options = []): MessageIdSet;
        public function getNamespaces(): object;
        public function unselect(): void;
    }
}

if (!interface_exists(ImapAclAware::class, false)) {
    interface ImapAclAware
    {
        public function getACL(string $mailbox): object;
        public function setACL(string $mailbox, string $identifier, array $options): void;
        public function deleteACL(string $mailbox, string $identifier): void;
        public function listACLRights(string $mailbox, string $identifier): object;
        public function getMyACLRights(string $mailbox): object;
    }
}

if (!enum_exists(SecureMode::class, false)) {
    enum SecureMode: string
    {
        case None = '';
        case Ssl = 'ssl';
        case Tls = 'tls';
        case Tlsv1 = 'tlsv1';
    }
}

if (!enum_exists(MailboxListMode::class, false)) {
    enum MailboxListMode: int
    {
        case Subscribed = 1;
        case SubscribedExists = 2;
        case Unsubscribed = 3;
        case All = 4;
        case AllSubscribed = 5;
    }
}

if (!class_exists(ConnectionConfig::class, false)) {
    final class ConnectionConfig
    {
        public function __construct(
            public readonly string $username,
            public readonly string|PasswordInterface $password,
            public readonly string $hostspec = 'localhost',
            public readonly ?int $port = null,
            public readonly SecureMode $secure = SecureMode::None,
            public readonly int $timeout = 30,
            public readonly int $readTimeout = 120,
            public readonly ?array $context = null,
            public readonly array $capabilityIgnore = [],
            public readonly ?array $id = null,
            public readonly array $lang = [],
        ) {}
    }
}

if (!interface_exists(PasswordInterface::class, false)) {
    interface PasswordInterface {}
}

if (!interface_exists(CapabilityInterface::class, false)) {
    interface CapabilityInterface {}
}

if (!class_exists(MessageIdSet::class, false)) {
    class MessageIdSet {}
}

if (!enum_exists(OpenMode::class, false)) {
    enum OpenMode: string
    {
        case ReadOnly = 'readonly';
        case ReadWrite = 'readwrite';
    }
}

namespace Horde\Imap\Client\Exception;

if (!class_exists(MailboxProtocolException::class, false)) {
    class MailboxProtocolException extends \RuntimeException {}
}

if (!class_exists(AuthenticationException::class, false)) {
    class AuthenticationException extends MailboxProtocolException {}
}
