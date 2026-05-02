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
use DateTimeImmutable;
use Horde\Imap\Client\ConnectionConfig;
use Horde\Imap\Client\Exception\AuthenticationException;
use Horde\Imap\Client\Exception\MailboxProtocolException;
use Horde\Imap\Client\MailboxProtocol;
use Horde\Imap\Client\SecureMode;
use RuntimeException;

/**
 * IMAP credential validation driver.
 *
 * Authenticates a user by attempting an IMAP login with the supplied
 * credentials. This driver is stateless — it creates a fresh connection
 * for each validation attempt.
 *
 * For user management (mailbox-based create/remove/list), use WritableImap.
 */
class Imap implements CredentialProvider
{
    /**
     * @param Closure(ConnectionConfig): MailboxProtocol $clientFactory Factory returning a
     *        MailboxProtocol given a ConnectionConfig. This allows the Auth package to stay
     *        decoupled from any specific IMAP socket implementation.
     * @param string $hostspec IMAP server hostname or IP
     * @param SecureMode $secure Transport security mode
     * @param int|null $port Server port (null = auto based on SecureMode)
     */
    public function __construct(
        protected readonly Closure $clientFactory,
        protected readonly string $hostspec = 'localhost',
        protected readonly SecureMode $secure = SecureMode::None,
        protected readonly ?int $port = null,
    ) {}

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $password = $credentials['password'] ?? '';

        $client = $this->createClient($userId, $password);

        try {
            $client->login();
        } catch (AuthenticationException) {
            return new AuthResultFail(
                'imap',
                new DateTimeImmutable(),
                ['reason' => 'bad_password'],
            );
        } catch (MailboxProtocolException $e) {
            throw new RuntimeException('IMAP server error: ' . $e->getMessage(), 0, $e);
        }

        try {
            $client->logout();
        } catch (MailboxProtocolException) {
            // Logout failure is non-fatal after successful auth.
        }

        return new AuthResultSuccess(
            'imap',
            new DateTimeImmutable(),
            $userId,
        );
    }

    /**
     * Create a MailboxProtocol client instance for the given credentials.
     */
    protected function createClient(string $username, string $password): MailboxProtocol
    {
        $config = new ConnectionConfig(
            username: $username,
            password: $password,
            hostspec: $this->hostspec,
            port: $this->port,
            secure: $this->secure,
        );

        return ($this->clientFactory)($config);
    }
}
