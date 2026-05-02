<?php

declare(strict_types=1);

/**
 * Copyright 1999-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Chuck Hagenbuch <chuck@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;
use Psr\Http\Message\ServerRequestInterface;

/**
 * HTTP Basic Authentication transparent provider.
 *
 * Extracts identity from PHP_AUTH_USER/PHP_AUTH_PW server params.
 * Optionally validates against an htpasswd-style file.
 */
class Http implements TransparentProvider, CredentialProvider
{
    /** @var array<string, string> username => hashed password */
    private array $users = [];

    /**
     * @param string $htpasswdFile Optional path to htpasswd file for credential validation
     * @param string $encryption Hash algorithm used in htpasswd file
     */
    public function __construct(
        private readonly string $htpasswdFile = '',
        private readonly string $encryption = 'crypt-des',
    ) {
        if ($this->htpasswdFile !== '' && is_readable($this->htpasswdFile)) {
            $lines = file($this->htpasswdFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
            foreach ($lines as $line) {
                if (str_starts_with($line, '#')) {
                    continue;
                }
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $this->users[trim($parts[0])] = trim($parts[1]);
                }
            }
        }
    }

    public function extractIdentity(ServerRequestInterface $request): ?AuthResultSuccess
    {
        $serverParams = $request->getServerParams();
        $username = $serverParams['PHP_AUTH_USER'] ?? '';
        $password = $serverParams['PHP_AUTH_PW'] ?? '';

        if ($username === '') {
            return null;
        }

        if ($this->users !== [] && $password !== '') {
            $result = $this->validate($username, ['password' => $password]);
            if ($result instanceof AuthResultSuccess) {
                return $result;
            }
            return null;
        }

        return new AuthResultSuccess(
            'http',
            new DateTimeImmutable(),
            $username,
        );
    }

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if ($password === '') {
            return new AuthResultFail('http', $timestamp, ['reason' => 'empty_password']);
        }

        if (!isset($this->users[$userId])) {
            return new AuthResultFail('http', $timestamp, ['reason' => 'unknown_user']);
        }

        $storedHash = $this->users[$userId];
        $encrypted = PasswordUtility::crypt($password, $this->encryption, $storedHash);

        if ($encrypted !== $storedHash) {
            return new AuthResultFail('http', $timestamp, ['reason' => 'bad_password']);
        }

        return new AuthResultSuccess('http', $timestamp, $userId);
    }
}
