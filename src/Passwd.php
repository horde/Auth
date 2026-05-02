<?php

declare(strict_types=1);

/**
 * Copyright 1997-2026 Rasmus Lerdorf <rasmus@php.net>
 * Copyright 2002-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Rasmus Lerdorf <rasmus@php.net>
 * @author   Chuck Hagenbuch <chuck@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\CredentialProvider;
use Horde\Auth\PasswordUtility;
use Horde\Auth\UserDirectory;
use Horde\Auth\UserEntry;
use RuntimeException;

/**
 * Read-only passwd file authentication driver.
 *
 * Authenticates against a Unix-style passwd file (user:hash:uid:gid:info:home:shell).
 * Provides credential validation and user directory listing.
 * For write operations, use WritablePasswd.
 */
class Passwd implements CredentialProvider, UserDirectory
{
    /** @var array<string, array{password: string, uid: string, gid: string, info: string, home: string, shell: string}>|null */
    private ?array $users = null;

    private const EXCLUDED_USERS = [
        'root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp',
        'mail', 'news', 'uucp', 'proxy', 'postgres', 'www-data', 'backup',
        'operator', 'list', 'irc', 'gnats', 'nobody', 'identd', 'sshd',
        'gdm', 'postfix', 'mysql', 'cyrus', 'ftp',
    ];

    public function __construct(
        private readonly string $filename,
        private readonly string $encryption = 'crypt-des',
    ) {}

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if ($password === '') {
            return new AuthResultFail('passwd', $timestamp, ['reason' => 'empty_password']);
        }

        $users = $this->getUsers();

        if (!isset($users[$userId])) {
            return new AuthResultFail('passwd', $timestamp, ['reason' => 'unknown_user']);
        }

        $storedHash = $users[$userId]['password'];
        $encrypted = PasswordUtility::crypt($password, $this->encryption, $storedHash);

        if ($encrypted !== $storedHash) {
            return new AuthResultFail('passwd', $timestamp, ['reason' => 'bad_password']);
        }

        return new AuthResultSuccess('passwd', $timestamp, $userId, [
            'uid' => $users[$userId]['uid'],
            'gid' => $users[$userId]['gid'],
            'info' => $users[$userId]['info'],
            'home' => $users[$userId]['home'],
            'shell' => $users[$userId]['shell'],
        ]);
    }

    public function exists(string $userId): bool
    {
        $users = $this->getUsers();
        return isset($users[$userId]);
    }

    public function list(): iterable
    {
        foreach ($this->getUsers() as $userId => $data) {
            yield new UserEntry($userId, 'passwd', [
                'uid' => $data['uid'],
                'gid' => $data['gid'],
                'info' => $data['info'],
                'home' => $data['home'],
                'shell' => $data['shell'],
            ]);
        }
    }

    public function search(string $query): iterable
    {
        $query = strtolower($query);
        foreach ($this->getUsers() as $userId => $data) {
            if (str_contains(strtolower($userId), $query)) {
                yield new UserEntry($userId, 'passwd', [
                    'uid' => $data['uid'],
                    'gid' => $data['gid'],
                    'info' => $data['info'],
                    'home' => $data['home'],
                    'shell' => $data['shell'],
                ]);
            }
        }
    }

    /**
     * @return array<string, array{password: string, uid: string, gid: string, info: string, home: string, shell: string}>
     */
    protected function getUsers(): array
    {
        if ($this->users === null) {
            $this->users = $this->parseFile();
        }
        return $this->users;
    }

    /**
     * @return array<string, array{password: string, uid: string, gid: string, info: string, home: string, shell: string}>
     */
    protected function parseFile(): array
    {
        if (!is_readable($this->filename)) {
            throw new RuntimeException("Cannot read passwd file: {$this->filename}");
        }

        $users = [];
        $lines = file($this->filename, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        foreach ($lines as $line) {
            if (str_starts_with($line, '#')) {
                continue;
            }

            $parts = explode(':', $line);
            if (count($parts) < 2) {
                continue;
            }

            $username = $parts[0];
            if (in_array($username, self::EXCLUDED_USERS, true)) {
                continue;
            }

            $users[$username] = [
                'password' => $parts[1] ?? '',
                'uid' => $parts[2] ?? '',
                'gid' => $parts[3] ?? '',
                'info' => $parts[4] ?? '',
                'home' => $parts[5] ?? '',
                'shell' => $parts[6] ?? '',
            ];
        }

        return $users;
    }
}
