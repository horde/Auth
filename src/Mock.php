<?php

declare(strict_types=1);

/**
 * Copyright 1999-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Chuck Hagenbuch <chuck@horde.org>
 * @author   Michael Slusarz <slusarz@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\CredentialProvider;
use Horde\Auth\PasswordManager;
use Horde\Auth\PasswordUtility;
use Horde\Auth\TransparentProvider;
use Horde\Auth\UserDirectory;
use Horde\Auth\UserEntry;
use Horde\Auth\UserLifecycleManager;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

/**
 * In-memory mock auth driver for testing.
 *
 * Implements all auth interfaces. Stores users in a simple array.
 */
class Mock implements CredentialProvider, TransparentProvider, UserDirectory, UserLifecycleManager, PasswordManager
{
    /** @var array<string, array{password: string, attributes: array<string, mixed>}> */
    private array $users;

    private readonly string $backend;

    /**
     * @param array<string, array{password: string, attributes?: array<string, mixed>}> $users Initial user set
     * @param string|null $autoLoginUser If set, extractIdentity() returns this user
     * @param string $backend Backend identifier for results
     */
    public function __construct(
        array $users = [],
        private readonly ?string $autoLoginUser = null,
        string $backend = 'mock',
    ) {
        $this->backend = $backend;
        $this->users = [];
        foreach ($users as $userId => $data) {
            $this->users[$userId] = [
                'password' => $data['password'],
                'attributes' => $data['attributes'] ?? [],
            ];
        }
    }

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if (!isset($this->users[$userId])) {
            return new AuthResultFail($this->backend, $timestamp, ['reason' => 'unknown_user']);
        }

        if ($this->users[$userId]['password'] !== $password) {
            return new AuthResultFail($this->backend, $timestamp, ['reason' => 'bad_password']);
        }

        return new AuthResultSuccess(
            $this->backend,
            $timestamp,
            $userId,
            $this->users[$userId]['attributes'],
        );
    }

    public function extractIdentity(ServerRequestInterface $request): ?AuthResultSuccess
    {
        if ($this->autoLoginUser === null) {
            return null;
        }

        return new AuthResultSuccess(
            $this->backend,
            new DateTimeImmutable(),
            $this->autoLoginUser,
            $this->users[$this->autoLoginUser]['attributes'] ?? [],
        );
    }

    public function exists(string $userId): bool
    {
        return isset($this->users[$userId]);
    }

    public function list(): iterable
    {
        foreach ($this->users as $userId => $data) {
            yield new UserEntry($userId, $this->backend, $data['attributes']);
        }
    }

    public function search(string $query): iterable
    {
        $query = strtolower($query);
        foreach ($this->users as $userId => $data) {
            if (str_contains(strtolower($userId), $query)) {
                yield new UserEntry($userId, $this->backend, $data['attributes']);
            }
        }
    }

    public function addUser(string $userId, array $attributes = []): UserEntry
    {
        if (isset($this->users[$userId])) {
            throw new RuntimeException("User '$userId' already exists");
        }

        $this->users[$userId] = [
            'password' => $attributes['password'] ?? '',
            'attributes' => array_diff_key($attributes, ['password' => true]),
        ];

        return new UserEntry($userId, $this->backend, $this->users[$userId]['attributes']);
    }

    public function removeUser(string $userId): void
    {
        if (!isset($this->users[$userId])) {
            throw new RuntimeException("User '$userId' not found");
        }

        unset($this->users[$userId]);
    }

    public function renameUser(string $oldId, string $newId): void
    {
        if (!isset($this->users[$oldId])) {
            throw new RuntimeException("User '$oldId' not found");
        }
        if (isset($this->users[$newId])) {
            throw new RuntimeException("User '$newId' already exists");
        }

        $this->users[$newId] = $this->users[$oldId];
        unset($this->users[$oldId]);
    }

    public function updateUser(string $userId, array $attributes): void
    {
        if (!isset($this->users[$userId])) {
            throw new RuntimeException("User '$userId' not found");
        }

        if (isset($attributes['password'])) {
            $this->users[$userId]['password'] = $attributes['password'];
            unset($attributes['password']);
        }

        $this->users[$userId]['attributes'] = array_merge(
            $this->users[$userId]['attributes'],
            $attributes,
        );
    }

    public function changePassword(string $userId, string $oldPassword, string $newPassword): void
    {
        if (!isset($this->users[$userId])) {
            throw new RuntimeException("User '$userId' not found");
        }
        if ($this->users[$userId]['password'] !== $oldPassword) {
            throw new RuntimeException('Old password is incorrect');
        }

        $this->users[$userId]['password'] = $newPassword;
    }

    public function resetPassword(string $userId): string
    {
        if (!isset($this->users[$userId])) {
            throw new RuntimeException("User '$userId' not found");
        }

        $newPassword = PasswordUtility::generateRandom();
        $this->users[$userId]['password'] = $newPassword;

        return $newPassword;
    }
}
