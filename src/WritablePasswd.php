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

use Horde\Auth\PasswordManager;
use Horde\Auth\PasswordUtility;
use Horde\Auth\UserEntry;
use Horde\Auth\UserLifecycleManager;
use RuntimeException;

/**
 * Writable passwd file authentication driver.
 *
 * Extends the read-only Passwd driver with user lifecycle and password
 * management. Uses file locking for safe concurrent access and atomic
 * writes via temp file + rename.
 */
class WritablePasswd extends Passwd implements UserLifecycleManager, PasswordManager
{
    /** @var array<string, array{password: string, uid: string, gid: string, info: string, home: string, shell: string}>|null */
    private ?array $mutableUsers = null;

    private readonly string $filename;
    private readonly string $encryption;

    public function __construct(
        string $filename,
        string $encryption = 'crypt-des',
    ) {
        parent::__construct($filename, $encryption);
        $this->filename = $filename;
        $this->encryption = $encryption;
    }

    public function addUser(string $userId, array $attributes = []): UserEntry
    {
        $users = $this->getMutableUsers();

        if (isset($users[$userId])) {
            throw new RuntimeException("User '$userId' already exists");
        }

        $password = $attributes['password'] ?? '';
        $hashedPassword = PasswordUtility::crypt($password, $this->encryption);

        $users[$userId] = [
            'password' => $hashedPassword,
            'uid' => $attributes['uid'] ?? '',
            'gid' => $attributes['gid'] ?? '',
            'info' => $attributes['info'] ?? '',
            'home' => $attributes['home'] ?? '',
            'shell' => $attributes['shell'] ?? '',
        ];

        $this->mutableUsers = $users;
        $this->flush();

        return new UserEntry($userId, 'passwd', array_diff_key($users[$userId], ['password' => true]));
    }

    public function removeUser(string $userId): void
    {
        $users = $this->getMutableUsers();

        if (!isset($users[$userId])) {
            throw new RuntimeException("User '$userId' not found");
        }

        unset($users[$userId]);
        $this->mutableUsers = $users;
        $this->flush();
    }

    public function renameUser(string $oldId, string $newId): void
    {
        $users = $this->getMutableUsers();

        if (!isset($users[$oldId])) {
            throw new RuntimeException("User '$oldId' not found");
        }
        if (isset($users[$newId])) {
            throw new RuntimeException("User '$newId' already exists");
        }

        $users[$newId] = $users[$oldId];
        unset($users[$oldId]);
        $this->mutableUsers = $users;
        $this->flush();
    }

    public function updateUser(string $userId, array $attributes): void
    {
        $users = $this->getMutableUsers();

        if (!isset($users[$userId])) {
            throw new RuntimeException("User '$userId' not found");
        }

        if (isset($attributes['password'])) {
            $users[$userId]['password'] = PasswordUtility::crypt($attributes['password'], $this->encryption);
            unset($attributes['password']);
        }

        foreach (['uid', 'gid', 'info', 'home', 'shell'] as $field) {
            if (isset($attributes[$field])) {
                $users[$userId][$field] = $attributes[$field];
            }
        }

        $this->mutableUsers = $users;
        $this->flush();
    }

    public function changePassword(string $userId, string $oldPassword, string $newPassword): void
    {
        $users = $this->getMutableUsers();

        if (!isset($users[$userId])) {
            throw new RuntimeException("User '$userId' not found");
        }

        $storedHash = $users[$userId]['password'];
        $encrypted = PasswordUtility::crypt($oldPassword, $this->encryption, $storedHash);

        if ($encrypted !== $storedHash) {
            throw new RuntimeException('Old password is incorrect');
        }

        $users[$userId]['password'] = PasswordUtility::crypt($newPassword, $this->encryption);
        $this->mutableUsers = $users;
        $this->flush();
    }

    public function resetPassword(string $userId): string
    {
        $users = $this->getMutableUsers();

        if (!isset($users[$userId])) {
            throw new RuntimeException("User '$userId' not found");
        }

        $newPassword = PasswordUtility::generateRandom();
        $users[$userId]['password'] = PasswordUtility::crypt($newPassword, $this->encryption);
        $this->mutableUsers = $users;
        $this->flush();

        return $newPassword;
    }

    /**
     * @return array<string, array{password: string, uid: string, gid: string, info: string, home: string, shell: string}>
     */
    private function getMutableUsers(): array
    {
        if ($this->mutableUsers === null) {
            $this->mutableUsers = $this->getUsers();
        }
        return $this->mutableUsers;
    }

    protected function getUsers(): array
    {
        if ($this->mutableUsers !== null) {
            return $this->mutableUsers;
        }
        return parent::getUsers();
    }

    private function flush(): void
    {
        $tmpFile = $this->filename . '.tmp.' . getmypid();
        $handle = fopen($tmpFile, 'w');
        if ($handle === false) {
            throw new RuntimeException("Cannot write to: $tmpFile");
        }

        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            unlink($tmpFile);
            throw new RuntimeException("Cannot acquire lock on: $tmpFile");
        }

        foreach ($this->mutableUsers as $userId => $data) {
            $line = implode(':', [
                $userId,
                $data['password'],
                $data['uid'],
                $data['gid'],
                $data['info'],
                $data['home'],
                $data['shell'],
            ]);
            fwrite($handle, $line . "\n");
        }

        flock($handle, LOCK_UN);
        fclose($handle);

        if (!rename($tmpFile, $this->filename)) {
            unlink($tmpFile);
            throw new RuntimeException("Cannot rename temp file to: {$this->filename}");
        }
    }
}
