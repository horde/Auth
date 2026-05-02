<?php

declare(strict_types=1);

/**
 * Copyright 2002-2026 Ronnie Garcia <ronnie@mk2.net>
 * Copyright 2002-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Ronnie Garcia <ronnie@mk2.net>
 * @author   Chuck Hagenbuch <chuck@horde.org>
 * @author   Joel Vandal <joel@scopserv.com>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;
use Horde\Db\Adapter as DbAdapter;
use Exception;
use RuntimeException;

/**
 * Custom SQL authentication driver.
 *
 * Allows fully custom SQL queries for each operation. Tokens:
 *   \L = quoted userId
 *   \P = quoted hashed password
 *   \O = quoted old userId (for rename)
 *
 * Implements interfaces conditionally based on which queries are configured.
 * Always implements CredentialProvider (query_auth required).
 */
class Customsql implements CredentialProvider, UserDirectory, UserLifecycleManager, PasswordManager
{
    public function __construct(
        private readonly DbAdapter $db,
        private readonly string $queryAuth,
        private readonly string $encryption = 'crypt-blowfish',
        private readonly bool $showEncryption = false,
        private readonly string $queryAdd = '',
        private readonly string $queryUpdate = '',
        private readonly string $queryResetpassword = '',
        private readonly string $queryRemove = '',
        private readonly string $queryList = '',
        private readonly string $queryExists = '',
        private readonly string $queryGetpw = '',
        private readonly string $backend = 'customsql',
    ) {}

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if ($password === '') {
            return new AuthResultFail($this->backend, $timestamp, ['reason' => 'empty_password']);
        }

        $storedHash = $this->getStoredPassword($userId);
        $hashed = PasswordUtility::crypt($password, $this->encryption, $storedHash, $this->showEncryption);

        $query = str_replace(
            ['\L', '\P'],
            [$this->db->quoteString($userId), $this->db->quoteString($hashed)],
            $this->queryAuth,
        );

        try {
            $result = $this->db->selectValue($query);
        } catch (Exception $e) {
            throw new RuntimeException('Database error during authentication: ' . $e->getMessage(), 0, $e);
        }

        if (!$result) {
            return new AuthResultFail($this->backend, $timestamp, ['reason' => 'bad_credentials']);
        }

        return new AuthResultSuccess($this->backend, $timestamp, $userId);
    }

    public function exists(string $userId): bool
    {
        if ($this->queryExists === '') {
            throw new RuntimeException('exists() not supported: query_exists not configured');
        }

        $query = str_replace('\L', $this->db->quoteString($userId), $this->queryExists);

        try {
            return (bool) $this->db->selectValue($query);
        } catch (Exception) {
            return false;
        }
    }

    public function list(): iterable
    {
        if ($this->queryList === '') {
            throw new RuntimeException('list() not supported: query_list not configured');
        }

        try {
            $users = $this->db->selectValues($this->queryList);
        } catch (Exception $e) {
            throw new RuntimeException('Database error listing users: ' . $e->getMessage(), 0, $e);
        }

        foreach ($users as $userId) {
            yield new UserEntry($userId, $this->backend);
        }
    }

    public function search(string $query): iterable
    {
        $query = strtolower($query);
        foreach ($this->list() as $entry) {
            if (str_contains(strtolower($entry->getUserId()), $query)) {
                yield $entry;
            }
        }
    }

    public function addUser(string $userId, array $attributes = []): UserEntry
    {
        if ($this->queryAdd === '') {
            throw new RuntimeException('addUser() not supported: query_add not configured');
        }

        $password = $attributes['password'] ?? '';
        $hashed = PasswordUtility::crypt($password, $this->encryption, '', $this->showEncryption);

        $query = str_replace(
            ['\L', '\P'],
            [$this->db->quoteString($userId), $this->db->quoteString($hashed)],
            $this->queryAdd,
        );

        try {
            $this->db->insert($query);
        } catch (Exception $e) {
            throw new RuntimeException('Database error adding user: ' . $e->getMessage(), 0, $e);
        }

        return new UserEntry($userId, $this->backend, array_diff_key($attributes, ['password' => true]));
    }

    public function removeUser(string $userId): void
    {
        if ($this->queryRemove === '') {
            throw new RuntimeException('removeUser() not supported: query_remove not configured');
        }

        $query = str_replace('\L', $this->db->quoteString($userId), $this->queryRemove);

        try {
            $this->db->delete($query);
        } catch (Exception $e) {
            throw new RuntimeException('Database error removing user: ' . $e->getMessage(), 0, $e);
        }
    }

    public function renameUser(string $oldId, string $newId): void
    {
        if ($this->queryUpdate === '') {
            throw new RuntimeException('renameUser() not supported: query_update not configured');
        }

        $storedHash = $this->getStoredPassword($oldId);
        $query = str_replace(
            ['\O', '\L', '\P'],
            [$this->db->quoteString($oldId), $this->db->quoteString($newId), $this->db->quoteString($storedHash)],
            $this->queryUpdate,
        );

        try {
            $this->db->update($query);
        } catch (Exception $e) {
            throw new RuntimeException('Database error renaming user: ' . $e->getMessage(), 0, $e);
        }
    }

    public function updateUser(string $userId, array $attributes): void
    {
        if (isset($attributes['password'])) {
            $hashed = PasswordUtility::crypt($attributes['password'], $this->encryption, '', $this->showEncryption);
            if ($this->queryUpdate !== '') {
                $query = str_replace(
                    ['\O', '\L', '\P'],
                    [$this->db->quoteString($userId), $this->db->quoteString($userId), $this->db->quoteString($hashed)],
                    $this->queryUpdate,
                );
                try {
                    $this->db->update($query);
                } catch (Exception $e) {
                    throw new RuntimeException('Database error updating user: ' . $e->getMessage(), 0, $e);
                }
            }
        }
    }

    public function changePassword(string $userId, string $oldPassword, string $newPassword): void
    {
        $result = $this->validate($userId, ['password' => $oldPassword]);
        if ($result instanceof AuthResultFail) {
            throw new RuntimeException('Old password is incorrect');
        }

        $this->updateUser($userId, ['password' => $newPassword]);
    }

    public function resetPassword(string $userId): string
    {
        if ($this->queryResetpassword === '') {
            throw new RuntimeException('resetPassword() not supported: query_resetpassword not configured');
        }

        $newPassword = PasswordUtility::generateRandom();
        $hashed = PasswordUtility::crypt($newPassword, $this->encryption, '', $this->showEncryption);

        $query = str_replace(
            ['\L', '\P'],
            [$this->db->quoteString($userId), $this->db->quoteString($hashed)],
            $this->queryResetpassword,
        );

        try {
            $this->db->update($query);
        } catch (Exception $e) {
            throw new RuntimeException('Database error resetting password: ' . $e->getMessage(), 0, $e);
        }

        return $newPassword;
    }

    private function getStoredPassword(string $userId): string
    {
        if ($this->queryGetpw === '') {
            return '';
        }

        $query = str_replace('\L', $this->db->quoteString($userId), $this->queryGetpw);

        try {
            return (string) ($this->db->selectValue($query) ?? '');
        } catch (Exception) {
            return '';
        }
    }
}
