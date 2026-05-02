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
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\CredentialProvider;
use Horde\Auth\PasswordManager;
use Horde\Auth\PasswordUtility;
use Horde\Auth\UserDirectory;
use Horde\Auth\UserEntry;
use Horde\Auth\UserLifecycleManager;
use Horde\Db\Adapter as DbAdapter;
use Exception;
use RuntimeException;

/**
 * SQL database authentication driver.
 *
 * Full-featured driver supporting credential validation, user directory,
 * user lifecycle management, and password operations.
 */
class Sql implements CredentialProvider, UserDirectory, UserLifecycleManager, PasswordManager
{
    public function __construct(
        private readonly DbAdapter $db,
        private readonly string $table = 'horde_users',
        private readonly string $usernameField = 'user_uid',
        private readonly string $passwordField = 'user_pass',
        private readonly string $encryption = 'crypt-blowfish',
        private readonly bool $showEncryption = false,
        private readonly ?string $softExpirationField = null,
        private readonly ?string $hardExpirationField = null,
        private readonly string $backend = 'sql',
    ) {}

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if ($password === '') {
            return new AuthResultFail($this->backend, $timestamp, ['reason' => 'empty_password']);
        }

        $sql = sprintf(
            'SELECT * FROM %s WHERE %s = ?',
            $this->db->quoteTableName($this->table),
            $this->db->quoteColumnName($this->usernameField),
        );

        try {
            $row = $this->db->selectOne($sql, [$userId]);
        } catch (Exception $e) {
            throw new RuntimeException('Database error during authentication: ' . $e->getMessage(), 0, $e);
        }

        if ($row === null || $row === false) {
            return new AuthResultFail($this->backend, $timestamp, ['reason' => 'unknown_user']);
        }

        $storedHash = $row[$this->passwordField] ?? '';
        if (!$this->comparePasswords($storedHash, $password)) {
            return new AuthResultFail($this->backend, $timestamp, ['reason' => 'bad_password']);
        }

        $metadata = [];
        if ($this->softExpirationField && isset($row[$this->softExpirationField])) {
            $metadata['soft_expiration'] = $row[$this->softExpirationField];
        }
        if ($this->hardExpirationField && isset($row[$this->hardExpirationField])) {
            $metadata['hard_expiration'] = $row[$this->hardExpirationField];
        }

        return new AuthResultSuccess($this->backend, $timestamp, $userId, $metadata);
    }

    public function exists(string $userId): bool
    {
        $sql = sprintf(
            'SELECT 1 FROM %s WHERE %s = ?',
            $this->db->quoteTableName($this->table),
            $this->db->quoteColumnName($this->usernameField),
        );

        $result = $this->db->selectValue($sql, [$userId]);
        return $result !== null && $result !== false;
    }

    public function list(): iterable
    {
        $sql = sprintf(
            'SELECT * FROM %s ORDER BY %s',
            $this->db->quoteTableName($this->table),
            $this->db->quoteColumnName($this->usernameField),
        );

        $rows = $this->db->selectAll($sql);
        foreach ($rows as $row) {
            yield $this->rowToEntry($row);
        }
    }

    public function search(string $query): iterable
    {
        $sql = sprintf(
            'SELECT * FROM %s WHERE %s LIKE ? ORDER BY %s',
            $this->db->quoteTableName($this->table),
            $this->db->quoteColumnName($this->usernameField),
            $this->db->quoteColumnName($this->usernameField),
        );

        $rows = $this->db->selectAll($sql, ['%' . $query . '%']);
        foreach ($rows as $row) {
            yield $this->rowToEntry($row);
        }
    }

    public function addUser(string $userId, array $attributes = []): UserEntry
    {
        $password = $attributes['password'] ?? '';
        $hashedPassword = PasswordUtility::crypt($password, $this->encryption, '', $this->showEncryption);

        $columns = [$this->usernameField, $this->passwordField];
        $values = [$userId, $hashedPassword];

        if ($this->softExpirationField && isset($attributes['soft_expiration'])) {
            $columns[] = $this->softExpirationField;
            $values[] = $attributes['soft_expiration'];
        }
        if ($this->hardExpirationField && isset($attributes['hard_expiration'])) {
            $columns[] = $this->hardExpirationField;
            $values[] = $attributes['hard_expiration'];
        }

        $sql = sprintf(
            'INSERT INTO %s (%s) VALUES (%s)',
            $this->db->quoteTableName($this->table),
            implode(', ', array_map([$this->db, 'quoteColumnName'], $columns)),
            implode(', ', array_fill(0, count($values), '?')),
        );

        $this->db->insert($sql, $values);

        return new UserEntry($userId, $this->backend, array_diff_key($attributes, ['password' => true]));
    }

    public function removeUser(string $userId): void
    {
        $sql = sprintf(
            'DELETE FROM %s WHERE %s = ?',
            $this->db->quoteTableName($this->table),
            $this->db->quoteColumnName($this->usernameField),
        );

        $this->db->delete($sql, [$userId]);
    }

    public function renameUser(string $oldId, string $newId): void
    {
        $sql = sprintf(
            'UPDATE %s SET %s = ? WHERE %s = ?',
            $this->db->quoteTableName($this->table),
            $this->db->quoteColumnName($this->usernameField),
            $this->db->quoteColumnName($this->usernameField),
        );

        $this->db->update($sql, [$newId, $oldId]);
    }

    public function updateUser(string $userId, array $attributes): void
    {
        $sets = [];
        $values = [];

        if (isset($attributes['password'])) {
            $sets[] = $this->db->quoteColumnName($this->passwordField) . ' = ?';
            $values[] = PasswordUtility::crypt($attributes['password'], $this->encryption, '', $this->showEncryption);
        }
        if ($this->softExpirationField && isset($attributes['soft_expiration'])) {
            $sets[] = $this->db->quoteColumnName($this->softExpirationField) . ' = ?';
            $values[] = $attributes['soft_expiration'];
        }
        if ($this->hardExpirationField && isset($attributes['hard_expiration'])) {
            $sets[] = $this->db->quoteColumnName($this->hardExpirationField) . ' = ?';
            $values[] = $attributes['hard_expiration'];
        }

        if (empty($sets)) {
            return;
        }

        $values[] = $userId;
        $sql = sprintf(
            'UPDATE %s SET %s WHERE %s = ?',
            $this->db->quoteTableName($this->table),
            implode(', ', $sets),
            $this->db->quoteColumnName($this->usernameField),
        );

        $this->db->update($sql, $values);
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
        if (!$this->exists($userId)) {
            throw new RuntimeException("User '$userId' not found");
        }

        $newPassword = PasswordUtility::generateRandom();
        $this->updateUser($userId, ['password' => $newPassword]);

        return $newPassword;
    }

    private function comparePasswords(string $storedHash, string $plaintext): bool
    {
        $encrypted = PasswordUtility::crypt($plaintext, $this->encryption, $storedHash, $this->showEncryption);
        return hash_equals($storedHash, $encrypted);
    }

    private function rowToEntry(array $row): UserEntry
    {
        $userId = $row[$this->usernameField];
        $attributes = array_diff_key($row, [$this->usernameField => true, $this->passwordField => true]);

        return new UserEntry($userId, $this->backend, $attributes);
    }
}
