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

use RuntimeException;

/**
 * CRUD operations on user accounts in a specific backend.
 *
 * Not all backends that can authenticate can also manage users.
 * This interface is implemented only by backends that support
 * user creation, removal, renaming, and attribute updates.
 */
interface UserLifecycleManager
{
    /**
     * Create a new user account in this backend.
     *
     * @param string $userId The user identifier for the new account
     * @param array<string, mixed> $attributes Backend-specific attributes;
     *        typically includes 'password'. Other keys are backend-dependent
     *        (e.g. 'uid', 'gid', 'home', 'shell' for passwd; 'soft_expiration',
     *        'hard_expiration' for SQL).
     *
     * @return UserEntry The created user entry (without password in attributes)
     *
     * @throws RuntimeException If the user already exists or on write failure
     */
    public function addUser(string $userId, array $attributes = []): UserEntry;

    /**
     * Remove a user account from this backend.
     *
     * @param string $userId The user identifier to remove
     *
     * @throws RuntimeException If the user does not exist or on write failure
     */
    public function removeUser(string $userId): void;

    /**
     * Rename a user account (change the user identifier).
     *
     * @param string $oldId The current user identifier
     * @param string $newId The new user identifier
     *
     * @throws RuntimeException If oldId does not exist, newId already exists,
     *         or on write failure
     */
    public function renameUser(string $oldId, string $newId): void;

    /**
     * Update attributes of an existing user account.
     *
     * Only the attributes present in the array are updated; others are left
     * unchanged. If 'password' is included, it will be hashed before storage.
     *
     * @param string $userId The user identifier to update
     * @param array<string, mixed> $attributes Backend-specific attributes to update
     *
     * @throws RuntimeException If the user does not exist or on write failure
     */
    public function updateUser(string $userId, array $attributes): void;
}
