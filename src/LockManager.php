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

/**
 * Manages account-level locks (independent of authentication backend).
 *
 * Locks prevent authentication attempts from reaching the credential
 * provider. They can be time-limited (auto-expire after a duration) or
 * permanent (require explicit admin unlock).
 *
 * Implementations range from in-memory (testing) to database or
 * distributed-lock backends (production).
 */
interface LockManager
{
    /**
     * Lock a user account.
     *
     * If the user is already locked, the lock is replaced with the new
     * duration (effectively extending or shortening it).
     *
     * @param string $userId The user to lock
     * @param int $duration Seconds until auto-unlock (0 = permanent lock)
     */
    public function lock(string $userId, int $duration = 0): void;

    /**
     * Unlock a user account.
     *
     * No-op if the user is not currently locked.
     *
     * @param string $userId The user to unlock
     */
    public function unlock(string $userId): void;

    /**
     * Check whether a user account is currently locked.
     *
     * Time-limited locks that have expired return false.
     *
     * @param string $userId The user to check
     *
     * @return bool True if the account is currently locked
     */
    public function isLocked(string $userId): bool;

    /**
     * Get detailed lock information for a user.
     *
     * Returns null if the user is not locked (including expired locks).
     *
     * @param string $userId The user to query
     *
     * @return array{locked_at: DateTimeImmutable, expires_at: ?DateTimeImmutable}|null
     *         Lock details, or null if not locked. expires_at is null for
     *         permanent locks.
     */
    public function getLockInfo(string $userId): ?array;
}
