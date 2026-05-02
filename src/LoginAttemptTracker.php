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

/**
 * Tracks failed login attempts for a user.
 *
 * Used by lockout policies to count consecutive failures and decide when
 * to trigger an auto-lock. Implementations range from in-memory (testing)
 * to database-backed (production).
 *
 * The counter represents consecutive failures since the last successful
 * login — a successful login resets the counter to zero.
 */
interface LoginAttemptTracker
{
    /**
     * Record a failed login attempt for a user.
     *
     * Increments the consecutive failure counter.
     *
     * @param string $userId The user who failed to authenticate
     */
    public function recordFailure(string $userId): void;

    /**
     * Get the current count of consecutive failed attempts.
     *
     * @param string $userId The user to check
     *
     * @return int Number of consecutive failures (0 = no recent failures)
     */
    public function getFailureCount(string $userId): int;

    /**
     * Reset the failure counter for a user.
     *
     * Called after a successful authentication to clear the slate.
     *
     * @param string $userId The user whose counter to reset
     */
    public function resetFailures(string $userId): void;
}
