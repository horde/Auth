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

namespace Horde\Auth\Policy;

use Horde\Auth\AccessDecision;
use Horde\Auth\AccessPolicy;
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\LockManager;
use Horde\Auth\LoginAttemptTracker;

/**
 * Lockout policy: blocks locked accounts and auto-locks after too many failures.
 *
 * Pre-auth: denies if the account is locked.
 * Post-auth: on failure, records the attempt and auto-locks when the threshold
 * is reached. On success, resets the failure counter.
 */
class LockoutPolicy implements AccessPolicy
{
    public function __construct(
        private readonly LoginAttemptTracker $tracker,
        private readonly LockManager $lockManager,
        private readonly int $maxAttempts = 5,
        private readonly int $lockDuration = 900,
    ) {}

    public function preAuth(string $userId): AccessDecision
    {
        $lockInfo = $this->lockManager->getLockInfo($userId);
        if ($lockInfo !== null) {
            return AccessDecision::deny('locked', $lockInfo);
        }

        return AccessDecision::allow();
    }

    public function postAuth(string $userId, AuthResultSuccess|AuthResultFail $result): AccessDecision
    {
        if ($result instanceof AuthResultSuccess) {
            $this->tracker->resetFailures($userId);
            return AccessDecision::allow();
        }

        $this->tracker->recordFailure($userId);
        $count = $this->tracker->getFailureCount($userId);

        if ($this->maxAttempts > 0 && $count >= $this->maxAttempts) {
            $this->lockManager->lock($userId, $this->lockDuration);
            return AccessDecision::deny('locked', [
                'reason' => 'max_attempts_exceeded',
                'attempts' => $count,
            ]);
        }

        return AccessDecision::allow();
    }
}
