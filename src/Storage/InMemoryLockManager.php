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

namespace Horde\Auth\Storage;

use DateTimeImmutable;
use Horde\Auth\LockManager;

/**
 * In-memory lock manager for testing and single-process use.
 *
 * Locks are lost when the process ends. For production, use a persistent
 * implementation (database, Horde_Lock adapter, etc.).
 */
class InMemoryLockManager implements LockManager
{
    /** @var array<string, array{locked_at: DateTimeImmutable, duration: int}> */
    private array $locks = [];

    public function lock(string $userId, int $duration = 0): void
    {
        $this->locks[$userId] = [
            'locked_at' => new DateTimeImmutable(),
            'duration' => $duration,
        ];
    }

    public function unlock(string $userId): void
    {
        unset($this->locks[$userId]);
    }

    public function isLocked(string $userId): bool
    {
        return $this->getLockInfo($userId) !== null;
    }

    public function getLockInfo(string $userId): ?array
    {
        if (!isset($this->locks[$userId])) {
            return null;
        }

        $lock = $this->locks[$userId];
        $lockedAt = $lock['locked_at'];
        $duration = $lock['duration'];

        if ($duration > 0) {
            $expiresAt = $lockedAt->modify("+{$duration} seconds");
            if ($expiresAt <= new DateTimeImmutable()) {
                unset($this->locks[$userId]);
                return null;
            }
            return ['locked_at' => $lockedAt, 'expires_at' => $expiresAt];
        }

        return ['locked_at' => $lockedAt, 'expires_at' => null];
    }
}
