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

use Horde\Auth\LoginAttemptTracker;

/**
 * In-memory login attempt tracker for testing and single-process use.
 *
 * State is lost when the process ends. For production, use a persistent
 * implementation (database, cache, etc.).
 */
class InMemoryAttemptTracker implements LoginAttemptTracker
{
    /** @var array<string, int> */
    private array $failures = [];

    public function recordFailure(string $userId): void
    {
        $this->failures[$userId] = ($this->failures[$userId] ?? 0) + 1;
    }

    public function getFailureCount(string $userId): int
    {
        return $this->failures[$userId] ?? 0;
    }

    public function resetFailures(string $userId): void
    {
        unset($this->failures[$userId]);
    }
}
