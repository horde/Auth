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
 * Base class for authentication results.
 *
 * Carries the backend identifier and timestamp common to both
 * success and failure outcomes.
 */
abstract class AuthResult
{
    public function __construct(
        private readonly string $backend,
        private readonly DateTimeImmutable $timestamp,
    ) {}

    public function getBackend(): string
    {
        return $this->backend;
    }

    public function getTimestamp(): DateTimeImmutable
    {
        return $this->timestamp;
    }
}
