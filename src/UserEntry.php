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
 * A user record returned by a UserDirectory.
 *
 * Carries backend provenance so callers can distinguish "hugo from SQL"
 * from "hugo from LDAP" in multi-backend scenarios.
 */
class UserEntry
{
    /**
     * @param string $userId The user identifier in this backend
     * @param string $backend Identifier of the backend this entry came from
     * @param array<string, mixed> $attributes Backend-specific attributes (bag-like)
     */
    public function __construct(
        private readonly string $userId,
        private readonly string $backend,
        private readonly array $attributes = [],
    ) {}

    public function getUserId(): string
    {
        return $this->userId;
    }

    public function getBackend(): string
    {
        return $this->backend;
    }

    /**
     * @return array<string, mixed>
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->attributes[$key] ?? $default;
    }
}
