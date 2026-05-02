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
 * Failed credential validation result.
 *
 * Carries whatever the backend chooses to disclose about why
 * validation failed. For composite/federated providers, metadata
 * may include sub-results from each attempted backend.
 */
class AuthResultFail extends AuthResult
{
    /**
     * @param string $backend Identifier of the backend that produced this result
     * @param DateTimeImmutable $timestamp When the validation occurred
     * @param array<string, mixed> $metadata Backend-disclosed failure details (bag-like)
     */
    public function __construct(
        string $backend,
        DateTimeImmutable $timestamp,
        private readonly array $metadata = [],
    ) {
        parent::__construct($backend, $timestamp);
    }

    /**
     * @return array<string, mixed>
     */
    public function getMetadata(): array
    {
        return $this->metadata;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->metadata[$key] ?? $default;
    }
}
