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
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\TransparentProvider;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Automatic transparent authentication driver.
 *
 * Asserts a configured identity for every request. Useful for
 * development/testing or firewall-protected environments.
 */
class Auto implements TransparentProvider
{
    public function __construct(
        private readonly string $username = 'horde_user',
        private readonly bool $allowRequestUser = false,
    ) {}

    public function extractIdentity(ServerRequestInterface $request): ?AuthResultSuccess
    {
        $userId = $this->username;

        if ($this->allowRequestUser) {
            $params = $request->getQueryParams();
            $body = $request->getParsedBody();
            $cookies = $request->getCookieParams();

            $userId = $params['username']
                ?? (is_array($body) ? ($body['username'] ?? null) : null)
                ?? $cookies['username']
                ?? $this->username;
        }

        return new AuthResultSuccess(
            backend: 'auto',
            timestamp: new DateTimeImmutable(),
            nativeKey: $userId,
        );
    }
}
