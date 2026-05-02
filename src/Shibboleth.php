<?php

declare(strict_types=1);

/**
 * Copyright 2006-2026 9Star Research, Inc. (http://www.protectnetwork.org/)
 * Copyright 2006-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Cassio Nishiguchi <cassio@protectnetwork.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Shibboleth transparent authentication driver.
 *
 * Extracts identity from HTTP headers set by a Shibboleth Service Provider.
 * Does not implement credential validation — the SP has already authenticated.
 */
class Shibboleth implements TransparentProvider
{
    public function __construct(
        private readonly string $usernameHeader = 'HTTP_EPPN',
        private readonly bool $stripScope = true,
    ) {}

    public function extractIdentity(ServerRequestInterface $request): ?AuthResultSuccess
    {
        $serverParams = $request->getServerParams();
        $username = $serverParams[$this->usernameHeader] ?? '';

        if ($username === '') {
            return null;
        }

        if ($this->stripScope) {
            $username = $this->removeScope($username);
        }

        return new AuthResultSuccess(
            'shibboleth',
            new DateTimeImmutable(),
            $username,
        );
    }

    private function removeScope(string $username): string
    {
        $pos = strrpos($username, '@');
        return ($pos !== false) ? substr($username, 0, $pos) : $username;
    }
}
