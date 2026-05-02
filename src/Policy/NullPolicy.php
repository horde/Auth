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

/**
 * Null policy: always allows. For testing or when access policy is disabled.
 */
class NullPolicy implements AccessPolicy
{
    public function preAuth(string $userId): AccessDecision
    {
        return AccessDecision::allow();
    }

    public function postAuth(string $userId, AuthResultSuccess|AuthResultFail $result): AccessDecision
    {
        return AccessDecision::allow();
    }
}
