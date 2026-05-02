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
 * Compound policy: chains multiple AccessPolicy implementations in order.
 *
 * For both preAuth and postAuth:
 * - First deny wins (short-circuits remaining policies)
 * - If no deny, first requireAction wins
 * - If neither, returns allow
 */
class CompoundPolicy implements AccessPolicy
{
    /** @var list<AccessPolicy> */
    private readonly array $policies;

    public function __construct(AccessPolicy ...$policies)
    {
        $this->policies = $policies;
    }

    public function preAuth(string $userId): AccessDecision
    {
        $advisory = null;

        foreach ($this->policies as $policy) {
            $decision = $policy->preAuth($userId);
            if ($decision->isDenied()) {
                return $decision;
            }
            if ($decision->requiresAction() && $advisory === null) {
                $advisory = $decision;
            }
        }

        return $advisory ?? AccessDecision::allow();
    }

    public function postAuth(string $userId, AuthResultSuccess|AuthResultFail $result): AccessDecision
    {
        $advisory = null;

        foreach ($this->policies as $policy) {
            $decision = $policy->postAuth($userId, $result);
            if ($decision->isDenied()) {
                return $decision;
            }
            if ($decision->requiresAction() && $advisory === null) {
                $advisory = $decision;
            }
        }

        return $advisory ?? AccessDecision::allow();
    }
}
