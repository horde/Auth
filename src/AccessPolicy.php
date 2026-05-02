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
 * Access control policy for authentication flows.
 *
 * An AccessPolicy wraps the authentication process with pre- and post-checks
 * that enforce concerns orthogonal to credential validation itself: account
 * lockout, password expiration, rate limiting, IP restrictions, etc.
 *
 * Policies do not validate credentials — that is the CredentialProvider's job.
 * Instead, they gate access before and inspect results after validation.
 *
 * Typical caller flow:
 *
 *     $decision = $policy->preAuth($userId);
 *     if ($decision->isDenied()) { return $decision; }
 *
 *     $result = $driver->validate($userId, $credentials);
 *
 *     $decision = $policy->postAuth($userId, $result);
 *     // handle deny or requireAction
 */
interface AccessPolicy
{
    /**
     * Pre-authentication check, called before credential validation.
     *
     * Use this to deny access early when the account state makes validation
     * pointless (locked, banned, disabled) or to enforce rate limits.
     *
     * @param string $userId The user identifier about to be authenticated
     *
     * @return AccessDecision Allow to proceed with validation, or deny to
     *         short-circuit the flow entirely.
     */
    public function preAuth(string $userId): AccessDecision;

    /**
     * Post-authentication check, called after credential validation.
     *
     * Use this to record login attempts, enforce password expiration, trigger
     * auto-lockout after too many failures, or attach advisories (e.g.
     * "password change required").
     *
     * @param string $userId The user identifier that was authenticated
     * @param AuthResultSuccess|AuthResultFail $result The credential validation result
     *
     * @return AccessDecision Allow to proceed, deny to block despite valid
     *         credentials (hard expiration), or requireAction to advise the
     *         caller of a needed step (soft expiration → change password).
     */
    public function postAuth(string $userId, AuthResultSuccess|AuthResultFail $result): AccessDecision;
}
