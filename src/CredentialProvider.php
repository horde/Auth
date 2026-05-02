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

use RuntimeException;

/**
 * Validates credentials against a backend.
 *
 * A CredentialProvider accepts user-supplied credentials (username + password
 * or equivalent) and reports whether the backend considers them valid.
 *
 * It has no knowledge of Identity, sessions, or access policy.
 * The caller decides what to do with the result.
 *
 * Never throws for authentication failures (wrong password, unknown user).
 * Exceptions are reserved for infrastructure failures (backend unreachable,
 * misconfigured, etc.)
 */
interface CredentialProvider
{
    /**
     * Validate user-supplied credentials against the backend.
     *
     * Never throws for authentication failures (wrong password, unknown user).
     * Returns AuthResultFail in those cases. Exceptions are reserved for
     * infrastructure failures (backend unreachable, misconfigured, etc.)
     *
     * @param string $userId User identifier as presented by the user
     * @param array<string, mixed> $credentials Backend-specific credential data;
     *        at minimum ['password' => string]. Some backends accept additional
     *        keys (e.g. 'domain', 'otp').
     *
     * @return AuthResultSuccess|AuthResultFail Success carries the native key
     *         and optional metadata; Fail carries the reason code.
     *
     * @throws RuntimeException On infrastructure failure (backend unreachable,
     *         misconfigured, required extension missing)
     */
    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail;
}
