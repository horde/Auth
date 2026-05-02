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
 * Password change and reset operations.
 *
 * Separated from CredentialProvider because not all backends that can
 * validate credentials can also manage passwords (IMAP, Radius, PAM
 * validate but don't expose password management).
 */
interface PasswordManager
{
    /**
     * Change a user's password after verifying the old password.
     *
     * This is the user-facing operation: the caller must supply the current
     * password for verification. Use resetPassword() for admin/flow-driven
     * resets that bypass old-password verification.
     *
     * @param string $userId The user identifier
     * @param string $oldPassword The current password (for verification)
     * @param string $newPassword The desired new password
     *
     * @throws RuntimeException If the old password is incorrect, the user does
     *         not exist, or on infrastructure failure
     */
    public function changePassword(string $userId, string $oldPassword, string $newPassword): void;

    /**
     * Reset a user's password to a random value without requiring the old one.
     *
     * This is the admin/flow-driven operation (e.g. "forgot password" flow).
     * The generated password is returned so it can be communicated to the user
     * through a secure channel.
     *
     * @param string $userId The user identifier
     *
     * @return string The newly generated random password
     *
     * @throws RuntimeException If the user does not exist or on infrastructure
     *         failure
     */
    public function resetPassword(string $userId): string;
}
