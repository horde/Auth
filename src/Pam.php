<?php

declare(strict_types=1);

/**
 * Copyright 2004-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Jon Parise <jon@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\CredentialProvider;

/**
 * PAM authentication driver.
 *
 * Validates credentials via the system PAM service.
 * Requires the PECL pam extension.
 */
class Pam implements CredentialProvider
{
    public function __construct(
        private readonly string $service = 'php',
    ) {}

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if ($password === '') {
            return new AuthResultFail('pam', $timestamp, ['reason' => 'empty_password']);
        }

        $error = '';
        if (@pam_auth($userId, $password, $error, false)) {
            return new AuthResultSuccess('pam', $timestamp, $userId);
        }

        return new AuthResultFail('pam', $timestamp, ['reason' => 'bad_credentials', 'error' => $error]);
    }
}
