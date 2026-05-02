<?php

declare(strict_types=1);

/**
 * Copyright 2004-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Jan Schneider <jan@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;

/**
 * System login (su) authentication driver.
 *
 * Validates credentials by piping the password to `su -c /bin/true $user`.
 * Useful for shadow password systems where the Passwd driver can't read hashes.
 */
class Login implements CredentialProvider
{
    public function __construct(
        private readonly string $suPath = '/bin/su',
        private readonly string $allowedUserRegex = '/^[a-zA-Z0-9._-]+$/',
        private readonly int $passwordLengthLimit = 2048,
    ) {}

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if ($password === '') {
            return new AuthResultFail('login', $timestamp, ['reason' => 'empty_password']);
        }

        if (strlen($password) > $this->passwordLengthLimit) {
            return new AuthResultFail('login', $timestamp, ['reason' => 'password_too_long']);
        }

        if (!preg_match($this->allowedUserRegex, $userId)) {
            return new AuthResultFail('login', $timestamp, ['reason' => 'invalid_username']);
        }

        $proc = @popen($this->suPath . ' -c /bin/true ' . escapeshellarg($userId), 'w');
        if (!is_resource($proc)) {
            return new AuthResultFail('login', $timestamp, ['reason' => 'process_failed']);
        }

        fwrite($proc, $password);
        $exitCode = @pclose($proc);

        if ($exitCode !== 0) {
            return new AuthResultFail('login', $timestamp, ['reason' => 'bad_credentials']);
        }

        return new AuthResultSuccess('login', $timestamp, $userId);
    }
}
