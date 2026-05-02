<?php

declare(strict_types=1);

/**
 * Copyright 1999-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Chuck Hagenbuch <chuck@horde.org>
 * @author   Max Kalika <max@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;
use RuntimeException;

/**
 * FTP authentication driver.
 *
 * Validates credentials by attempting an FTP login to a configured server.
 */
class Ftp implements CredentialProvider
{
    public function __construct(
        private readonly string $host = 'localhost',
        private readonly int $port = 21,
        private readonly int $timeout = 10,
    ) {}

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if ($password === '') {
            return new AuthResultFail('ftp', $timestamp, ['reason' => 'empty_password']);
        }

        if (!extension_loaded('ftp')) {
            throw new RuntimeException('ext-ftp is required for FTP authentication');
        }

        $ftp = @ftp_connect($this->host, $this->port, $this->timeout);
        if ($ftp === false) {
            return new AuthResultFail('ftp', $timestamp, ['reason' => 'connection_failed']);
        }

        $result = @ftp_login($ftp, $userId, $password);
        @ftp_quit($ftp);

        if (!$result) {
            return new AuthResultFail('ftp', $timestamp, ['reason' => 'bad_credentials']);
        }

        return new AuthResultSuccess('ftp', $timestamp, $userId);
    }
}
