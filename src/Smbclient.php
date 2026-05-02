<?php

declare(strict_types=1);

/**
 * Copyright 1999-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Jon Parise <jon@horde.org>
 * @author   Marcus I. Ryan <marcus@riboflavin.net>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;

/**
 * SMB authentication driver (smbclient binary).
 *
 * Validates credentials by invoking the smbclient command-line tool
 * to list shares on the target host.
 */
class Smbclient implements CredentialProvider
{
    public function __construct(
        private readonly string $hostspec,
        private readonly string $domain,
        private readonly string $smbclientPath = '/usr/bin/smbclient',
    ) {}

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if ($password === '') {
            return new AuthResultFail('smbclient', $timestamp, ['reason' => 'empty_password']);
        }

        $cmd = implode(' ', [
            escapeshellarg($this->smbclientPath),
            '-L',
            escapeshellarg($this->hostspec),
            '-W',
            escapeshellarg($this->domain),
            '-U',
            escapeshellarg($userId),
        ]);

        $proc = @popen($cmd, 'w');
        if ($proc === false) {
            return new AuthResultFail('smbclient', $timestamp, ['reason' => 'process_failed']);
        }

        fwrite($proc, $password);
        $exitCode = @pclose($proc);

        if (($exitCode & 0xff) !== 0) {
            return new AuthResultFail('smbclient', $timestamp, ['reason' => 'bad_credentials']);
        }

        return new AuthResultSuccess('smbclient', $timestamp, $userId);
    }
}
