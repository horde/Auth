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
use RuntimeException;

use function err2str;
use function validate;

/**
 * SMB authentication driver (smbauth extension).
 *
 * Validates credentials against a Windows domain using the smbauth PECL extension.
 */
class Smb implements CredentialProvider
{
    public function __construct(
        private readonly string $hostspec,
        private readonly string $domain,
        private readonly string $group = '',
    ) {}

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if ($password === '') {
            return new AuthResultFail('smb', $timestamp, ['reason' => 'empty_password']);
        }

        if (!extension_loaded('smbauth')) {
            throw new RuntimeException('ext-smbauth is required for SMB authentication');
        }

        /** @noinspection PhpUndefinedFunctionInspection */
        $rval = validate($this->hostspec, $this->domain, $this->group, $userId, $password);

        if ($rval === 0) {
            return new AuthResultSuccess('smb', $timestamp, $userId);
        }

        if ($rval === 1) {
            return new AuthResultFail('smb', $timestamp, ['reason' => 'connection_failed']);
        }

        /** @noinspection PhpUndefinedFunctionInspection */
        return new AuthResultFail('smb', $timestamp, [
            'reason' => 'bad_credentials',
            'detail' => err2str(),
        ]);
    }
}
