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
use RuntimeException;

/**
 * PECL SASL authentication driver.
 *
 * Validates credentials using the SASL library via the pecl-sasl extension.
 */
class Peclsasl implements CredentialProvider
{
    public function __construct(
        private readonly string $appName = 'horde',
        private readonly string $service = 'php',
    ) {}

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if ($password === '') {
            return new AuthResultFail('sasl', $timestamp, ['reason' => 'empty_password']);
        }

        if (!extension_loaded('sasl')) {
            throw new RuntimeException('ext-sasl is required for SASL authentication');
        }

        sasl_server_init($this->appName);
        $conn = sasl_server_new($this->service);

        if (!is_resource($conn)) {
            return new AuthResultFail('sasl', $timestamp, ['reason' => 'connection_failed']);
        }

        if (!sasl_checkpass($conn, $userId, $password)) {
            return new AuthResultFail('sasl', $timestamp, [
                'reason' => 'bad_credentials',
                'detail' => sasl_errdetail($conn),
            ]);
        }

        return new AuthResultSuccess('sasl', $timestamp, $userId);
    }
}
