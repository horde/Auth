<?php

declare(strict_types=1);

/**
 * Copyright 2002-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Michael Slusarz <slusarz@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;
use RuntimeException;

/**
 * RADIUS authentication driver.
 *
 * Validates credentials against a RADIUS server using the pecl-radius extension.
 * Currently supports PAP authentication only.
 */
class Radius implements CredentialProvider
{
    public function __construct(
        private readonly string $host,
        private readonly string $secret,
        private readonly int $port = 0,
        private readonly int $timeout = 3,
        private readonly int $retries = 3,
        private readonly string $nas = '',
        private readonly string $suffix = '',
    ) {}

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if ($password === '') {
            return new AuthResultFail('radius', $timestamp, ['reason' => 'empty_password']);
        }

        if (!extension_loaded('radius')) {
            throw new RuntimeException('ext-radius is required for RADIUS authentication');
        }

        if ($this->suffix !== '' && !str_contains($userId, '@')) {
            $userId .= '@' . $this->suffix;
        }

        $nas = $this->nas !== '' ? $this->nas : ($_SERVER['HTTP_HOST'] ?? 'localhost');

        $res = radius_auth_open();
        radius_add_server($res, $this->host, $this->port, $this->secret, $this->timeout, $this->retries);
        radius_create_request($res, RADIUS_ACCESS_REQUEST);
        radius_put_attr($res, RADIUS_NAS_IDENTIFIER, $nas);
        radius_put_attr($res, RADIUS_NAS_PORT_TYPE, RADIUS_VIRTUAL);
        radius_put_attr($res, RADIUS_SERVICE_TYPE, RADIUS_FRAMED);
        radius_put_attr($res, RADIUS_FRAMED_PROTOCOL, RADIUS_PPP);
        radius_put_attr($res, RADIUS_USER_NAME, $userId);
        radius_put_attr($res, RADIUS_USER_PASSWORD, $password);

        $result = radius_send_request($res);

        if ($result === RADIUS_ACCESS_ACCEPT) {
            return new AuthResultSuccess('radius', $timestamp, $userId);
        }

        $reason = ($result === RADIUS_ACCESS_REJECT) ? 'rejected' : 'error';
        return new AuthResultFail('radius', $timestamp, [
            'reason' => $reason,
            'detail' => radius_strerror($res),
        ]);
    }
}
