<?php

declare(strict_types=1);

/**
 * Copyright 2013-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Michael J Rubinsky <mrubinsk@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

/**
 * X.509 client certificate transparent authentication driver.
 *
 * Extracts identity from a client certificate presented via TLS.
 * Reads certificate data from server params (set by the web server).
 * Optionally validates certificate purpose and subject fields.
 */
class X509 implements TransparentProvider
{
    /**
     * @param string $usernameField Server param holding the username (e.g. email from cert subject)
     * @param string $certificateField Server param holding the PEM certificate
     * @param bool $ignorePurpose Skip X509_PURPOSE check (default true for broad compat)
     * @param array<string, string> $filter Subject fields that must match (key:subkey => value)
     */
    public function __construct(
        private readonly string $usernameField = 'SSL_CLIENT_S_DN_CN',
        private readonly string $certificateField = 'SSL_CLIENT_CERT',
        private readonly bool $ignorePurpose = true,
        private readonly array $filter = [],
    ) {}

    public function extractIdentity(ServerRequestInterface $request): ?AuthResultSuccess
    {
        $serverParams = $request->getServerParams();

        $username = $serverParams[$this->usernameField] ?? '';
        $certPem = $serverParams[$this->certificateField] ?? '';

        if ($username === '' || $certPem === '') {
            return null;
        }

        if (!extension_loaded('openssl')) {
            throw new RuntimeException('ext-openssl is required for X.509 authentication');
        }

        $cert = @openssl_x509_read($certPem);
        if ($cert === false) {
            return null;
        }

        if (!$this->ignorePurpose) {
            if (!openssl_x509_checkpurpose($cert, X509_PURPOSE_SSL_CLIENT)
                && !openssl_x509_checkpurpose($cert, X509_PURPOSE_ANY)) {
                return null;
            }
        }

        $parsed = openssl_x509_parse($cert);
        if ($parsed === false) {
            return null;
        }

        if (!$this->matchesFilter($parsed)) {
            return null;
        }

        $metadata = [
            'certificate_hash' => $parsed['hash'] ?? '',
            'issuer' => $parsed['issuer'] ?? [],
            'valid_from' => $parsed['validFrom_time_t'] ?? null,
            'valid_to' => $parsed['validTo_time_t'] ?? null,
        ];

        return new AuthResultSuccess(
            'x509',
            new DateTimeImmutable(),
            $username,
            $metadata,
        );
    }

    private function matchesFilter(array $parsed): bool
    {
        foreach ($this->filter as $key => $expected) {
            $keys = explode(':', $key);
            $value = $parsed;
            foreach ($keys as $k) {
                if (!is_array($value) || !isset($value[$k])) {
                    return false;
                }
                $value = $value[$k];
            }
            if ((string) $value !== $expected) {
                return false;
            }
        }
        return true;
    }
}
