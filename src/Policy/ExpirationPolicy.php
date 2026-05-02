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

namespace Horde\Auth\Policy;

use DateTimeImmutable;
use Horde\Auth\AccessDecision;
use Horde\Auth\AccessPolicy;
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;

/**
 * Password expiration policy: enforces soft and hard expiration from metadata.
 *
 * Reads 'soft_expiration' and 'hard_expiration' timestamps from
 * AuthResultSuccess metadata (as set by SQL, LDAP, or other drivers).
 *
 * - Hard expiration: denies access entirely (password must be reset by admin)
 * - Soft expiration: allows access but advises 'change_password' action
 *
 * Pre-auth: always allows (expiration needs authentication result metadata).
 * Post-auth: inspects metadata on success to enforce expiration.
 */
class ExpirationPolicy implements AccessPolicy
{
    public function preAuth(string $userId): AccessDecision
    {
        return AccessDecision::allow();
    }

    public function postAuth(string $userId, AuthResultSuccess|AuthResultFail $result): AccessDecision
    {
        if ($result instanceof AuthResultFail) {
            return AccessDecision::allow();
        }

        $now = new DateTimeImmutable();

        $hardExpiration = $result->get('hard_expiration');
        if ($hardExpiration !== null) {
            $expiresAt = $this->toDateTime($hardExpiration);
            if ($expiresAt !== null && $expiresAt <= $now) {
                return AccessDecision::deny('hard_expired', [
                    'expired_at' => $expiresAt,
                ]);
            }
        }

        $softExpiration = $result->get('soft_expiration');
        if ($softExpiration !== null) {
            $expiresAt = $this->toDateTime($softExpiration);
            if ($expiresAt !== null && $expiresAt <= $now) {
                return AccessDecision::requireAction('change_password', [
                    'expired_at' => $expiresAt,
                ]);
            }
        }

        return AccessDecision::allow();
    }

    private function toDateTime(mixed $value): ?DateTimeImmutable
    {
        if ($value instanceof DateTimeImmutable) {
            return $value;
        }
        if (is_int($value)) {
            return new DateTimeImmutable('@' . $value);
        }
        if (is_string($value) && $value !== '') {
            $dt = DateTimeImmutable::createFromFormat('U', $value);
            return $dt !== false ? $dt : null;
        }
        return null;
    }
}
