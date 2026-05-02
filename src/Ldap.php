<?php

declare(strict_types=1);

/**
 * Copyright 1999-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Jon Parise <jon@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;
use Horde_Ldap;
use Horde_Ldap_Exception;
use Horde_Ldap_Filter;
use Horde_Ldap_Search;
use RuntimeException;

/**
 * Read-only LDAP authentication driver.
 *
 * Validates credentials by binding as the user and provides user directory
 * operations (exists, list, search). Does not modify the directory.
 *
 * For write operations (add/remove/rename users, password management),
 * use WritableLdap.
 */
class Ldap implements CredentialProvider, UserDirectory
{
    /**
     * @param Horde_Ldap $ldap Connected LDAP client (bound as service account)
     * @param string $baseDn Base DN for user searches
     * @param string $uidAttribute LDAP attribute containing the username
     * @param array<string> $objectClass objectClass filter for user entries
     * @param bool $activeDirectory Whether this is an Active Directory backend
     * @param string|null $filter Custom LDAP filter string (overrides objectClass filter)
     * @param string $backend Backend identifier for result objects
     */
    public function __construct(
        protected readonly Horde_Ldap $ldap,
        protected readonly string $baseDn,
        protected readonly string $uidAttribute = 'uid',
        protected readonly array $objectClass = ['posixAccount'],
        protected readonly bool $activeDirectory = false,
        protected readonly ?string $filter = null,
        protected readonly string $backend = 'ldap',
    ) {}

    public function validate(string $userId, array $credentials): AuthResultSuccess|AuthResultFail
    {
        $timestamp = new DateTimeImmutable();
        $password = $credentials['password'] ?? '';

        if ($password === '') {
            return new AuthResultFail($this->backend, $timestamp, ['reason' => 'empty_password']);
        }

        try {
            $dn = $this->findUserDn($userId);
        } catch (RuntimeException) {
            return new AuthResultFail($this->backend, $timestamp, ['reason' => 'unknown_user']);
        }

        try {
            $this->ldap->bind($dn, $password);
            $this->rebindAsService();
        } catch (Horde_Ldap_Exception $e) {
            $this->rebindAsService();
            return new AuthResultFail($this->backend, $timestamp, [
                'reason' => 'bad_credentials',
                'ldap_error' => $e->getMessage(),
            ]);
        }

        $metadata = ['dn' => $dn];
        try {
            $entry = $this->ldap->getEntry($dn);
            $attrs = $entry->getValues();
            if (isset($attrs['mail'])) {
                $metadata['mail'] = is_array($attrs['mail']) ? $attrs['mail'][0] : $attrs['mail'];
            }
            if (isset($attrs['shadowLastChange'])) {
                $metadata['shadowLastChange'] = $attrs['shadowLastChange'];
            }
            if (isset($attrs['shadowMax'])) {
                $metadata['shadowMax'] = $attrs['shadowMax'];
            }
            if (isset($attrs['shadowWarning'])) {
                $metadata['shadowWarning'] = $attrs['shadowWarning'];
            }
        } catch (Horde_Ldap_Exception) {
            // Non-critical — metadata is optional
        }

        return new AuthResultSuccess($this->backend, $timestamp, $dn, $metadata);
    }

    public function exists(string $userId): bool
    {
        try {
            $this->findUserDn($userId);
            return true;
        } catch (RuntimeException) {
            return false;
        }
    }

    public function list(): iterable
    {
        $filter = $this->buildUserFilter();
        $search = $this->ldap->search($this->baseDn, $filter, ['attributes' => [$this->uidAttribute, 'mail', 'cn']]);

        foreach ($search as $entry) {
            $attrs = $entry->getValues();
            $uid = is_array($attrs[$this->uidAttribute] ?? null)
                ? ($attrs[$this->uidAttribute][0] ?? '')
                : ($attrs[$this->uidAttribute] ?? '');

            if ($uid === '') {
                continue;
            }

            yield new UserEntry($uid, $this->backend, $this->normalizeAttributes($attrs));
        }
    }

    public function search(string $query): iterable
    {
        $userFilter = $this->buildUserFilter();
        $searchFilter = Horde_Ldap_Filter::create($this->uidAttribute, 'contains', $query);
        $combined = Horde_Ldap_Filter::combine('and', [$userFilter, $searchFilter]);

        $search = $this->ldap->search($this->baseDn, $combined, ['attributes' => [$this->uidAttribute, 'mail', 'cn']]);

        foreach ($search as $entry) {
            $attrs = $entry->getValues();
            $uid = is_array($attrs[$this->uidAttribute] ?? null)
                ? ($attrs[$this->uidAttribute][0] ?? '')
                : ($attrs[$this->uidAttribute] ?? '');

            if ($uid === '') {
                continue;
            }

            yield new UserEntry($uid, $this->backend, $this->normalizeAttributes($attrs));
        }
    }

    /**
     * Find the DN for a given userId.
     *
     * @throws RuntimeException If user not found
     */
    protected function findUserDn(string $userId): string
    {
        $filter = Horde_Ldap_Filter::combine('and', [
            $this->buildUserFilter(),
            Horde_Ldap_Filter::create($this->uidAttribute, 'equals', $userId),
        ]);

        $search = $this->ldap->search($this->baseDn, $filter, ['attributes' => ['dn']]);

        if ($search->count() === 0) {
            throw new RuntimeException("User '$userId' not found in LDAP");
        }

        return $search->current()->dn();
    }

    /**
     * Build the LDAP filter for finding user entries.
     */
    protected function buildUserFilter(): Horde_Ldap_Filter
    {
        if ($this->filter !== null) {
            return Horde_Ldap_Filter::parse($this->filter);
        }

        $filters = [];
        foreach ($this->objectClass as $oc) {
            $filters[] = Horde_Ldap_Filter::create('objectClass', 'equals', $oc);
        }

        return count($filters) === 1 ? $filters[0] : Horde_Ldap_Filter::combine('and', $filters);
    }

    /**
     * Rebind as the service account after a user bind.
     */
    protected function rebindAsService(): void
    {
        try {
            $this->ldap->bind();
        } catch (Horde_Ldap_Exception) {
            // Best-effort rebind
        }
    }

    /**
     * Normalize multi-valued LDAP attributes to single values.
     *
     * @return array<string, string>
     */
    protected function normalizeAttributes(array $attrs): array
    {
        $normalized = [];
        foreach ($attrs as $key => $value) {
            if ($key === $this->uidAttribute || $key === 'userPassword') {
                continue;
            }
            $normalized[$key] = is_array($value) ? ($value[0] ?? '') : $value;
        }
        return $normalized;
    }
}
