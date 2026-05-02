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

use Horde_Ldap;
use Horde_Ldap_Exception;
use RuntimeException;

/**
 * Writable LDAP authentication driver.
 *
 * Extends the read-only Ldap driver with user lifecycle and password
 * management. Creates, removes, renames, and updates LDAP entries
 * under the configured base DN.
 *
 * Not available in Active Directory mode (use AD-specific tooling for
 * account lifecycle there).
 */
class WritableLdap extends Ldap implements UserLifecycleManager, PasswordManager
{
    private readonly string $encryption;

    /**
     * @param Horde_Ldap $ldap Connected LDAP client (bound as service account with write access)
     * @param string $baseDn Base DN for user entries
     * @param string $uidAttribute LDAP attribute containing the username
     * @param array<string> $objectClass objectClass values for new user entries
     * @param string $encryption Password hashing scheme (e.g. 'ssha', 'sha', 'md5', 'crypt')
     * @param bool $activeDirectory Whether this is an Active Directory backend
     * @param string|null $filter Custom LDAP filter string
     * @param string $backend Backend identifier for result objects
     */
    public function __construct(
        Horde_Ldap $ldap,
        string $baseDn,
        string $uidAttribute = 'uid',
        array $objectClass = ['posixAccount'],
        string $encryption = 'ssha',
        bool $activeDirectory = false,
        ?string $filter = null,
        string $backend = 'ldap',
    ) {
        if ($activeDirectory) {
            throw new RuntimeException(
                'WritableLdap does not support Active Directory — use AD-specific tooling'
            );
        }

        $this->encryption = $encryption;

        parent::__construct($ldap, $baseDn, $uidAttribute, $objectClass, $activeDirectory, $filter, $backend);
    }

    public function addUser(string $userId, array $attributes = []): UserEntry
    {
        $password = $attributes['password'] ?? '';
        $hashedPassword = PasswordUtility::crypt($password, $this->encryption, '', true);

        $entryAttrs = [
            $this->uidAttribute => $userId,
            'userPassword' => $hashedPassword,
            'objectClass' => $this->objectClass,
            'cn' => $attributes['cn'] ?? $userId,
        ];

        if (isset($attributes['sn'])) {
            $entryAttrs['sn'] = $attributes['sn'];
        }

        $dn = $this->uidAttribute . '=' . $userId . ',' . $this->baseDn;
        $entry = Horde_Ldap::createEntry($dn, $entryAttrs);
        $this->ldap->add($entry);

        return new UserEntry($userId, $this->backend, array_diff_key($attributes, ['password' => true]));
    }

    public function removeUser(string $userId): void
    {
        $dn = $this->findUserDn($userId);
        $this->ldap->delete($dn);
    }

    public function renameUser(string $oldId, string $newId): void
    {
        $dn = $this->findUserDn($oldId);
        $newRdn = $this->uidAttribute . '=' . $newId;
        $this->ldap->move($dn, $newRdn . ',' . $this->baseDn);
    }

    public function updateUser(string $userId, array $attributes): void
    {
        $dn = $this->findUserDn($userId);
        $entry = $this->ldap->getEntry($dn);

        if (isset($attributes['password'])) {
            $entry->replace([
                'userPassword' => PasswordUtility::crypt($attributes['password'], $this->encryption, '', true),
            ]);
            unset($attributes['password']);
        }

        foreach ($attributes as $key => $value) {
            $entry->replace([$key => $value]);
        }

        $entry->update();
    }

    public function changePassword(string $userId, string $oldPassword, string $newPassword): void
    {
        $result = $this->validate($userId, ['password' => $oldPassword]);
        if ($result instanceof AuthResultFail) {
            throw new RuntimeException('Old password is incorrect');
        }

        $this->updateUser($userId, ['password' => $newPassword]);
    }

    public function resetPassword(string $userId): string
    {
        if (!$this->exists($userId)) {
            throw new RuntimeException("User '$userId' not found");
        }

        $newPassword = PasswordUtility::generateRandom();
        $this->updateUser($userId, ['password' => $newPassword]);

        return $newPassword;
    }
}
