<?php
/**
 * Copyright 2017 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (LGPL). If you did
 * not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Ralf Lang <lang@b1-systems.de>
 * @category Horde
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 * @package  Auth
 */

/**
 * The Horde_Auth_Mock class provides an in-memory user list.
 *
 * It is meant to be used for throwaway setups, satellite systems or for
 * providing a source of administrative accounts in Composite or Cascading driver
 * The driver can also be used as a mock-like backend for integration tests
 *
 * @author    Ralf Lang <lang@b1-systems.de>
 * @category  Horde
 * @copyright 2017 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL-2.1
 * @package   Auth
 */
class Horde_Auth_Mock extends Horde_Auth_Base
{
    /**
     * An array of capabilities, so that the driver can report which
     * operations it supports and which it doesn't.
     *
     * @var array
     */
    protected $_capabilities = array(
        'authenticate' => true,
        'list' => true,
        'update' => true,
        'remove' => true,
        'add' => true,
    );

    /**
     * Constructor.
     *
     * @param array $params  Optional parameters:
     * <pre>
     * 'users' - (array) Usernames are hash keys, passwords are values
     * 'encryption' - (string) Optionally supply an encryption or hashing
     * 'show_encryption' - (boolean) prepend encryption info to password string
     * </pre>
     */
    public function __construct(array $params = array())
    {
        $params = array_merge(
            array(
                'encryption' => 'plain',
                'users' => array(),
                'show_encryption' => false
            ),
            $params
        );
        parent::__construct($params);
    }

    /**
     * Adds a set of authentication credentials.
     *
     * @param string $userId      The userId to add.
     * @param array $credentials  The credentials to use.
     *
     * @throws Horde_Auth_Exception
     */
    public function addUser($userId, $credentials)
    {
        // TODO: use persistence callback if given
        if ($this->exists($userId)) {
            throw new Horde_Auth_Exception('User already exists');
        }
        $this->_params['users'][$userId] = Horde_Auth::getCryptedPassword(
             $credentials['password'],
             '',
             $this->_params['encryption'],
             $this->_params['show_encryption']);
    }

    /**
     * Lists all users in the system.
     *
     * @param boolean $sort  Sort the users?
     *
     * @return mixed  The array of userIds.
     */
    public function listUsers($sort = false)
    {
        return $this->_sort(array_keys($this->_params['users']), $sort);
    }

    /**
     * Updates a set of authentication credentials for the life time of the driver.
     *
     * @param string $oldID       The old userId.
     * @param string $newID       The new userId.
     * @param array $credentials  The new credentials
     *
     * @throws Horde_Auth_Exception
     */
    public function updateUser($oldID, $newID, $credentials)
    {
        if (!$this->exists($oldID)) {
            throw new Horde_Auth_Exception('User does not exist');
        }
        if ($this->exists($newID) && $newID != $oldID) {
            throw new Horde_Auth_Exception('Cannot rename to existing user name');
        }
        $this->removeUser($oldID);
        $this->addUser($newID, $credentials);
    }

    /**
     * Deletes a set of authentication credentials for the life of the driver.
     *
     * @param string $userId  The userId to delete.
     */
    public function removeUser($userId)
    {
        // TODO: use persistence callback if given
        unset($this->_params['users'][$userId]);
    }

    /**
     * Authenticate.
     *
     * @param string $userId      The userID to check.
     * @param array $credentials  An array of login credentials.
     *
     * @throws Horde_Auth_Exception
     */
    protected function _authenticate($userId, $credentials)
    {
        if (!$this->exists($userId) || 
            !$this->_comparePasswords(
                $this->_params['users'][$userId],
                $credentials['password']
            )) {
            throw new Horde_Auth_Exception('', Horde_Auth::REASON_BADLOGIN);
        }
        return;
    }

    /**
     * Compare an encrypted password to a plaintext string to see if
     * they match.
     *
     * @param string $encrypted  The crypted password to compare against.
     * @param string $plaintext  The plaintext password to verify.
     *
     * @return boolean  True if matched, false otherwise.
     */
    protected function _comparePasswords($encrypted, $plaintext)
    {
        return $encrypted == Horde_Auth::getCryptedPassword(
            $plaintext,
            $encrypted,
            $this->_params['encryption'],
            $this->_params['show_encryption']);
    }

}
