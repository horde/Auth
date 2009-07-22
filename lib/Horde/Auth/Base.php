<?php
/**
 * The Horde_Auth_Base:: class provides a common abstracted interface to
 * creating various authentication backends.
 *
 * Copyright 1999-2009 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (LGPL). If you did
 * not receive this file, see http://opensource.org/licenses/lgpl-2.1.php
 *
 * @author  Chuck Hagenbuch <chuck@horde.org>
 * @author  Michael Slusarz <slusarz@curecanti.org>
 * @package Horde_Auth
 */
abstract class Horde_Auth_Base
{
    /**
     * An array of capabilities, so that the driver can report which
     * operations it supports and which it doesn't.
     *
     * @var array
     */
    protected $_capabilities = array(
        'add'           => false,
        'authenticate'  => true,
        'groups'        => false,
        'list'          => false,
        'resetpassword' => false,
        'remove'        => false,
        'transparent'   => false,
        'update'        => false
    );

    /**
     * Hash containing parameters needed for the drivers.
     *
     * @var array
     */
    protected $_params = array();

    /**
     * The credentials currently being authenticated.
     *
     * @var array
     */
    protected $_credentials = array();

    /**
     * Constructor.
     *
     * @param array $params  A hash containing parameters.
     */
    public function __construct($params = array())
    {
        $this->_params = $params;
    }

    /**
     * Finds out if a set of login credentials are valid, and if requested,
     * mark the user as logged in in the current session.
     *
     * @param string $userId      The userId to check.
     * @param array $credentials  The credentials to check.
     * @param boolean $login      Whether to log the user in. If false, we'll
     *                            only test the credentials and won't modify
     *                            the current session. Defaults to true.
     *
     * @return boolean  Whether or not the credentials are valid.
     */
    public function authenticate($userId, $credentials, $login = true)
    {
        $auth = false;
        $userId = trim($userId);

        if (!empty($GLOBALS['conf']['hooks']['preauthenticate'])) {
            if (!Horde::callHook('_horde_hook_preauthenticate', array($userId, $credentials), 'horde')) {
                if (Horde_Auth::getAuthError() != Horde_Auth::REASON_MESSAGE) {
                    Horde_Auth::setAuthError(Horde_Auth::REASON_FAILED);
                }
                return $auth;
            }
        }

        /* Store the credentials being checked so that subclasses can modify
         * them if necessary. */
        $this->_credentials = array(
            'credentials' => $credentials,
            'params' => array('change' => false),
            'userId' => $userId
        );

        try {
            $this->_authenticate($userId, $credentials);

            if ($login) {
                $auth = Horde_Auth::setAuth(
                    $this->_credentials['userId'],
                    $this->_credentials['credentials'],
                    $this->_credentials['params']
                );
            } else {
                $auth = Horde_Auth::checkExistingAuth();
            }
        } catch (Horde_Auth_Exception $e) {
            if ($e->getCode()) {
                Horde_Auth::setAuthError($e->getCode());
            } else {
                Horde_Auth::setAuthError(Horde_Auth::REASON_MESSAGE, $e->getMessage());
            }
        }

        return $auth;
    }

    /**
     * Authentication stub.
     *
     * On failure, Horde_Auth_Exception should pass a message string (if any)
     * in the message field, and the Horde_Auth::REASON_* constant in the code
     * field (defaults to Horde_Auth::REASON_MESSAGE).
     *
     * @param string $userID      The userID to check.
     * @param array $credentials  An array of login credentials.
     *
     * @throws Horde_Auth_Exception
     */
    abstract protected function _authenticate($userId, $credentials);

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
        throw new Horde_Auth_Exception('unsupported');
    }

    /**
     * Updates a set of authentication credentials.
     *
     * @param string $oldID       The old userId.
     * @param string $newID       The new userId.
     * @param array $credentials  The new credentials
     *
     * @throws Horde_Auth_Exception
     */
    public function updateUser($oldID, $newID, $credentials)
    {
        throw new Horde_Auth_Exception('unsupported');
    }

    /**
     * Deletes a set of authentication credentials.
     *
     * @param string $userId  The userId to delete.
     *
     * @throws Horde_Auth_Exception
     */
    public function removeUser($userId)
    {
        throw new Horde_Auth_Exception('unsupported');
    }

    /**
     * Lists all users in the system.
     *
     * @return mixed  The array of userIds.
     * @throws Horde_Auth_Exception
     */
    public function listUsers()
    {
        throw new Horde_Auth_Exception('unsupported');
    }

    /**
     * Checks if $userId exists in the system.
     *
     * @param string $userId  User ID for which to check
     *
     * @return boolean  Whether or not $userId already exists.
     */
    public function exists($userId)
    {
        try {
            $users = $this->listUsers();
            return in_array($userId, $users);
        } catch (Horde_Auth_Exception $e) {
            return false;
        }
    }

    /**
     * Automatic authentication.
     *
     * @return boolean  Whether or not the client is allowed.
     * @throws Horde_Auth_Exception
     */
    public function transparent()
    {
        /* Reset the credentials being checked so that subclasses can modify
         * them if necessary. */
        $this->_credentials = array(
            'credentials' => array(),
            'params' => array('change' => false),
            'userId' => ''
        );

        if ($this->_transparent()) {
            return Horde_Auth::setAuth(
                $this->_credentials['userId'],
                $this->_credentials['credentials'],
                $this->_credentials['params']
            );
        }

        return false;
    }

    /**
     * Transparent authentication stub.
     *
     * Transparent authentication should set 'userId', 'credentials', or
     * 'params' in $this->_credentials as needed - these values will be used
     * to set the credentials in the session.
     *
     * Transparent authentication should normally never throw an error - false
     * should normally be returned. However, it is also possible that a
     * transparent authentication is the only available auth method; if so,
     * attempting to login via a login page may cause an endless loop. In this
     * case, an Exception should be thrown which will act as a fatal error.
     *
     * @return boolean  Whether transparent login is supported.
     * @throws Horde_Auth_Exception
     */
    protected function _transparent()
    {
        return false;
    }

    /**
     * Reset a user's password. Used for example when the user does not
     * remember the existing password.
     *
     * @param string $userId  The user id for which to reset the password.
     *
     * @return string  The new password on success.
     * @throws Horde_Auth_Exception
     */
    public function resetPassword($userId)
    {
        throw new Horde_Auth_Exception('unsupported');
    }

    /**
     * Queries the current driver to find out if it supports the given
     * capability.
     *
     * @param string $capability  The capability to test for.
     *
     * @return boolean  Whether or not the capability is supported.
     */
    public function hasCapability($capability)
    {
        return !empty($this->_capabilities[$capability]);
    }

    /**
     * Returns the named parameter for the current auth driver.
     *
     * @param string $param  The parameter to fetch.
     *
     * @return string  The parameter's value, or null if it doesn't exist.
     */
    public function getParam($param)
    {
        return isset($this->_params[$param])
            ? $this->_params[$param]
            : null;
    }

    /**
     * Returns information on what login parameters to display on the login
     * screen. If not defined, will display the default (username, password).
     *
     * @return array  An array with the following elements:
     * <pre>
     * 'js_code' - (array) A list of javascript code to output to the login
     *              page.
     * 'js_files' - (array) A list of javascript files to include in the login
     *              page.
     * 'params' - (array) TODO
     * </pre>
     * @throws Horde_Exception
     */
    public function getLoginParams()
    {
        return array(
            'js_code' => array(),
            'js_files' => array(),
            'params' => array()
        );
    }

}