<?php
/**
 * Test the Horde_Auth_Mock:: class.
 *
 * Copyright 2017 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @category   Horde
 * @package    Auth
 * @subpackage UnitTests
 * @author     Ralf Lang <lang@b1-systems.de>
 * @license    http://www.horde.org/licenses/lgpl21 LGPL-2.1
 * @link       http://pear.horde.org/index.php?package=Auth
 */
class Horde_Auth_Unit_MockCryptShowTest extends Horde_Auth_TestCase
{
    public function setUp()
    {
        $this->driver = new Horde_Auth_Mock(
            array(
                'users' => array(
                    'user1' => '{crypt}$1$S/EKq8Dg$OJvaV8Lu1HgCXKNqAo.wG/',
                    'user2' => '{crypt}$1$aCWZiBAW$dK0DCmTGYR1gEX11pMxbi0',
                    'tester' => '{crypt}$1$sjSx+Q9x$3WIEdh1Ei16QouYx1Xkct1'
                ),
                'encryption' => 'crypt-md5',
                'show_encryption' => true
           )
        );
    }

    public function testAuthenticate()
    {
        $this->assertTrue($this->driver->authenticate('user1', array('password' => 'user1pw')));
        $this->assertTrue($this->driver->authenticate('user2', array('password' => 'user2pw')));
        $this->assertTrue($this->driver->authenticate('tester', array('password' => 'WeirdPW92401#1')));
        // correct password extended by garbage
        $this->assertFalse($this->driver->authenticate('user1', array('password' => 'user1pwfalse')));
        // Existing user with all kinds of garbage
        $this->assertFalse($this->driver->authenticate('user1', array('password' => 'any')));
        $this->assertFalse($this->driver->authenticate('user1', array('password' => '')));
        $this->assertFalse($this->driver->authenticate('user1', array('password' => null)));
        $this->assertFalse($this->driver->authenticate('user1', array('password' => '0')));
        // Unknown user with all kinds of garbage
        $this->assertFalse($this->driver->authenticate('unknownuser', array('password' => 'any')));
        $this->assertFalse($this->driver->authenticate('unknownuser', array('password' => '')));
        $this->assertFalse($this->driver->authenticate('unknownuser', array('password' => null)));
        $this->assertFalse($this->driver->authenticate('unknownuser', array('password' => '0')));
    }

    public function testRemoveUser()
    {
        // Delete somebody who doesn't exist
        $this->driver->removeUser('user');
        $this->assertCount(3, $this->driver->listUsers());
        $this->driver->removeUser('user1');
        $this->assertCount(2, $this->driver->listUsers());
        $this->driver->removeUser('user2');
        $this->assertCount(1, $this->driver->listUsers());
        $this->driver->removeUser('tester');
        $this->assertCount(0, $this->driver->listUsers());
        // Restore setup
        $this->setUp();
    }

    public function testAddUser()
    {
        // Add somebody who already exist
        $this->driver->addUser('user4', array('password' => 'foo'));
        $this->assertCount(4, $this->driver->listUsers());
        // Add somebody who already exist
        $this->setExpectedException('Horde_Auth_Exception');
        $this->driver->addUser('user4', array('password' => 'foo'));
        $this->assertCount(4, $this->driver->listUsers());

        // Restore setup
        $this->setUp();
    }

    public function testUpdateUser()
    {
        // Try a password change
        $this->driver->updateUser('tester', 'tester',  array('password' => 'foo'));
        $this->assertCount(3, $this->driver->listUsers());
        $this->assertTrue($this->driver->exists('tester'));
        // Try renaming
        $this->driver->updateUser('tester', 'newname',  array('password' => 'foo'));
        $this->assertCount(3, $this->driver->listUsers());
        $this->assertTrue($this->driver->exists('newname'));
        $this->assertFalse($this->driver->exists('tester'));
        $this->setUp();
    }

    public function testUpdateUserFailDoesNotExist()
    {
        // Try renaming unknown user
        $this->setExpectedException('Horde_Auth_Exception');
        $this->driver->updateUser('unknownuser', 'newname',  array('password' => 'foo'));
        $this->setUp();
    }

    public function testUpdateUserFailNewNameExists()
    {
        // Try renaming unknown user
        $this->setExpectedException('Horde_Auth_Exception');
        $this->driver->updateUser('tester', 'user1',  array('password' => 'foo'));
        $this->setUp();
    }



    public function testExists()
    {
        $this->assertTrue($this->driver->exists('user1'));
        $this->assertTrue($this->driver->exists('user2'));
        $this->assertTrue($this->driver->exists('tester'));
        $this->assertFalse($this->driver->exists('somebody'));
        $this->assertFalse($this->driver->exists(''));
        $this->assertFalse($this->driver->exists(null));
    }

    /**
     * This is actually a test against Horde_Auth_Base
     * TODO: Copy or move to a test with a phpunit mock
     */

    public function testSearchUsers()
    {
        $this->assertCount(2, $this->driver->searchUsers('user'));
        $this->assertCount(1, $this->driver->searchUsers('test'));
        $this->assertEquals(array('tester'), $this->driver->searchUsers('test'));
    }

    public function testListUsers()
    {
        $this->assertEquals(array('tester', 'user1', 'user2'), $this->driver->listUsers(true));
        $this->assertEquals(array('user1', 'user2', 'tester'), $this->driver->listUsers(false));
        $this->assertEquals(array('user1', 'user2', 'tester'), $this->driver->listUsers());
    }
}
