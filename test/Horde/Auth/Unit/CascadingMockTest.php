<?php
/**
 * PHP version 5
 * Test the Horde_Auth_Dummy:: class. 
 * 
 * Copyright 2017-2018 Horde LLC (http://www.horde.org/)
 * 
 * See the enclosed file COPYING for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 * 
 * @category   Horde
 * @package    Auth
 * @subpackage UnitTests
 * @author     Florian Frank <frank@b1-systems.de>
 * @license    http://www.horde.org/licenses/lgpl21 LGPL-2.1
 * @link       http://pear.horde.org/index.php?package=Auth
 */

class Horde_Auth_Unit_CascadingTest extends Horde_Auth_TestCase
{

    function setUp() {
        $d1 = new Horde_Auth_Mock(array('users' => array('user1' => 'pw1','user2' => 'pw2')));
        $d2 = new Horde_Auth_Mock(array('users' => array('user1' => 'pw3443243', 'tester2' => 'pw3323242')));
        $d3 = new Horde_Auth_Mock(
                        array(
                            'users' => array(
                                'tester1337' => '$1$W1n1f.uf$4pL90iQvvfS0PqshMaMLi.', //testpassword1
                                'tester1338' => '$1$W1n1f.uf$M3F2kPykfT3Z1ywuAqvO6.', //testpassword2
                                'tester2'    => '$1$W1n1f.uf$ng08WnPr8wQuVGg2pvw2f1' //hi$M+i3Rd
                            ),                        
                            'encryption' => 'crypt-md5',
                            'show_encryption' => false
                        )
                    );
        $this->cascading = new Horde_Auth_Cascading(
            array(
                'drivers' => array('admins' => $d1, 'db' => $d2, 'cryptdb' => $d3),
                'order' => array('admins', 'db', 'cryptdb'),
            )
        );
    }

    public function testHasCapability()
    {
        $this->assertFalse($this->cascading->hasCapability('transparent'));
        $this->assertTrue($this->cascading->hasCapability('authenticate'));
        $this->assertTrue($this->cascading->hasCapability('remove'));
        $this->assertTrue($this->cascading->hasCapability('update'));
    }

    public function testTransparent()
    {
        //throw exception if no backend provides transparent
        $this->setExpectedException(Horde_Auth_Exception::class);
        $this->cascading->transparent();
    }

    public function testListUsers()
    {
        $this->assertEquals(array('user1', 'user2', 'tester2', 'tester1337', 'tester1338'), $this->cascading->listUsers(true));
        $this->assertEquals(array('user1', 'user2', 'tester2', 'tester1337', 'tester1338'), $this->cascading->listUsers(false));
        $this->assertEquals(array('user1', 'user2', 'tester2', 'tester1337', 'tester1338'), $this->cascading->listUsers());
        $this->assertCount(5, $this->cascading->listUsers());
        $this->assertCount(5, $this->cascading->listUsers(true));
        $this->assertCount(5, $this->cascading->listUsers(false));
    }

    public function testRemoveUser()
    {
        $this->cascading->removeUser('user1');
        $this->assertCount(4, $this->cascading->listUsers());
        $this->assertFalse($this->cascading->exists('user1'));
        $this->assertFalse($this->cascading->authenticate('user1', array('password' => 'pw1')));
        $this->assertFalse($this->cascading->authenticate('user1', array('password' => 'pw3443243')));
    }

    public function testUpdateUser()
    {
        //change password
        $this->cascading->updateUser('user1', 'user1',  array('password' => 'foo'));
        $this->assertCount(5, $this->cascading->listUsers());
        $this->assertTrue($this->cascading->exists('user1'));
        // check if new password works
        $this->assertFalse($this->cascading->authenticate('user1', array('password' => 'pw1')));
        $this->assertTrue($this->cascading->authenticate('user1', array('password' => 'foo')));
        //change userID
        $this->cascading->updateUser('user2', 'user42',  array('password' => 'pw2'));
        $this->assertCount(5, $this->cascading->listUsers());
        $this->assertTrue($this->cascading->exists('user42'));
        // check if new user works
        $this->assertTrue($this->cascading->authenticate('user42', array('password' => 'pw2')));
        //check if old users still can log in
        $this->assertFalse($this->cascading->authenticate('user2', array('password' => 'pw2')));
        //change userID and password
        $this->cascading->updateUser('tester2', 'tester1339', array('password' => 'pw1337'));
        $this->assertCount(5, $this->cascading->listUsers());
        $this->assertTrue($this->cascading->exists('tester1339'));
        // check if new user can log in
        $this->assertTrue($this->cascading->authenticate('tester1339', array('password' => 'pw1337')));
        //check if old users still exists
        $this->assertFalse($this->cascading->authenticate('tester2', array('password' => 'pw3323242')));
        //update user with encrypted password
        $this->cascading->updateUser('tester1337', 'tester1337',  array('password' => 'testpassword1337'));
        $this->assertTrue($this->cascading->authenticate('tester1337', array('password' => 'testpassword1337')));
    }

    public function testUpdateUserFailDoesNotExist()
    {
        // Try renaming unknown user
       // $this->setExpectedException(Horde_Auth_Exception::class);
        $this->cascading->updateUser('unknownuser', 'newname',  array('password' => 'foo'));
        $this->setUp();
    }

    public function testResetPassword()
    {
        $this->setExpectedException(Horde_Auth_Exception::class);
        $newPassword = $this->cascading->resetPassword('user1');
        //old Password should not work
        $this->assertFalse($this->cascading->authenticate('user1' , array('password' => 'pw1')));
        //new password should work
        $this->assertTrue($this->cascading->authenticate('user1' ,  array('password' => $newPassword)));
    }

    public function testAddUser()
    {
        //new user who does not exist in any backend
        $this->cascading->addUser('user42', array('password' => 'foo'));
        $this->assertCount(6, $this->cascading->listUsers());
        //new user who already exists in one backend with the same password
        $this->cascading->addUser('user2', array('password' => 'pw2'));
        $this->assertCount(6, $this->cascading->listUsers());
        //new user who already exists in one backend with a wrong password 
        $this->cascading->addUser('user2', array('password' => 'pw42'));
        $this->assertCount(6, $this->cascading->listUsers());
        $this->assertFalse($this->cascading->authenticate('user2' ,  array('password' => 'pw42')));
        $this->assertTrue($this->cascading->authenticate('user2' ,  array('password' => 'pw2')));
        //new user who already exists in all backends
        $this->cascading->addUser('user1', array('password' => 'pw1'));
        $this->assertEquals(array('user1', 'user2', 'user42', 'tester2', 'tester1337', 'tester1338'), $this->cascading->listUsers(true));
        $this->assertTrue($this->cascading->authenticate('user1' ,  array('password' => 'pw3443243')));
        //check authenticate
        $this->assertTrue($this->cascading->authenticate('user42', array('password' => 'foo')));
        $this->assertFalse($this->cascading->authenticate('user42', array('password' => 'bar')));
    }

    public function testAuthenticate()
    {
        // user does not exist in any backend
        $this->assertFalse($this->cascading->authenticate('user42', array('password' => 'pw1')));
        // user exists in two backends with different passwords
        $this->assertTrue($this->cascading->authenticate('user1', array('password' => 'pw3443243')));
        $this->assertTrue($this->cascading->authenticate('user1', array('password' => 'pw1')));
        // user exists in one backend
        $this->assertTrue($this->cascading->authenticate('user2', array('password' => 'pw2')));
        //user has encrypeted password
        $this->assertTrue($this->cascading->authenticate('tester1337', array('password' => 'testpassword1')));
        $this->assertTrue($this->cascading->authenticate('tester2', array('password' => 'hi$M+i3Rd')));
        // user has wrong password
        $this->assertFalse($this->cascading->authenticate('user1', array('password' => 'pw42')));
    }

    public function testExists()
    {
        $this->assertTrue($this->cascading->exists('user1'));
        $this->assertFalse($this->cascading->exists('user42'));
    }
}
