<?php
/**
 * Test the Horde_Auth_Kolab:: class.
 *
 * Copyright 2010-2017 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @category   Horde
 * @package    Auth
 * @subpackage UnitTests
 * @author     Gunnar Wrobel <wrobel@pardus.de>
 * @license    http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */
namespace Horde\Auth\Unit;
use Horde\Auth\TestCase;

class KolabTest extends TestCase
{
    public function setUp(): void
    {
        if (!interface_exists('Horde_Kolab_Session')) {
            $this->markTestSkipped('The Kolab_Session package is apparently not installed (Interface Horde_Kolab_Session is unavailable).');
        }
        $this->kolab = $this->getMock('Horde_Kolab_Session');
        $this->driver = new Horde_Auth_Kolab(array('kolab' => $this->kolab));
    }

    public function testAuthenticate()
    {
        $this->kolab->expects($this->once())
            ->method('connect')
            ->with('user', array('password' => 'password'))
            ->will($this->returnValue(null));
        $this->assertTrue($this->driver->authenticate('user', array('password' => 'password')));
    }

    public function testBadLogin()
    {
        $this->kolab->expects($this->once())
            ->method('connect')
            ->with('user', array('password' => 'incorrect'))
            ->will($this->throwException(new Horde_Kolab_Session_Exception_Badlogin()));
        try {
            $this->driver->authenticate('user', array('password' => 'incorrect'));
        } catch (Horde_Auth_Exception $e) {
            $this->assertEquals(Horde_Auth::REASON_BADLOGIN, $e->getCode());
        }
    }

    public function testFailure()
    {
        $this->kolab->expects($this->once())
            ->method('connect')
            ->with('user', array('password' => ''))
            ->will($this->throwException(new Horde_Kolab_Session_Exception()));
        try {
            $this->driver->authenticate('user', array('password' => ''));
        } catch (Horde_Auth_Exception $e) {
            $this->assertEquals(Horde_Auth::REASON_FAILED, $e->getCode());
        }
    }

    public function testUidRewrite()
    {
        $this->kolab->expects($this->once())
            ->method('connect')
            ->with('user', array('password' => 'password'))
            ->will($this->returnValue(null));
        $this->kolab->expects($this->once())
            ->method('getMail')
            ->will($this->returnValue('user@example.com'));
        $this->driver->authenticate('user', array('password' => 'password'));
        $this->assertEquals(
            'user@example.com', $this->driver->getCredential('userId')
        );
    }
}
