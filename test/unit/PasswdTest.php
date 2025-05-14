<?php

/**
 * PHP version 5
 * Test the Horde_Auth_Passwd:: class.
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

namespace Horde\Auth\Test\Unit;

use Horde\Auth\Test\BaseTestCase;
use Horde_Auth_Passwd;

use PHPUnit\Framework\Attributes\CoversNothing;
#[CoversNothing]
class PasswdTest extends BaseTestCase
{
    public function setUp(): void
    {
        $this->driver = new Horde_Auth_Passwd(
            ['filename' => __DIR__ . '/../fixtures/test.passwd']
        );
    }

    public function testAuthenticate()
    {
        $this->assertTrue($this->driver->authenticate('user', ['password' => 'password']));
    }

    public function testListUsers()
    {
        $this->assertEquals(['user'], $this->driver->listUsers());
    }
}
