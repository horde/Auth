<?php

/**
 * Test the Horde_Auth:: class.
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
use Horde_Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(Horde_Auth::class)]
class AuthTest extends BaseTestCase
{
    #[DataProvider('getSaltData')]
    public function testGetSalt($encryption, $password, $salt)
    {
        $this->assertEquals($salt, Horde_Auth::getSalt($encryption, $password, 'foobar'));
    }

    #[DataProvider('getCryptedData')]
    public function testGetCryptedPassword($encryption, $password, $salt, $show_encryption = false)
    {
        $this->assertEquals($password, Horde_Auth::getCryptedPassword('foobar', $password, $encryption, $show_encryption));
    }
}
