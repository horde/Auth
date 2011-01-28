<?php
/**
 * Base for testing.
 *
 * PHP version 5
 *
 * @category   Horde
 * @package    Auth
 * @subpackage UnitTests
 * @author     Gunnar Wrobel <wrobel@pardus.de>
 * @license    http://www.fsf.org/copyleft/lgpl.html LGPL
 * @link       http://pear.horde.org/index.php?package=Auth
 */

/**
 * Base for testing.
 *
 * Copyright 2010-2011 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file COPYING for license information (LGPL). If you
 * did not receive this file, see http://www.fsf.org/copyleft/lgpl.html.
 *
 * @category   Horde
 * @package    Auth
 * @subpackage UnitTests
 * @author     Gunnar Wrobel <wrobel@pardus.de>
 * @license    http://www.fsf.org/copyleft/lgpl.html LGPL
 * @link       http://pear.horde.org/index.php?package=Auth
 */
class Horde_Auth_TestCase extends PHPUnit_Framework_TestCase
{
    public function getCredentials()
    {
        return array(
            array('plain', 'foobar', ''),
            array('msad', '" f o o b a r " ', ''),
            array('sha', 'iEPX+SQWIR3p67lj/0zigSWTKHg=', ''),
            array('crypt', '8e3IWstJmsmxs', '8e'),
            array('crypt-des', '45MibW6/G3XEY', '45'),
            array('crypt-md5', '$1$537a3a0e$CWyLVJdQKfxbKPBv/Efzm0', '$1$537a3a0e$'),
            array('crypt-blowfish', '*0OayF9ttbxIs', '*0OayF9ttbxIs'),
            array('md5-base64', 'OFj2IjCsPJFfMAxmQxLGPw==', ''),
            array('ssha', 'buQrQ9vazjrHtO6oIfSZhSBjVxdjemZvZHVubg==', 'czfodunn'),
            array('ssha', 'BLDmpxHYTH2/Bmg4veVfbglU68jQKEuK', '�(K�'),
            array('ssha', '2iXr83rPabLxmrx7uulT4W7mJFrawT41', '��>5'),
            array('smd5', 'ISCNJwzwP30CadahjpkbL2l6bHJxd2h2', 'izlrqwhv'),
            array('smd5', 'bn3EnZ0TFc+yyx3KotqS5GlydmM=', 'irvc'),
            array('smd5', 'GZ4KWKk2W6eSOHjVXLhOOzADuwA=', '0� '),
            array('smd5', '6y2n+CGCZhuB32dyFu3keQtY0Vc=', 'X�W'),
            array('aprmd5', '$apr1$11CBbKXP$AvvMGBjr81bC/NSMZIxrG.', '11CBbKXP'),
            array('md5-hex', '3858f62230ac3c915f300c664312c63f', ''),
        );
    }
}