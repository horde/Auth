<?php

/**
 * Base for testing.
 *
 * Copyright 2010-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @category   Horde
 * @package    Auth
 * @subpackage UnitTests
 * @author     Gunnar Wrobel <wrobel@pardus.de>
 * @license    http://www.horde.org/licenses/lgpl21 LGPL
 */

namespace Horde\Auth\Test;

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversNothing;

#[CoversNothing]
class BaseTestCase extends TestCase
{
    public static function getSaltData(): array
    {
        return [
            ['aprmd5', '$apr1$11CBbKXP$AvvMGBjr81bC/NSMZIxrG.', '11CBbKXP'],
            ['crypt', '8e3IWstJmsmxs', '8e'],
            ['crypt-blowfish', '$2a$08$xJOYeQ7koDohq69yZeFXNO5TvrTlFLs4NP2..EcZP57oeOVgXoxqy', '$2a$08$xJOYeQ7koDohq69yZeFXNO$'],
            ['crypt-des', '45MibW6/G3XEY', '45'],
            ['crypt-md5', '$1$537a3a0e$CWyLVJdQKfxbKPBv/Efzm0', '$1$537a3a0e$'],
            ['md5-base64', 'OFj2IjCsPJFfMAxmQxLGPw==', ''],
            ['md5-hex', '3858f62230ac3c915f300c664312c63f', ''],
            ['msad', "\"\0f\0o\0o\0b\0a\0r\0\"\0", ''],
            ['mysql', '*9B500343BC52E2911172EB52AE5CF4847604C6E5', ''],
            ['plain', 'foobar', ''],
            ['sha', 'iEPX+SQWIR3p67lj/0zigSWTKHg=', ''],
            ['smd5', 'ISCNJwzwP30CadahjpkbL2l6bHJxd2h2', 'izlrqwhv'],
            ['smd5', 'bn3EnZ0TFc+yyx3KotqS5GlydmM=', 'irvc'],
            ['smd5', 'GZ4KWKk2W6eSOHjVXLhOOzADuwA=', hex2bin('3003bb00')],
            ['smd5', '6y2n+CGCZhuB32dyFu3keQtY0Vc=', hex2bin('0b58d157')],
            ['ssha', 'buQrQ9vazjrHtO6oIfSZhSBjVxdjemZvZHVubg==', 'czfodunn'],
            ['ssha', 'BLDmpxHYTH2/Bmg4veVfbglU68jQKEuK', hex2bin('d0284b8a')],
            ['ssha', '2iXr83rPabLxmrx7uulT4W7mJFrawT41', hex2bin('dac13e35')],
            ['ssha', '6IeOcols85dHJeTHevA356ruftrA2PRX', hex2bin('c0d8f457')],
            ['ssha256', 'wnD9GBo+WIXZ+bVD7DjoDokQBjkVgtufXyBh1EqfXn11+sUG', hex2bin('75fac506')],
        ];
    }

    public static function getCryptedData(): array
    {
        return [
            ['aprmd5', '$apr1$11CBbKXP$AvvMGBjr81bC/NSMZIxrG.', '11CBbKXP', false],
            ['crypt', '8e3IWstJmsmxs', '8e', false],
            ['crypt-blowfish', '$2a$08$xJOYeQ7koDohq69yZeFXNO5TvrTlFLs4NP2..EcZP57oeOVgXoxqy', '$2a$08$xJOYeQ7koDohq69yZeFXNO$', false],
            ['crypt-des', '45MibW6/G3XEY', '45', false],
            ['crypt-md5', '$1$537a3a0e$CWyLVJdQKfxbKPBv/Efzm0', '$1$537a3a0e$', false],
            ['md5-base64', 'OFj2IjCsPJFfMAxmQxLGPw==', '', false],
            ['md5-hex', '3858f62230ac3c915f300c664312c63f', '', false],
            ['msad', "\"\0f\0o\0o\0b\0a\0r\0\"\0", '', false],
            ['mysql', '*9B500343BC52E2911172EB52AE5CF4847604C6E5', '', false],
            ['plain', 'foobar', '', false],
            ['sha', 'iEPX+SQWIR3p67lj/0zigSWTKHg=', '', false],
            ['smd5', 'ISCNJwzwP30CadahjpkbL2l6bHJxd2h2', 'izlrqwhv', false],
            ['smd5', '{SMD5}ISCNJwzwP30CadahjpkbL2l6bHJxd2h2', 'izlrqwhv', true],
            ['smd5', 'bn3EnZ0TFc+yyx3KotqS5GlydmM=', 'irvc', false],
            ['smd5', 'GZ4KWKk2W6eSOHjVXLhOOzADuwA=', hex2bin('3003bb00'), false],
            ['smd5', '6y2n+CGCZhuB32dyFu3keQtY0Vc=', hex2bin('0b58d157'), false],
            ['ssha', 'buQrQ9vazjrHtO6oIfSZhSBjVxdjemZvZHVubg==', 'czfodunn', false],
            ['ssha', 'BLDmpxHYTH2/Bmg4veVfbglU68jQKEuK', hex2bin('d0284b8a'), false],
            ['ssha', '2iXr83rPabLxmrx7uulT4W7mJFrawT41', hex2bin('dac13e35'), false],
            ['ssha', '{SSHA}6IeOcols85dHJeTHevA356ruftrA2PRX', hex2bin('c0d8f457'), true],
            ['ssha', '6IeOcols85dHJeTHevA356ruftrA2PRX', hex2bin('c0d8f457'), false],
            ['ssha256', '{SSHA256}wnD9GBo+WIXZ+bVD7DjoDokQBjkVgtufXyBh1EqfXn11+sUG', hex2bin('75fac506'), true],
            ['ssha256', 'wnD9GBo+WIXZ+bVD7DjoDokQBjkVgtufXyBh1EqfXn11+sUG', hex2bin('75fac506'), false],
        ];
    }

    public static function getCredentials(): array
    {
        // Deprecated: Use getSaltData() or getCryptedData() instead
        return self::getCryptedData();
    }
}
