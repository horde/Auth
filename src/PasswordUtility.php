<?php

declare(strict_types=1);

/**
 * Copyright 1999-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Chuck Hagenbuch <chuck@horde.org>
 * @author   Michael Slusarz <slusarz@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use InvalidArgumentException;

/**
 * Password hashing, generation, and policy validation utilities.
 */
class PasswordUtility
{
    private const VOWELS = 'aeiouy';
    private const CONSONANTS = 'bcdfghjklmnpqrstvwxz';
    private const NUMBERS = '0123456789';
    private const APRMD5_VALID = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    /**
     * Hash a password using the specified algorithm.
     *
     * @param string $plaintext The password to hash
     * @param string $algorithm Hashing algorithm (md5-hex, sha, ssha, crypt-blowfish, etc.)
     * @param string $salt Optional salt (generated if empty)
     * @param bool $showEncrypt Prepend encryption tag ({SHA}, {SSHA}, etc.)
     */
    public static function crypt(
        string $plaintext,
        string $algorithm = 'crypt-blowfish',
        string $salt = '',
        bool $showEncrypt = false,
    ): string {
        if ($algorithm === 'crypt-blowfish' && $salt === '') {
            return ($showEncrypt ? '{crypt}' : '') . password_hash($plaintext, PASSWORD_BCRYPT);
        }

        $salt = self::generateSalt($algorithm, $salt, $plaintext);

        return match ($algorithm) {
            'aprmd5' => self::cryptAprMd5($plaintext, $salt),
            'crypt', 'crypt-des', 'crypt-md5', 'crypt-sha256', 'crypt-sha512', 'crypt-blowfish'
                => ($showEncrypt ? '{crypt}' : '') . crypt($plaintext, $salt),
            'md5-base64' => ($showEncrypt ? '{MD5}' : '') . base64_encode(pack('H*', hash('md5', $plaintext))),
            'plain' => $plaintext,
            'sha', 'sha1' => ($showEncrypt ? '{SHA}' : '') . base64_encode(pack('H*', hash('sha1', $plaintext))),
            'sha256', 'ssha256' => ($showEncrypt ? '{SSHA256}' : '') . base64_encode(pack('H*', hash('sha256', $plaintext . $salt)) . $salt),
            'smd5' => ($showEncrypt ? '{SMD5}' : '') . base64_encode(pack('H*', hash('md5', $plaintext . $salt)) . $salt),
            'ssha' => ($showEncrypt ? '{SSHA}' : '') . base64_encode(pack('H*', hash('sha1', $plaintext . $salt)) . $salt),
            'md5-hex' => ($showEncrypt ? '{MD5}' : '') . hash('md5', $plaintext),
            default => hash('md5', $plaintext),
        };
    }

    /**
     * Generate or extract a salt for the given algorithm.
     *
     * @param string $algorithm The hashing algorithm
     * @param string $seed Existing hash to extract salt from (empty = generate new)
     * @param string $plaintext Plaintext password (used by some salt algorithms)
     */
    public static function generateSalt(string $algorithm = 'md5-hex', string $seed = '', string $plaintext = ''): string
    {
        return match ($algorithm) {
            'aprmd5' => $seed
                ? substr(preg_replace('/^\$apr1\$(.{8}).*/', '\\1', $seed), 0, 8)
                : self::randomString(8, self::APRMD5_VALID),
            'crypt', 'crypt-des' => $seed
                ? substr(preg_replace('|^{crypt}|i', '', $seed), 0, 2)
                : substr(base64_encode(random_bytes(8)), 0, 2),
            'crypt-blowfish' => $seed
                ? preg_replace('#^(?:{crypt})?(\$2[axy]\$(?:(0[4-9]|[1-2][0-9]|3[01])\$)[0-9A-Za-z./]{22}).*#i', '$1$', $seed)
                : '$2y$10$' . str_replace('+', '.', base64_encode(random_bytes(16))) . '$',
            'crypt-md5' => $seed
                ? substr(preg_replace('|^{crypt}|i', '', $seed), 0, 12)
                : '$1$' . base64_encode(random_bytes(6)) . '$',
            'crypt-sha256' => $seed
                ? substr(preg_replace('|^{crypt}|i', '', $seed), 0, strrpos($seed, '$') ?: 0)
                : '$5$' . base64_encode(random_bytes(12)) . '$',
            'crypt-sha512' => $seed
                ? substr(preg_replace('|^{crypt}|i', '', $seed), 0, strrpos($seed, '$') ?: 0)
                : '$6$' . base64_encode(random_bytes(12)) . '$',
            'ssha' => $seed
                ? substr(base64_decode(preg_replace('|^{SSHA}|i', '', $seed)), 20)
                : random_bytes(4),
            'smd5' => $seed
                ? substr(base64_decode(preg_replace('|^{SMD5}|i', '', $seed)), 16)
                : random_bytes(4),
            'sha256', 'ssha256' => $seed
                ? substr(base64_decode(preg_replace('|^{SSHA256}|i', '', $seed)), 32)
                : random_bytes(4),
            default => '',
        };
    }

    /**
     * Generate a random password.
     *
     * @param int $length Desired length (minimum 4)
     */
    public static function generateRandom(int $length = 12): string
    {
        if ($length < 4) {
            throw new InvalidArgumentException('Password length must be at least 4');
        }

        $password = '';
        for ($i = 0; $i < $length - 2; $i++) {
            $pool = ($i % 2 === 0) ? self::CONSONANTS : self::VOWELS;
            $password .= $pool[random_int(0, strlen($pool) - 1)];
        }
        $password .= self::NUMBERS[random_int(0, 9)];
        $password .= self::NUMBERS[random_int(0, 9)];

        return $password;
    }

    /**
     * Validate a password against a policy.
     *
     * @return list<string> List of violation descriptions (empty = passes policy)
     */
    public static function checkPolicy(string $password, PasswordPolicy $policy): array
    {
        $violations = [];
        $length = strlen($password);

        if ($policy->minLength > 0 && $length < $policy->minLength) {
            $violations[] = sprintf('Password must be at least %d characters', $policy->minLength);
        }
        if ($policy->maxLength > 0 && $length > $policy->maxLength) {
            $violations[] = sprintf('Password must not exceed %d characters', $policy->maxLength);
        }

        $upper = $lower = $numeric = $symbol = 0;
        $classes = [];
        for ($i = 0; $i < $length; $i++) {
            $char = $password[$i];
            if (ctype_upper($char)) {
                $upper++;
                $classes['upper'] = true;
            } elseif (ctype_lower($char)) {
                $lower++;
                $classes['lower'] = true;
            } elseif (ctype_digit($char)) {
                $numeric++;
                $classes['numeric'] = true;
            } elseif (ctype_punct($char) || ctype_space($char)) {
                $symbol++;
                $classes['symbol'] = true;
            }
        }

        if ($policy->minUppercase > 0 && $upper < $policy->minUppercase) {
            $violations[] = sprintf('Password must contain at least %d uppercase characters', $policy->minUppercase);
        }
        if ($policy->minLowercase > 0 && $lower < $policy->minLowercase) {
            $violations[] = sprintf('Password must contain at least %d lowercase characters', $policy->minLowercase);
        }
        if ($policy->minNumeric > 0 && $numeric < $policy->minNumeric) {
            $violations[] = sprintf('Password must contain at least %d numeric characters', $policy->minNumeric);
        }
        if ($policy->minSymbol > 0 && $symbol < $policy->minSymbol) {
            $violations[] = sprintf('Password must contain at least %d symbol characters', $policy->minSymbol);
        }
        if ($policy->minClasses > 0 && count($classes) < $policy->minClasses) {
            $violations[] = sprintf('Password must contain at least %d character classes', $policy->minClasses);
        }

        return $violations;
    }

    /**
     * Check password similarity against a dictionary of strings.
     *
     * @param string $password The new password
     * @param list<string> $dictionary Strings to compare against (old password, username, etc.)
     * @param float $maxSimilarity Maximum allowed similarity percentage (0-100)
     * @return bool True if password is sufficiently different
     */
    public static function checkSimilarity(string $password, array $dictionary, float $maxSimilarity = 80.0): bool
    {
        foreach ($dictionary as $test) {
            if (strcasecmp($password, $test) === 0 || strcasecmp($password, strrev($test)) === 0) {
                return false;
            }
            similar_text(strtolower($password), strtolower($test), $percent);
            if ($percent > $maxSimilarity) {
                return false;
            }
        }

        return true;
    }

    private static function randomString(int $length, string $chars): string
    {
        $result = '';
        $max = strlen($chars) - 1;
        for ($i = 0; $i < $length; $i++) {
            $result .= $chars[random_int(0, $max)];
        }
        return $result;
    }

    private static function cryptAprMd5(string $plaintext, string $salt): string
    {
        $length = strlen($plaintext);
        $context = $plaintext . '$apr1$' . $salt;
        $binary = pack('H*', hash('md5', $plaintext . $salt . $plaintext));

        for ($i = $length; $i > 0; $i -= 16) {
            $context .= substr($binary, 0, min($i, 16));
        }
        for ($i = $length; $i > 0; $i >>= 1) {
            $context .= ($i & 1) ? "\0" : $plaintext[0];
        }

        $binary = pack('H*', hash('md5', $context));

        for ($i = 0; $i < 1000; ++$i) {
            $new = ($i & 1) ? $plaintext : substr($binary, 0, 16);
            if ($i % 3) {
                $new .= $salt;
            }
            if ($i % 7) {
                $new .= $plaintext;
            }
            $new .= ($i & 1) ? substr($binary, 0, 16) : $plaintext;
            $binary = pack('H*', hash('md5', $new));
        }

        $p = [];
        for ($i = 0; $i < 5; $i++) {
            $k = $i + 6;
            $j = $i + 12;
            if ($j === 16) {
                $j = 5;
            }
            $p[] = self::toAprMd5(
                (ord($binary[$i]) << 16) | (ord($binary[$k]) << 8) | ord($binary[$j]),
                5,
            );
        }

        return '$apr1$' . $salt . '$' . implode('', $p) . self::toAprMd5(ord($binary[11]), 3);
    }

    private static function toAprMd5(int $value, int $count): string
    {
        $result = '';
        $valid = self::APRMD5_VALID;
        while (--$count) {
            $result .= $valid[$value & 0x3f];
            $value >>= 6;
        }
        return $result;
    }
}
