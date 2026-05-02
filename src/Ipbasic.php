<?php

declare(strict_types=1);

/**
 * Copyright 1999-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Chuck Hagenbuch <chuck@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

use DateTimeImmutable;
use Psr\Http\Message\ServerRequestInterface;

/**
 * IP/CIDR-based transparent authentication.
 *
 * Grants access based on client IP address matching configured CIDR blocks.
 * The "userId" is set to the matching CIDR block.
 */
class Ipbasic implements TransparentProvider
{
    /** @var list<string> */
    private readonly array $blocks;

    /**
     * @param list<string> $blocks CIDR blocks to allow (e.g. ['192.168.0.0/16', '10.0.0.0/8'])
     */
    public function __construct(array $blocks = [])
    {
        $this->blocks = $blocks;
    }

    public function extractIdentity(ServerRequestInterface $request): ?AuthResultSuccess
    {
        $serverParams = $request->getServerParams();
        $remoteAddr = $serverParams['REMOTE_ADDR'] ?? '';

        if ($remoteAddr === '') {
            return null;
        }

        foreach ($this->blocks as $cidr) {
            if ($this->addressWithinCidr($remoteAddr, $cidr)) {
                return new AuthResultSuccess(
                    'ipbasic',
                    new DateTimeImmutable(),
                    $cidr,
                    ['remote_addr' => $remoteAddr],
                );
            }
        }

        return null;
    }

    private function addressWithinCidr(string $address, string $cidr): bool
    {
        $ip = ip2long($address);
        if ($ip === false) {
            return false;
        }

        if (!str_contains($cidr, '/')) {
            return $ip === ip2long($cidr);
        }

        [$quad, $bits] = explode('/', $cidr);
        $bits = (int) $bits;
        $network = ip2long($quad);

        if ($network === false || $bits < 0 || $bits > 32) {
            return false;
        }

        return ($ip >> (32 - $bits)) === ($network >> (32 - $bits));
    }
}
