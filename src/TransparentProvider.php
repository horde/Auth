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

use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

/**
 * Asserts identity from request context without user interaction.
 *
 * A TransparentProvider inspects an incoming HTTP request for identity
 * assertions (client certificates, HTTP headers, IP ranges, tokens).
 * It has internal configuration/invariants that determine what to look for.
 *
 * Returns AuthResultSuccess if identity can be confidently asserted.
 * Returns null if this provider cannot determine identity from the request
 * (header missing, cert not presented, IP not in range). This is not a
 * failure — just "not applicable to this request."
 *
 * Never throws for "no identity found." Exceptions are reserved for
 * infrastructure failures.
 */
interface TransparentProvider
{
    /**
     * Extract an identity assertion from the incoming HTTP request.
     *
     * Inspects request attributes (headers, client certificates, IP address,
     * cookies, query parameters) for identity assertions that this provider
     * understands.
     *
     * Returns null when this provider cannot determine identity from the
     * request — this is not a failure, just "not applicable to this request."
     * The caller may try another provider.
     *
     * @param ServerRequestInterface $request The incoming HTTP request to inspect
     *
     * @return AuthResultSuccess|null Success if identity is confidently asserted;
     *         null if this provider has nothing to say about this request.
     *
     * @throws RuntimeException On infrastructure failure (misconfiguration,
     *         required extension missing)
     */
    public function extractIdentity(ServerRequestInterface $request): ?AuthResultSuccess;
}
