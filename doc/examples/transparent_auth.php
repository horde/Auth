<?php

/**
 * Transparent authentication from HTTP request headers (Shibboleth, X.509, IP).
 */

declare(strict_types=1);

use Horde\Auth\Shibboleth;

// Shibboleth SP sets headers after assertion
$provider = new Shibboleth(
    usernameHeader: 'Shib-Person-uid',
    headersToAttributes: ['Shib-Person-mail' => 'mail'],
);

// $request is a PSR-7 ServerRequestInterface
$result = $provider->extractIdentity($request);

if ($result !== null) {
    echo 'Identity asserted: ' . $result->getNativeKey() . "\n";
    echo 'Email: ' . $result->get('mail') . "\n";
} else {
    echo "No identity in this request — redirect to login.\n";
}
