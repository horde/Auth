<?php

/**
 * Basic credential validation against an SQL database.
 */

declare(strict_types=1);

use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Sql;

// $db is a Horde\Db\Adapter instance
$auth = new Sql(
    db: $db,
    table: 'horde_users',
    encryption: 'crypt-blowfish',
);

$result = $auth->validate('alice', ['password' => 'secret']);

if ($result instanceof AuthResultSuccess) {
    echo 'Authenticated as: ' . $result->getNativeKey() . "\n";
} else {
    echo 'Login failed: ' . $result->get('reason') . "\n";
}
