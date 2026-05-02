<?php

/**
 * User management: add, list, search, rename, remove users.
 */

declare(strict_types=1);

use Horde\Auth\Sql;
use Horde\Auth\UserLifecycleManager;

// $db is a Horde\Db\Adapter instance
$auth = new Sql(db: $db, encryption: 'crypt-blowfish');

// Type-check before calling lifecycle methods
assert($auth instanceof UserLifecycleManager);

// Add a user
$entry = $auth->addUser('bob', ['password' => 'initial-pass']);
echo "Created: {$entry->getUserId()} on {$entry->getBackend()}\n";

// List all users
foreach ($auth->list() as $user) {
    echo "  - {$user->getUserId()}\n";
}

// Search
foreach ($auth->search('bo') as $user) {
    echo "  Found: {$user->getUserId()}\n";
}

// Rename
$auth->renameUser('bob', 'robert');

// Update attributes (password re-hashed automatically)
$auth->updateUser('robert', ['password' => 'new-pass']);

// Remove
$auth->removeUser('robert');
