<?php

/**
 * Access policy with lockout and password expiration.
 *
 * Demonstrates the full auth flow: preAuth -> validate -> postAuth,
 * using in-memory stores suitable for testing or single-process use.
 */

declare(strict_types=1);

use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Mock;
use Horde\Auth\Policy\CompoundPolicy;
use Horde\Auth\Policy\ExpirationPolicy;
use Horde\Auth\Policy\LockoutPolicy;
use Horde\Auth\Storage\InMemoryAttemptTracker;
use Horde\Auth\Storage\InMemoryLockManager;

// --- Setup ---

$driver = new Mock(users: [
    'alice' => ['password' => 'correct', 'attributes' => []],
]);

$tracker = new InMemoryAttemptTracker();
$lockManager = new InMemoryLockManager();

$policy = new CompoundPolicy(
    new LockoutPolicy($tracker, $lockManager, maxAttempts: 3, lockDuration: 900),
    new ExpirationPolicy(),
);

// --- Auth flow helper ---

$authenticate = function (string $userId, string $password) use ($driver, $policy): void {
    // Step 1: Pre-auth check (is user locked?)
    $decision = $policy->preAuth($userId);
    if ($decision->isDenied()) {
        echo "DENIED (pre): {$decision->getReason()}\n";
        return;
    }

    // Step 2: Credential validation
    $result = $driver->validate($userId, ['password' => $password]);

    // Step 3: Post-auth check (record attempt, check expiration)
    $decision = $policy->postAuth($userId, $result);

    if ($decision->isDenied()) {
        echo "DENIED (post): {$decision->getReason()}\n";
    } elseif ($decision->requiresAction()) {
        echo "OK but action required: {$decision->getAction()}\n";
    } elseif ($result instanceof AuthResultSuccess) {
        echo "SUCCESS: Welcome {$result->getNativeKey()}\n";
    } else {
        echo "FAILED: {$result->get('reason')}\n";
    }
};

// --- Demonstration ---

// Successful login
$authenticate('alice', 'correct');    // SUCCESS

// Three failures trigger lockout
$authenticate('alice', 'wrong');      // FAILED
$authenticate('alice', 'wrong');      // FAILED
$authenticate('alice', 'wrong');      // DENIED (post): locked

// Subsequent attempts are blocked in preAuth
$authenticate('alice', 'correct');    // DENIED (pre): locked

// Admin unlocks
$lockManager->unlock('alice');
$authenticate('alice', 'correct');    // SUCCESS
