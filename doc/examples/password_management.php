<?php

/**
 * Password management: change (user-driven) and reset (admin-driven).
 */

declare(strict_types=1);

namespace Horde\Auth\Examples;

use Horde\Auth\Mock;
use Horde\Auth\PasswordManager;
use Horde\Auth\PasswordPolicy;
use Horde\Auth\PasswordUtility;
use RuntimeException;

$auth = new Mock(users: [
    'alice' => ['password' => 'old-password', 'attributes' => []],
]);

assert($auth instanceof PasswordManager);

// --- User-driven password change (requires old password) ---

$newPassword = 'My-New-Pa$$w0rd';

// Optional: check policy before changing
$policy = new PasswordPolicy(minLength: 10, minClasses: 3);
$violations = PasswordUtility::checkPolicy($newPassword, $policy);

if (!empty($violations)) {
    echo "Policy violations:\n";
    foreach ($violations as $v) {
        echo "  - $v\n";
    }
} else {
    try {
        $auth->changePassword('alice', 'old-password', $newPassword);
        echo "Password changed successfully.\n";
    } catch (RuntimeException $e) {
        echo "Change failed: {$e->getMessage()}\n";
    }
}

// --- Admin-driven password reset (no old password needed) ---

$generated = $auth->resetPassword('alice');
echo "New password for alice: $generated\n";
