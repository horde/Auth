<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit\Policy;

use DateTimeImmutable;
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Policy\CompoundPolicy;
use Horde\Auth\Policy\ExpirationPolicy;
use Horde\Auth\Policy\LockoutPolicy;
use Horde\Auth\Policy\NullPolicy;
use Horde\Auth\Storage\InMemoryAttemptTracker;
use Horde\Auth\Storage\InMemoryLockManager;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(CompoundPolicy::class)]
class CompoundPolicyTest extends BaseTestCase
{
    public function testEmptyCompoundAlwaysAllows(): void
    {
        $policy = new CompoundPolicy();

        $this->assertTrue($policy->preAuth('alice')->isAllowed());

        $result = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice');
        $this->assertTrue($policy->postAuth('alice', $result)->isAllowed());
    }

    public function testFirstDenyWinsInPreAuth(): void
    {
        $lockManager = new InMemoryLockManager();
        $lockManager->lock('alice');

        $lockout = new LockoutPolicy(new InMemoryAttemptTracker(), $lockManager);
        $null = new NullPolicy();

        $policy = new CompoundPolicy($null, $lockout);
        $decision = $policy->preAuth('alice');

        $this->assertTrue($decision->isDenied());
        $this->assertSame('locked', $decision->getReason());
    }

    public function testFirstDenyWinsInPostAuth(): void
    {
        $past = time() - 86400;
        $success = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice', [
            'hard_expiration' => $past,
        ]);

        $expiration = new ExpirationPolicy();
        $null = new NullPolicy();

        $policy = new CompoundPolicy($null, $expiration);
        $decision = $policy->postAuth('alice', $success);

        $this->assertTrue($decision->isDenied());
        $this->assertSame('hard_expired', $decision->getReason());
    }

    public function testRequireActionReturnedWhenNoDeny(): void
    {
        $past = time() - 86400;
        $success = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice', [
            'soft_expiration' => $past,
        ]);

        $expiration = new ExpirationPolicy();
        $null = new NullPolicy();

        $policy = new CompoundPolicy($null, $expiration, $null);
        $decision = $policy->postAuth('alice', $success);

        $this->assertTrue($decision->requiresAction());
        $this->assertSame('change_password', $decision->getAction());
    }

    public function testDenyOverridesRequireAction(): void
    {
        $past = time() - 86400;
        $success = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice', [
            'soft_expiration' => $past,
            'hard_expiration' => $past,
        ]);

        $expiration = new ExpirationPolicy();
        $policy = new CompoundPolicy($expiration);
        $decision = $policy->postAuth('alice', $success);

        $this->assertTrue($decision->isDenied());
    }

    public function testAllPoliciesAllowReturnsAllow(): void
    {
        $success = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice');

        $policy = new CompoundPolicy(new NullPolicy(), new NullPolicy(), new NullPolicy());
        $decision = $policy->postAuth('alice', $success);

        $this->assertTrue($decision->isAllowed());
    }

    public function testLockoutAndExpirationTogether(): void
    {
        $tracker = new InMemoryAttemptTracker();
        $lockManager = new InMemoryLockManager();
        $lockout = new LockoutPolicy($tracker, $lockManager, 3, 900);
        $expiration = new ExpirationPolicy();

        $policy = new CompoundPolicy($lockout, $expiration);

        // Simulate 3 failures
        $fail = new AuthResultFail('test', new DateTimeImmutable(), ['reason' => 'bad_password']);
        $policy->postAuth('alice', $fail);
        $policy->postAuth('alice', $fail);
        $policy->postAuth('alice', $fail);

        // Now preAuth should deny
        $decision = $policy->preAuth('alice');
        $this->assertTrue($decision->isDenied());
        $this->assertSame('locked', $decision->getReason());
    }
}
