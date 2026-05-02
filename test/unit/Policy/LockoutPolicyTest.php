<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit\Policy;

use DateTimeImmutable;
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Policy\LockoutPolicy;
use Horde\Auth\Storage\InMemoryAttemptTracker;
use Horde\Auth\Storage\InMemoryLockManager;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(LockoutPolicy::class)]
class LockoutPolicyTest extends BaseTestCase
{
    private InMemoryAttemptTracker $tracker;
    private InMemoryLockManager $lockManager;

    protected function setUp(): void
    {
        $this->tracker = new InMemoryAttemptTracker();
        $this->lockManager = new InMemoryLockManager();
    }

    private function createPolicy(int $maxAttempts = 3, int $lockDuration = 900): LockoutPolicy
    {
        return new LockoutPolicy($this->tracker, $this->lockManager, $maxAttempts, $lockDuration);
    }

    public function testPreAuthAllowsUnlockedUser(): void
    {
        $policy = $this->createPolicy();
        $decision = $policy->preAuth('alice');

        $this->assertTrue($decision->isAllowed());
    }

    public function testPreAuthDeniesLockedUser(): void
    {
        $this->lockManager->lock('alice');
        $policy = $this->createPolicy();

        $decision = $policy->preAuth('alice');

        $this->assertTrue($decision->isDenied());
        $this->assertSame('locked', $decision->getReason());
    }

    public function testPostAuthResetsCounterOnSuccess(): void
    {
        $this->tracker->recordFailure('alice');
        $this->tracker->recordFailure('alice');
        $policy = $this->createPolicy();

        $result = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice');
        $decision = $policy->postAuth('alice', $result);

        $this->assertTrue($decision->isAllowed());
        $this->assertSame(0, $this->tracker->getFailureCount('alice'));
    }

    public function testPostAuthRecordsFailure(): void
    {
        $policy = $this->createPolicy(maxAttempts: 5);

        $result = new AuthResultFail('test', new DateTimeImmutable(), ['reason' => 'bad_password']);
        $policy->postAuth('alice', $result);

        $this->assertSame(1, $this->tracker->getFailureCount('alice'));
    }

    public function testPostAuthLocksAfterMaxAttempts(): void
    {
        $policy = $this->createPolicy(maxAttempts: 3);
        $fail = new AuthResultFail('test', new DateTimeImmutable(), ['reason' => 'bad_password']);

        $policy->postAuth('alice', $fail);
        $policy->postAuth('alice', $fail);
        $decision = $policy->postAuth('alice', $fail);

        $this->assertTrue($decision->isDenied());
        $this->assertSame('locked', $decision->getReason());
        $this->assertTrue($this->lockManager->isLocked('alice'));
    }

    public function testPostAuthAllowsBeforeThreshold(): void
    {
        $policy = $this->createPolicy(maxAttempts: 3);
        $fail = new AuthResultFail('test', new DateTimeImmutable(), ['reason' => 'bad_password']);

        $decision = $policy->postAuth('alice', $fail);
        $this->assertTrue($decision->isAllowed());

        $decision = $policy->postAuth('alice', $fail);
        $this->assertTrue($decision->isAllowed());
    }

    public function testZeroMaxAttemptsDisablesAutoLock(): void
    {
        $policy = $this->createPolicy(maxAttempts: 0);
        $fail = new AuthResultFail('test', new DateTimeImmutable(), ['reason' => 'bad_password']);

        for ($i = 0; $i < 100; $i++) {
            $decision = $policy->postAuth('alice', $fail);
            $this->assertTrue($decision->isAllowed());
        }

        $this->assertFalse($this->lockManager->isLocked('alice'));
    }

    public function testPreAuthReturnsDenialMetadata(): void
    {
        $this->lockManager->lock('alice', 3600);
        $policy = $this->createPolicy();

        $decision = $policy->preAuth('alice');

        $this->assertTrue($decision->isDenied());
        $metadata = $decision->getMetadata();
        $this->assertArrayHasKey('locked_at', $metadata);
        $this->assertArrayHasKey('expires_at', $metadata);
    }
}
