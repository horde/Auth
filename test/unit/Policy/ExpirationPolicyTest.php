<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit\Policy;

use DateTimeImmutable;
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Policy\ExpirationPolicy;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ExpirationPolicy::class)]
class ExpirationPolicyTest extends BaseTestCase
{
    private ExpirationPolicy $policy;

    protected function setUp(): void
    {
        $this->policy = new ExpirationPolicy();
    }

    public function testPreAuthAlwaysAllows(): void
    {
        $decision = $this->policy->preAuth('alice');
        $this->assertTrue($decision->isAllowed());
    }

    public function testPostAuthAllowsOnFail(): void
    {
        $fail = new AuthResultFail('test', new DateTimeImmutable(), ['reason' => 'bad_password']);
        $decision = $this->policy->postAuth('alice', $fail);

        $this->assertTrue($decision->isAllowed());
    }

    public function testPostAuthAllowsWithNoExpirationMetadata(): void
    {
        $success = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice');
        $decision = $this->policy->postAuth('alice', $success);

        $this->assertTrue($decision->isAllowed());
    }

    public function testPostAuthAllowsWithFutureExpiration(): void
    {
        $future = time() + 86400;
        $success = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice', [
            'soft_expiration' => $future,
            'hard_expiration' => $future,
        ]);

        $decision = $this->policy->postAuth('alice', $success);
        $this->assertTrue($decision->isAllowed());
    }

    public function testPostAuthDeniesOnHardExpiration(): void
    {
        $past = time() - 86400;
        $success = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice', [
            'hard_expiration' => $past,
        ]);

        $decision = $this->policy->postAuth('alice', $success);

        $this->assertTrue($decision->isDenied());
        $this->assertSame('hard_expired', $decision->getReason());
        $this->assertArrayHasKey('expired_at', $decision->getMetadata());
    }

    public function testPostAuthRequiresActionOnSoftExpiration(): void
    {
        $past = time() - 86400;
        $success = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice', [
            'soft_expiration' => $past,
        ]);

        $decision = $this->policy->postAuth('alice', $success);

        $this->assertTrue($decision->requiresAction());
        $this->assertSame('change_password', $decision->getAction());
        $this->assertArrayHasKey('expired_at', $decision->getMetadata());
    }

    public function testHardExpirationTakesPrecedenceOverSoft(): void
    {
        $past = time() - 86400;
        $success = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice', [
            'soft_expiration' => $past,
            'hard_expiration' => $past,
        ]);

        $decision = $this->policy->postAuth('alice', $success);

        $this->assertTrue($decision->isDenied());
        $this->assertSame('hard_expired', $decision->getReason());
    }

    public function testAcceptsDateTimeImmutableValues(): void
    {
        $past = new DateTimeImmutable('-1 day');
        $success = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice', [
            'soft_expiration' => $past,
        ]);

        $decision = $this->policy->postAuth('alice', $success);
        $this->assertTrue($decision->requiresAction());
    }

    public function testAcceptsStringTimestampValues(): void
    {
        $past = (string) (time() - 86400);
        $success = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice', [
            'hard_expiration' => $past,
        ]);

        $decision = $this->policy->postAuth('alice', $success);
        $this->assertTrue($decision->isDenied());
    }
}
