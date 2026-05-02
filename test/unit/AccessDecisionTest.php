<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\AccessDecision;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(AccessDecision::class)]
class AccessDecisionTest extends BaseTestCase
{
    public function testAllowIsAllowed(): void
    {
        $decision = AccessDecision::allow();

        $this->assertTrue($decision->isAllowed());
        $this->assertFalse($decision->isDenied());
        $this->assertFalse($decision->requiresAction());
        $this->assertNull($decision->getReason());
        $this->assertNull($decision->getAction());
        $this->assertSame([], $decision->getMetadata());
    }

    public function testDenyIsDenied(): void
    {
        $decision = AccessDecision::deny('locked', ['attempts' => 5]);

        $this->assertFalse($decision->isAllowed());
        $this->assertTrue($decision->isDenied());
        $this->assertFalse($decision->requiresAction());
        $this->assertSame('locked', $decision->getReason());
        $this->assertNull($decision->getAction());
        $this->assertSame(['attempts' => 5], $decision->getMetadata());
    }

    public function testRequireActionState(): void
    {
        $decision = AccessDecision::requireAction('change_password', ['expired_at' => 12345]);

        $this->assertFalse($decision->isAllowed());
        $this->assertFalse($decision->isDenied());
        $this->assertTrue($decision->requiresAction());
        $this->assertNull($decision->getReason());
        $this->assertSame('change_password', $decision->getAction());
        $this->assertSame(['expired_at' => 12345], $decision->getMetadata());
    }

    public function testDenyWithoutMetadata(): void
    {
        $decision = AccessDecision::deny('rate_limited');

        $this->assertTrue($decision->isDenied());
        $this->assertSame('rate_limited', $decision->getReason());
        $this->assertSame([], $decision->getMetadata());
    }

    public function testRequireActionWithoutMetadata(): void
    {
        $decision = AccessDecision::requireAction('verify_email');

        $this->assertTrue($decision->requiresAction());
        $this->assertSame('verify_email', $decision->getAction());
        $this->assertSame([], $decision->getMetadata());
    }
}
