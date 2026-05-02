<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit\Policy;

use DateTimeImmutable;
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Policy\NullPolicy;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(NullPolicy::class)]
class NullPolicyTest extends BaseTestCase
{
    public function testPreAuthAlwaysAllows(): void
    {
        $policy = new NullPolicy();
        $this->assertTrue($policy->preAuth('anyone')->isAllowed());
    }

    public function testPostAuthAlwaysAllowsOnSuccess(): void
    {
        $policy = new NullPolicy();
        $result = new AuthResultSuccess('test', new DateTimeImmutable(), 'alice');
        $this->assertTrue($policy->postAuth('alice', $result)->isAllowed());
    }

    public function testPostAuthAlwaysAllowsOnFail(): void
    {
        $policy = new NullPolicy();
        $result = new AuthResultFail('test', new DateTimeImmutable(), ['reason' => 'bad']);
        $this->assertTrue($policy->postAuth('alice', $result)->isAllowed());
    }
}
