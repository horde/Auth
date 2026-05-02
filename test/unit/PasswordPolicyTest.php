<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\PasswordPolicy;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use ReflectionClass;

#[CoversClass(PasswordPolicy::class)]
class PasswordPolicyTest extends BaseTestCase
{
    public function testDefaults(): void
    {
        $policy = new PasswordPolicy();

        $this->assertSame(8, $policy->minLength);
        $this->assertSame(0, $policy->maxLength);
        $this->assertSame(0, $policy->minUppercase);
        $this->assertSame(0, $policy->minLowercase);
        $this->assertSame(0, $policy->minNumeric);
        $this->assertSame(0, $policy->minSymbol);
        $this->assertSame(0, $policy->minClasses);
    }

    public function testCustomValues(): void
    {
        $policy = new PasswordPolicy(
            minLength: 12,
            maxLength: 128,
            minUppercase: 1,
            minLowercase: 1,
            minNumeric: 2,
            minSymbol: 1,
            minClasses: 3,
        );

        $this->assertSame(12, $policy->minLength);
        $this->assertSame(128, $policy->maxLength);
        $this->assertSame(1, $policy->minUppercase);
        $this->assertSame(1, $policy->minLowercase);
        $this->assertSame(2, $policy->minNumeric);
        $this->assertSame(1, $policy->minSymbol);
        $this->assertSame(3, $policy->minClasses);
    }

    public function testImmutability(): void
    {
        $policy = new PasswordPolicy(minLength: 10);

        // readonly properties cannot be modified — this verifies the contract
        $reflection = new ReflectionClass($policy);
        foreach ($reflection->getProperties() as $property) {
            $this->assertTrue($property->isReadOnly());
        }
    }
}
