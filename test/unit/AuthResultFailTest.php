<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use DateTimeImmutable;
use Horde\Auth\AuthResultFail;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(AuthResultFail::class)]
class AuthResultFailTest extends BaseTestCase
{
    public function testConstruction(): void
    {
        $timestamp = new DateTimeImmutable('2026-04-30 12:00:00');
        $result = new AuthResultFail(
            backend: 'ldap',
            timestamp: $timestamp,
            metadata: ['reason' => 'account_expired'],
        );

        $this->assertSame('ldap', $result->getBackend());
        $this->assertSame($timestamp, $result->getTimestamp());
        $this->assertSame('account_expired', $result->get('reason'));
    }

    public function testEmptyMetadata(): void
    {
        $result = new AuthResultFail(
            backend: 'sql',
            timestamp: new DateTimeImmutable(),
        );

        $this->assertSame([], $result->getMetadata());
        $this->assertNull($result->get('reason'));
    }

    public function testCompositeSubResults(): void
    {
        $ldapFail = new AuthResultFail(
            backend: 'ldap',
            timestamp: new DateTimeImmutable(),
            metadata: ['reason' => 'unknown_user'],
        );
        $sqlFail = new AuthResultFail(
            backend: 'sql:local',
            timestamp: new DateTimeImmutable(),
            metadata: ['reason' => 'bad_password'],
        );

        $composite = new AuthResultFail(
            backend: 'composite',
            timestamp: new DateTimeImmutable(),
            metadata: ['attempts' => [$ldapFail, $sqlFail]],
        );

        $this->assertSame('composite', $composite->getBackend());
        $attempts = $composite->get('attempts');
        $this->assertCount(2, $attempts);
        $this->assertInstanceOf(AuthResultFail::class, $attempts[0]);
        $this->assertSame('ldap', $attempts[0]->getBackend());
        $this->assertSame('unknown_user', $attempts[0]->get('reason'));
        $this->assertSame('sql:local', $attempts[1]->getBackend());
        $this->assertSame('bad_password', $attempts[1]->get('reason'));
    }

    public function testGetWithDefault(): void
    {
        $result = new AuthResultFail(
            backend: 'radius',
            timestamp: new DateTimeImmutable(),
            metadata: ['code' => 3],
        );

        $this->assertSame(3, $result->get('code'));
        $this->assertSame('unknown', $result->get('message', 'unknown'));
    }
}
