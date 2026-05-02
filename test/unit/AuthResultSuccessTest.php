<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use DateTimeImmutable;
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(AuthResultSuccess::class)]
class AuthResultSuccessTest extends BaseTestCase
{
    public function testConstruction(): void
    {
        $timestamp = new DateTimeImmutable('2026-04-30 12:00:00');
        $result = new AuthResultSuccess(
            backend: 'ldap',
            timestamp: $timestamp,
            nativeKey: 'uid=jsmith,ou=people,dc=example,dc=com',
            metadata: ['mail' => 'jsmith@example.com', 'groups' => ['admin', 'users']],
        );

        $this->assertSame('ldap', $result->getBackend());
        $this->assertSame($timestamp, $result->getTimestamp());
        $this->assertSame('uid=jsmith,ou=people,dc=example,dc=com', $result->getNativeKey());
        $this->assertSame('jsmith@example.com', $result->get('mail'));
        $this->assertSame(['admin', 'users'], $result->get('groups'));
    }

    public function testEmptyMetadata(): void
    {
        $result = new AuthResultSuccess(
            backend: 'pam',
            timestamp: new DateTimeImmutable(),
            nativeKey: 'jsmith',
        );

        $this->assertSame([], $result->getMetadata());
        $this->assertNull($result->get('nonexistent'));
        $this->assertSame('default', $result->get('nonexistent', 'default'));
    }

    public function testGetWithDefault(): void
    {
        $result = new AuthResultSuccess(
            backend: 'sql',
            timestamp: new DateTimeImmutable(),
            nativeKey: '42',
            metadata: ['email' => 'test@example.com'],
        );

        $this->assertSame('test@example.com', $result->get('email'));
        $this->assertSame('fallback', $result->get('missing', 'fallback'));
        $this->assertNull($result->get('missing'));
    }
}
