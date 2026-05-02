<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit;

use Horde\Auth\Test\BaseTestCase;
use Horde\Auth\UserEntry;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(UserEntry::class)]
class UserEntryTest extends BaseTestCase
{
    public function testConstruction(): void
    {
        $entry = new UserEntry(
            userId: 'jsmith',
            backend: 'ldap',
            attributes: ['mail' => 'jsmith@example.com', 'cn' => 'John Smith'],
        );

        $this->assertSame('jsmith', $entry->getUserId());
        $this->assertSame('ldap', $entry->getBackend());
        $this->assertSame('jsmith@example.com', $entry->get('mail'));
        $this->assertSame('John Smith', $entry->get('cn'));
    }

    public function testEmptyAttributes(): void
    {
        $entry = new UserEntry(
            userId: 'hugo',
            backend: 'sql:local',
        );

        $this->assertSame('hugo', $entry->getUserId());
        $this->assertSame('sql:local', $entry->getBackend());
        $this->assertSame([], $entry->getAttributes());
        $this->assertNull($entry->get('email'));
    }

    public function testGetWithDefault(): void
    {
        $entry = new UserEntry(
            userId: 'admin',
            backend: 'breakglass',
            attributes: ['role' => 'emergency'],
        );

        $this->assertSame('emergency', $entry->get('role'));
        $this->assertSame('N/A', $entry->get('email', 'N/A'));
    }

    public function testBackendProvenance(): void
    {
        $sqlEntry = new UserEntry('hugo', 'sql:users');
        $ldapEntry = new UserEntry('hugo', 'ldap:corporate');

        $this->assertSame('sql:users', $sqlEntry->getBackend());
        $this->assertSame('ldap:corporate', $ldapEntry->getBackend());
        $this->assertSame($sqlEntry->getUserId(), $ldapEntry->getUserId());
    }
}
