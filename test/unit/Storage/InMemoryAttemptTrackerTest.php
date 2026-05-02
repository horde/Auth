<?php

declare(strict_types=1);

namespace Horde\Auth\Test\Unit\Storage;

use Horde\Auth\Storage\InMemoryAttemptTracker;
use Horde\Auth\Test\BaseTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(InMemoryAttemptTracker::class)]
class InMemoryAttemptTrackerTest extends BaseTestCase
{
    public function testInitialCountIsZero(): void
    {
        $tracker = new InMemoryAttemptTracker();
        $this->assertSame(0, $tracker->getFailureCount('alice'));
    }

    public function testRecordFailureIncrements(): void
    {
        $tracker = new InMemoryAttemptTracker();
        $tracker->recordFailure('alice');
        $this->assertSame(1, $tracker->getFailureCount('alice'));

        $tracker->recordFailure('alice');
        $this->assertSame(2, $tracker->getFailureCount('alice'));
    }

    public function testResetFailuresClearsCount(): void
    {
        $tracker = new InMemoryAttemptTracker();
        $tracker->recordFailure('alice');
        $tracker->recordFailure('alice');
        $tracker->recordFailure('alice');

        $tracker->resetFailures('alice');
        $this->assertSame(0, $tracker->getFailureCount('alice'));
    }

    public function testUsersAreIndependent(): void
    {
        $tracker = new InMemoryAttemptTracker();
        $tracker->recordFailure('alice');
        $tracker->recordFailure('alice');
        $tracker->recordFailure('bob');

        $this->assertSame(2, $tracker->getFailureCount('alice'));
        $this->assertSame(1, $tracker->getFailureCount('bob'));

        $tracker->resetFailures('alice');
        $this->assertSame(0, $tracker->getFailureCount('alice'));
        $this->assertSame(1, $tracker->getFailureCount('bob'));
    }

    public function testResetNonexistentUserIsNoOp(): void
    {
        $tracker = new InMemoryAttemptTracker();
        $tracker->resetFailures('nobody');
        $this->assertSame(0, $tracker->getFailureCount('nobody'));
    }
}
