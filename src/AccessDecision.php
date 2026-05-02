<?php

declare(strict_types=1);

/**
 * Copyright 1999-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Chuck Hagenbuch <chuck@horde.org>
 * @author   Michael Slusarz <slusarz@horde.org>
 * @license  http://www.horde.org/licenses/lgpl21 LGPL-2.1
 */

namespace Horde\Auth;

/**
 * Immutable value object representing an access control decision.
 *
 * Three possible states:
 * - **allow**: proceed normally
 * - **deny**: block access (reason explains why: 'locked', 'hard_expired', etc.)
 * - **requireAction**: allow access but advise the caller that an action is
 *   needed (e.g. 'change_password' for soft expiration)
 *
 * Construct via named constructors: allow(), deny(), requireAction().
 */
class AccessDecision
{
    private const STATE_ALLOW = 'allow';
    private const STATE_DENY = 'deny';
    private const STATE_REQUIRE_ACTION = 'require_action';

    private function __construct(
        private readonly string $state,
        private readonly ?string $reason = null,
        private readonly ?string $action = null,
        private readonly array $metadata = [],
    ) {}

    /**
     * Create an "allow" decision — proceed normally.
     */
    public static function allow(): self
    {
        return new self(self::STATE_ALLOW);
    }

    /**
     * Create a "deny" decision — block access entirely.
     *
     * @param string $reason Machine-readable reason code (e.g. 'locked',
     *        'hard_expired', 'rate_limited')
     * @param array<string, mixed> $metadata Additional context (e.g.
     *        ['locked_until' => DateTimeImmutable, 'attempts' => 5])
     */
    public static function deny(string $reason, array $metadata = []): self
    {
        return new self(self::STATE_DENY, reason: $reason, metadata: $metadata);
    }

    /**
     * Create a "require action" decision — allow but advise a needed step.
     *
     * @param string $action Machine-readable action code (e.g. 'change_password')
     * @param array<string, mixed> $metadata Additional context (e.g.
     *        ['expired_at' => DateTimeImmutable])
     */
    public static function requireAction(string $action, array $metadata = []): self
    {
        return new self(self::STATE_REQUIRE_ACTION, action: $action, metadata: $metadata);
    }

    public function isAllowed(): bool
    {
        return $this->state === self::STATE_ALLOW;
    }

    public function isDenied(): bool
    {
        return $this->state === self::STATE_DENY;
    }

    public function requiresAction(): bool
    {
        return $this->state === self::STATE_REQUIRE_ACTION;
    }

    /**
     * @return string|null The denial reason code, or null if not denied
     */
    public function getReason(): ?string
    {
        return $this->reason;
    }

    /**
     * @return string|null The required action code, or null if no action needed
     */
    public function getAction(): ?string
    {
        return $this->action;
    }

    /**
     * @return array<string, mixed>
     */
    public function getMetadata(): array
    {
        return $this->metadata;
    }
}
