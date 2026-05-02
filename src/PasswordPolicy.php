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
 * Password complexity requirements.
 *
 * Immutable value object describing the rules a password must satisfy.
 * A value of 0 means "no constraint" for that dimension.
 */
class PasswordPolicy
{
    public function __construct(
        public readonly int $minLength = 8,
        public readonly int $maxLength = 0,
        public readonly int $minUppercase = 0,
        public readonly int $minLowercase = 0,
        public readonly int $minNumeric = 0,
        public readonly int $minSymbol = 0,
        public readonly int $minClasses = 0,
    ) {}
}
