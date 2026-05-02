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

use RuntimeException;

/**
 * Queries user existence, lists, and searches a backend's user store.
 *
 * Returns UserEntry objects carrying backend provenance, not bare strings.
 * In multi-backend scenarios, the caller aggregates results from multiple
 * UserDirectory instances.
 */
interface UserDirectory
{
    /**
     * Check whether a user exists in this backend.
     *
     * @param string $userId The user identifier to look up
     *
     * @return bool True if the user exists in this backend
     *
     * @throws RuntimeException On infrastructure failure (backend unreachable)
     */
    public function exists(string $userId): bool;

    /**
     * List all users known to this backend.
     *
     * Implementations may return a generator for memory efficiency on
     * large directories. The caller should not assume random access.
     *
     * @return iterable<UserEntry> All user entries in this backend
     *
     * @throws RuntimeException On infrastructure failure or if listing is
     *         not supported/configured for this backend
     */
    public function list(): iterable;

    /**
     * Search for users matching a query string.
     *
     * The search semantics are backend-specific: SQL backends use LIKE,
     * LDAP backends use attribute filters, file-based backends use
     * substring matching on usernames.
     *
     * @param string $query The search term (substring, pattern, or filter
     *        depending on backend)
     *
     * @return iterable<UserEntry> Matching user entries (may be empty)
     *
     * @throws RuntimeException On infrastructure failure or if search is
     *         not supported/configured for this backend
     */
    public function search(string $query): iterable;
}
