<?php

/**
 * Stubs for Horde_Ldap classes.
 *
 * These exist so unit tests can mock LDAP types without requiring
 * horde/ldap as a dev dependency.
 */

declare(strict_types=1);

if (!class_exists('Horde_Ldap', false)) {
    class Horde_Ldap
    {
        public function bind(?string $dn = null, ?string $password = null): bool
        {
            return true;
        }

        public function search(string $base, $filter, array $params = []): Horde_Ldap_Search
        {
            return new Horde_Ldap_Search();
        }

        public function getEntry(string $dn): Horde_Ldap_Entry
        {
            return new Horde_Ldap_Entry();
        }

        public function add(Horde_Ldap_Entry $entry): void {}

        public function delete(string $dn): void {}

        public function move(string $dn, string $newLocation): void {}

        public static function createEntry(string $dn, array $attrs): Horde_Ldap_Entry
        {
            return new Horde_Ldap_Entry();
        }
    }
}

if (!class_exists('Horde_Ldap_Entry', false)) {
    class Horde_Ldap_Entry
    {
        private array $values = [];

        public function dn(): string
        {
            return '';
        }

        public function getValues(): array
        {
            return $this->values;
        }

        public function replace(array $attrs): void {}

        public function update(): void {}
    }
}

if (!class_exists('Horde_Ldap_Search', false)) {
    class Horde_Ldap_Search implements IteratorAggregate, Countable
    {
        private array $entries = [];

        public function count(): int
        {
            return count($this->entries);
        }

        public function current(): ?Horde_Ldap_Entry
        {
            return $this->entries[0] ?? null;
        }

        public function getIterator(): ArrayIterator
        {
            return new ArrayIterator($this->entries);
        }
    }
}

if (!class_exists('Horde_Ldap_Filter', false)) {
    class Horde_Ldap_Filter
    {
        private string $repr;

        private function __construct(string $repr = '')
        {
            $this->repr = $repr;
        }

        public static function create(string $attr, string $match, string $value): self
        {
            return new self("($attr $match $value)");
        }

        public static function combine(string $op, array $filters): self
        {
            return new self("($op ...)");
        }

        public static function parse(string $filter): self
        {
            return new self($filter);
        }

        public function __toString(): string
        {
            return $this->repr;
        }
    }
}

if (!class_exists('Horde_Ldap_Exception', false)) {
    class Horde_Ldap_Exception extends RuntimeException {}
}
