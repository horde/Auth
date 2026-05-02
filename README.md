# Horde Auth

Authentication and user management library for the Horde framework.

Provides a clean, interface-based architecture for credential validation,
transparent authentication, user directory queries, user lifecycle management,
and password operations across multiple backends.

## New in this version

The main interface has been split into several capability oriented interface.
Drivers no longer pseudo implement capabilities they don't really have but only expose those interfaces they really provide,
i.e. certificate authentication does no longer provide an interface to list users or change passwords.
Authentication results are now objects instead of booleans.

## Installation

```bash
composer require horde/auth
```

## Interfaces

| Interface | Purpose |
|-----------|---------|
| `CredentialProvider` | Validate credentials (username + password) |
| `TransparentProvider` | Assert identity from HTTP request context |
| `UserDirectory` | Check existence, list, and search users |
| `UserLifecycleManager` | Add, remove, rename, and update users |
| `PasswordManager` | Change and reset passwords |
| `AccessPolicy` | Pre/post-auth hooks for lockout, expiration, rate limiting |
| `LoginAttemptTracker` | Count and reset failed login attempts |
| `LockManager` | Lock/unlock user accounts |

## Available drivers

`Sql`, `Customsql`, `Ldap`, `Passwd`, `WritablePasswd`, `Ftp`, `Http`,
`Radius`, `Pam`, `Peclsasl`, `Smb`, `Smbclient`, `Login`, `Shibboleth`,
`X509`, `Ipbasic`, `Auto`, `Mock`

## Quick example

```php
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Policy\CompoundPolicy;
use Horde\Auth\Policy\LockoutPolicy;
use Horde\Auth\Sql;
use Horde\Auth\Storage\InMemoryAttemptTracker;
use Horde\Auth\Storage\InMemoryLockManager;

$auth = new Sql(db: $db, encryption: 'crypt-blowfish');
$policy = new CompoundPolicy(
    new LockoutPolicy(new InMemoryAttemptTracker(), new InMemoryLockManager()),
);

$decision = $policy->preAuth('alice');
if (!$decision->isDenied()) {
    $result = $auth->validate('alice', ['password' => 'secret']);
    $decision = $policy->postAuth('alice', $result);
}
```

## Documentation

- [doc/USAGE.md](doc/USAGE.md) — full usage guide with examples
- [doc/UPGRADING.md](doc/UPGRADING.md) — migration from legacy `Horde_Auth_Base`
- [doc/examples/](doc/examples/) — runnable example scripts

## License

LGPL-2.1 - see [LICENSE](LICENSE).
