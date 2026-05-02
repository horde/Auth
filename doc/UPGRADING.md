# Upgrading to the new Horde\Auth API

This document covers migrating from the legacy `Horde_Auth_Base` class hierarchy
(`lib/Horde/Auth/`) to the new interface-based architecture (`src/`).

Both APIs coexist in the same package via PSR-0 (`lib/`) and PSR-4 (`src/`)
autoloading. You can migrate incrementally.

## Key architectural changes

### Interfaces replace inheritance

The legacy `Horde_Auth_Base` abstract class with its capability array is gone.
Drivers now declare capabilities by implementing interfaces:

| Interface | Purpose |
|-----------|---------|
| `CredentialProvider` | Validate username + password against a backend |
| `TransparentProvider` | Assert identity from request context (certs, headers, IP) |
| `UserDirectory` | Query user existence, list, search |
| `UserLifecycleManager` | Create, remove, rename, update users |
| `PasswordManager` | Change or reset passwords |

Use `instanceof` to test capabilities at runtime.

### Result objects replace exceptions

Authentication failures are **not** exceptions. `validate()` returns either
`AuthResultSuccess` or `AuthResultFail`. Exceptions are reserved for
infrastructure failures (backend unreachable, extension missing).

```php
// Legacy
try {
    $auth->authenticate($user, ['password' => $pass]);
} catch (Horde_Auth_Exception $e) {
    // failure
}

// New
$result = $driver->validate($user, ['password' => $pass]);
if ($result instanceof AuthResultFail) {
    $reason = $result->get('reason'); // 'bad_password', 'unknown_user', etc.
}
```

### No session state in drivers

Drivers no longer call `setCredential()` / `getCredential()` or manipulate
sessions. The caller (typically Core) decides how to use the result.

### No locking or login-attempt tracking in drivers

Bad-login counting and account lockout are no longer driver concerns. They have
been extracted into the `AccessPolicy` layer (see below).

## Namespace mapping

All new classes live under `Horde\Auth\`:

| Legacy class | New class |
|---|---|
| `Horde_Auth_Sql` | `Horde\Auth\Sql` |
| `Horde_Auth_Customsql` | `Horde\Auth\Customsql` |
| `Horde_Auth_Passwd` | `Horde\Auth\Passwd` (read-only) |
| — | `Horde\Auth\WritablePasswd` (read-write) |
| `Horde_Auth_Ldap` | `Horde\Auth\Ldap` (read-only) |
| — | `Horde\Auth\WritableLdap` (read-write) |
| `Horde_Auth_Ftp` | `Horde\Auth\Ftp` |
| `Horde_Auth_Radius` | `Horde\Auth\Radius` |
| `Horde_Auth_Pam` | `Horde\Auth\Pam` |
| `Horde_Auth_Peclsasl` | `Horde\Auth\Peclsasl` |
| `Horde_Auth_Smb` | `Horde\Auth\Smb` |
| `Horde_Auth_Smbclient` | `Horde\Auth\Smbclient` |
| `Horde_Auth_Login` | `Horde\Auth\Login` |
| `Horde_Auth_Http` | `Horde\Auth\Http` |
| `Horde_Auth_Shibboleth` | `Horde\Auth\Shibboleth` |
| `Horde_Auth_X509` | `Horde\Auth\X509` |
| `Horde_Auth_Ipbasic` | `Horde\Auth\Ipbasic` |
| `Horde_Auth_Auto` | `Horde\Auth\Auto` |
| `Horde_Auth_Imap` | `Horde\Auth\Imap` (credential-only) |
| — | `Horde\Auth\WritableImap` (user management) |
| — | `Horde\Auth\Mock` (testing) |

## Constructor changes

Drivers use named constructor parameters instead of a `$params` array:

```php
// Legacy
$auth = new Horde_Auth_Sql([
    'db' => $db,
    'table' => 'horde_users',
    'encryption' => 'crypt-blowfish',
]);

// New
$auth = new Sql(
    db: $db,
    table: 'horde_users',
    encryption: 'crypt-blowfish',
);
```

## TransparentProvider replaces transparent auth

The legacy `transparent()` method on `Horde_Auth_Base` is replaced by the
`TransparentProvider` interface and its `extractIdentity()` method, which
accepts a PSR-7 `ServerRequestInterface`:

```php
// Legacy
if ($auth->transparent()) {
    $user = $auth->getCredential('userId');
}

// New
$result = $provider->extractIdentity($request);
if ($result !== null) {
    $user = $result->getNativeKey();
}
```

## Password hashing

`Horde_Auth::getCryptedPassword()` is replaced by `PasswordUtility::crypt()`.
The same encryption schemes are supported (`crypt-blowfish`, `crypt-sha256`,
`ssha`, `md5-hex`, `plain`, etc.).

## Passwd driver split

The legacy `Horde_Auth_Passwd` handled both reading and writing. The new API
splits this into:

- `Passwd` read-only (`CredentialProvider` + `UserDirectory`)
- `WritablePasswd` extends `Passwd`, adds `UserLifecycleManager` + `PasswordManager`

Use `WritablePasswd` only when you need to modify the file.

## LDAP driver split

The legacy `Horde_Auth_Ldap` implemented everything in one class and used a
runtime `$activeDirectory` flag to disable write operations. The new API splits
this cleanly:

- `Ldap` — read-only (`CredentialProvider` + `UserDirectory`): validates by
  binding as the user, lists/searches entries
- `WritableLdap` — extends `Ldap`, adds `UserLifecycleManager` + `PasswordManager`:
  creates/removes/renames LDAP entries, changes/resets passwords

`WritableLdap` rejects Active Directory in its constructor — AD deployments
should use the read-only `Ldap` driver and AD-specific tooling for lifecycle.

```php
// Legacy
$auth = new Horde_Auth_Ldap([
    'basedn' => 'ou=people,dc=example,dc=com',
    'ldap' => $ldap,
    'uid' => 'uid',
    'encryption' => 'ssha',
]);

// New (read-only)
$auth = new Ldap(
    ldap: $ldap,
    baseDn: 'ou=people,dc=example,dc=com',
    uidAttribute: 'uid',
);

// New (with write access)
$auth = new WritableLdap(
    ldap: $ldap,
    baseDn: 'ou=people,dc=example,dc=com',
    uidAttribute: 'uid',
    encryption: 'ssha',
);
```

## IMAP driver split

The legacy `Horde_Auth_Imap` mixed credential validation with mailbox-based
user management (create/delete/list). The new API splits this:

- `Imap` — credential-only (`CredentialProvider`): validates by attempting login
- `WritableImap` — extends `Imap`, adds `UserDirectory` + `UserLifecycleManager`
  (mailbox creation/deletion with ACL management via admin credentials)

Both accept a `Closure` factory that returns a `MailboxProtocol` (or
`ImapProtocol & ImapAclAware` for the writable variant) from a
`ConnectionConfig`. This decouples Auth from any specific socket implementation.

```php
// Legacy
$auth = new Horde_Auth_Imap([
    'hostspec' => 'imap.example.com',
    'secure' => 'tls',
    'admin_user' => 'admin',
    'admin_password' => 'secret',
    'userhierarchy' => 'user.',
]);

// New (credential-only)
$auth = new Imap(
    clientFactory: fn (ConnectionConfig $c) => new ImapSocket($c),
    hostspec: 'imap.example.com',
    secure: SecureMode::Tls,
);

// New (with user management)
$auth = new WritableImap(
    clientFactory: fn (ConnectionConfig $c) => new ImapSocket($c),
    hostspec: 'imap.example.com',
    secure: SecureMode::Tls,
    adminUser: 'admin',
    adminPassword: 'secret',
    userHierarchy: 'user.',
);
```

## Removed functionality

- `Horde_Auth_Base::getCredential()` / `setCredential()` — no session state
- `Horde_Auth_Base::getParam()` — use constructor params directly
- `Horde_Auth_Base::hasCapability()` — use `instanceof` checks
- `Horde_Auth_Exception` for auth failures — use `AuthResultFail`
- `Horde_Auth_Cyrus` — use Customsql or Sql with appropriate queries
- `Horde_Auth_Composite` — will be redesigned separately

## Access policy migration

The legacy `Horde_Auth_Base` embedded lockout and expiration logic directly,
using injected `Horde_History` and `Horde_Lock` instances. The new architecture
extracts this into a composable `AccessPolicy` layer.

### Legacy approach

```php
// Built into Horde_Auth_Base and configured via params:
$auth = new Horde_Auth_Sql([
    'db' => $db,
    'history_api' => $history,     // for bad login counting
    'lock_api' => $lock,           // for account locking
    'login_block_count' => 5,
    'login_block_time' => 15,
]);

// Lockout was invisible — happened inside authenticate()
$auth->authenticate($user, ['password' => $pass]);
```

### New approach

```php
use Horde\Auth\Policy\CompoundPolicy;
use Horde\Auth\Policy\ExpirationPolicy;
use Horde\Auth\Policy\LockoutPolicy;
use Horde\Auth\Sql;
use Horde\Auth\Storage\InMemoryAttemptTracker;
use Horde\Auth\Storage\InMemoryLockManager;

// Driver is pure credential validation
$driver = new Sql(db: $db, encryption: 'crypt-blowfish');

// Policy is separate and explicit
$policy = new CompoundPolicy(
    new LockoutPolicy(
        new InMemoryAttemptTracker(),
        new InMemoryLockManager(),
        maxAttempts: 5,
        lockDuration: 900,
    ),
    new ExpirationPolicy(),
);

// Caller orchestrates the flow
$decision = $policy->preAuth($userId);
if ($decision->isDenied()) { /* blocked */ }

$result = $driver->validate($userId, ['password' => $pass]);

$decision = $policy->postAuth($userId, $result);
if ($decision->isDenied()) { /* hard expiration */ }
if ($decision->requiresAction()) { /* soft expiration → change password */ }
```

### Key differences

| Aspect | Legacy | New |
|--------|--------|-----|
| Lockout logic | Inside `authenticate()` | Explicit `AccessPolicy` |
| Storage coupling | `Horde_History` + `Horde_Lock` | `LoginAttemptTracker` + `LockManager` interfaces |
| Visibility | Hidden side effects | Caller sees `AccessDecision` |
| Composability | Monolithic | Chain policies via `CompoundPolicy` |
| Testing | Requires mocking History/Lock | Use in-memory implementations |

### Storage interface mapping

| Legacy | New interface | In-memory impl |
|--------|---|---|
| `Horde_History` (bad login log) | `LoginAttemptTracker` | `InMemoryAttemptTracker` |
| `Horde_Lock` (account locks) | `LockManager` | `InMemoryLockManager` |

Production adapters wrapping `Horde_History` and `Horde_Lock` will be provided
by `horde/core`.
