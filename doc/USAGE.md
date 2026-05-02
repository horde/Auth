# Usage Guide

This guide covers common usage patterns for `Horde\Auth`. For migration from
the legacy API see [UPGRADING.md](UPGRADING.md).

## Concepts

The library separates authentication into distinct concerns:

- **Drivers** validate credentials or assert identity from request context
- **Access policies** enforce lockout, expiration and rate limiting around the auth flow
- **Storage interfaces** abstract the persistence of attempt counts and locks

Drivers implement only the interfaces they truly support. A certificate-based
driver does not pretend to manage users.

## Credential validation

The simplest use case: validate a username and password.

```php
use Horde\Auth\AuthResultSuccess;
use Horde\Auth\Sql;

$auth = new Sql(db: $db, encryption: 'crypt-blowfish');
$result = $auth->validate('alice', ['password' => 'secret']);

if ($result instanceof AuthResultSuccess) {
    $userId = $result->getNativeKey();
    $metadata = $result->getMetadata(); // backend-specific data
}
```

The result is never an exception for wrong credentials. `AuthResultFail`
carries a machine-readable reason (`bad_password`, `unknown_user`,
`empty_password`).

See [examples/basic_auth.php](examples/basic_auth.php).

## Transparent authentication

For environments where identity is established outside the application
(Shibboleth, client certificates, trusted proxies):

```php
use Horde\Auth\Shibboleth;

$provider = new Shibboleth(usernameHeader: 'Shib-Person-uid');
$result = $provider->extractIdentity($request); // PSR-7 ServerRequestInterface

if ($result !== null) {
    // identity is asserted
}
```

Returns `null` when this provider has nothing to say about the request — the
caller should try another provider or redirect to a login form.

See [examples/transparent_auth.php](examples/transparent_auth.php).

## User directory

Drivers implementing `UserDirectory` support existence checks, listing and
search:

```php
if ($auth->exists('alice')) { /* ... */ }

foreach ($auth->list() as $entry) {
    echo $entry->getUserId() . ' on ' . $entry->getBackend();
}

foreach ($auth->search('ali') as $entry) { /* ... */ }
```

Results are `UserEntry` objects carrying the user ID, backend identifier and
optional attributes.

## User lifecycle management

Drivers implementing `UserLifecycleManager` support CRUD operations:

```php
$entry = $auth->addUser('bob', ['password' => 'initial']);
$auth->renameUser('bob', 'robert');
$auth->updateUser('robert', ['password' => 'changed']);
$auth->removeUser('robert');
```

Use `instanceof UserLifecycleManager` to check at runtime.

See [examples/user_management.php](examples/user_management.php).

## Password management

Drivers implementing `PasswordManager` support password operations:

```php
// User-driven (requires old password verification)
$auth->changePassword('alice', 'old-pass', 'new-pass');

// Admin/reset-flow (generates random password, returns it)
$newPass = $auth->resetPassword('alice');
```

### Password policy validation

`PasswordUtility::checkPolicy()` validates complexity requirements before
changing:

```php
use Horde\Auth\PasswordPolicy;
use Horde\Auth\PasswordUtility;

$policy = new PasswordPolicy(minLength: 12, minClasses: 3);
$violations = PasswordUtility::checkPolicy($newPassword, $policy);
// $violations is empty if the password passes
```

See [examples/password_management.php](examples/password_management.php).

## Access policies

Access policies wrap the auth flow with pre- and post-checks for lockout,
expiration and other concerns orthogonal to credential validation.

### The flow

```php
use Horde\Auth\AccessDecision;

// 1. Pre-auth: is the user allowed to attempt login?
$decision = $policy->preAuth($userId);
if ($decision->isDenied()) {
    // e.g. account locked — do not hit the backend
    return;
}

// 2. Validate credentials
$result = $driver->validate($userId, $credentials);

// 3. Post-auth: record attempt, check expiration
$decision = $policy->postAuth($userId, $result);

if ($decision->isDenied()) {
    // e.g. hard password expiration — credentials valid but access denied
} elseif ($decision->requiresAction()) {
    // e.g. soft expiration — allow login but redirect to password change
    $action = $decision->getAction(); // 'change_password'
}
```

### AccessDecision states

| State | Meaning | Typical reasons |
|-------|---------|----------------|
| `allow` | Proceed normally | — |
| `deny` | Block access | `locked`, `hard_expired`, `rate_limited` |
| `requireAction` | Allow but advise | `change_password` |

### Built-in policies

#### LockoutPolicy

Blocks locked accounts (pre-auth) and auto-locks after N failures (post-auth):

```php
use Horde\Auth\Policy\LockoutPolicy;
use Horde\Auth\Storage\InMemoryAttemptTracker;
use Horde\Auth\Storage\InMemoryLockManager;

$policy = new LockoutPolicy(
    tracker: new InMemoryAttemptTracker(),
    lockManager: new InMemoryLockManager(),
    maxAttempts: 5,      // lock after 5 failures
    lockDuration: 900,   // 15 minutes (0 = permanent)
);
```

#### ExpirationPolicy

Enforces soft/hard password expiration from `AuthResultSuccess` metadata:

```php
use Horde\Auth\Policy\ExpirationPolicy;

$policy = new ExpirationPolicy();
// Reads 'soft_expiration' and 'hard_expiration' timestamps from result metadata.
// SQL and LDAP drivers set these when configured.
```

#### CompoundPolicy

Chains multiple policies — first deny wins, first requireAction wins:

```php
use Horde\Auth\Policy\CompoundPolicy;

$policy = new CompoundPolicy(
    new LockoutPolicy($tracker, $lockManager, maxAttempts: 5),
    new ExpirationPolicy(),
);
```

#### NullPolicy

Always allows. Use when policies are disabled or in tests:

```php
use Horde\Auth\Policy\NullPolicy;
$policy = new NullPolicy();
```

See [examples/access_policy.php](examples/access_policy.php).

## Storage interfaces

Policies require two storage backends:

| Interface | Purpose | In-memory impl |
|-----------|---------|----------------|
| `LoginAttemptTracker` | Count consecutive failures, reset on success | `InMemoryAttemptTracker` |
| `LockManager` | Lock/unlock accounts, time-limited or permanent | `InMemoryLockManager` |

The in-memory implementations are suitable for testing and single-process
scripts. Production deployments should use persistent backends (see below).

## Testing with Mock driver

The `Mock` driver implements all interfaces (CredentialProvider,
TransparentProvider, UserDirectory, UserLifecycleManager, PasswordManager)
backed by an in-memory array:

```php
use Horde\Auth\Mock;

$auth = new Mock(users: [
    'alice' => ['password' => 'secret', 'attributes' => ['role' => 'admin']],
    'bob'   => ['password' => 'pass123', 'attributes' => []],
]);

$result = $auth->validate('alice', ['password' => 'secret']);
$auth->addUser('carol', ['password' => 'new']);
$auth->removeUser('bob');
```

## Integration with Horde Core

In a full Horde deployment, Core provides the factory wiring and persistent
storage backends. The Auth library defines the interfaces and Core supplies the
implementations and configuration.

### Factory pattern

Core's `AuthFactory` (or equivalent DI container configuration) assembles the
driver and policy from `$conf['auth']`:

```php
// Simplified pseudocode. Actual Core factory reads conf.php
$driver = new Sql(db: $injector->getInstance(DbAdapter::class));

$tracker = new SqlAttemptTracker($db);       // Core provides this
$lockManager = new HordeLockAdapter($lock);  // Core wraps Horde_Lock

$policy = new CompoundPolicy(
    new LockoutPolicy($tracker, $lockManager,
        maxAttempts: $conf['auth']['login_block_count'],
        lockDuration: $conf['auth']['login_block_time'] * 60,
    ),
    new ExpirationPolicy(),
);
```

### Persistent storage backends (provided by Core)

| Auth interface | Core implementation | Backed by |
|---|---|---|
| `LoginAttemptTracker` | `SqlAttemptTracker` | `horde_login_attempts` table or `Horde_History` |
| `LockManager` | `HordeLockAdapter` | `Horde_Lock` (SQL/Mongo backends) |

### Configuration keys

Core maps these `conf.php` settings to the access policy:

| Key | Effect |
|-----|--------|
| `$conf['auth']['driver']` | Which `CredentialProvider` to instantiate |
| `$conf['auth']['login_block']` | Enable/disable lockout policy |
| `$conf['auth']['login_block_count']` | `LockoutPolicy::$maxAttempts` |
| `$conf['auth']['login_block_time']` | `LockoutPolicy::$lockDuration` (minutes) |
| `$conf['auth']['soft_expiration_window']` | Days until soft expiration (SQL driver metadata) |
| `$conf['auth']['hard_expiration_window']` | Days until hard expiration (SQL driver metadata) |

### The boundary

Auth library owns:
- Interfaces (`AccessPolicy`, `LoginAttemptTracker`, `LockManager`)
- Value objects (`AccessDecision`, `AuthResultSuccess`, `AuthResultFail`)
- Policy logic (`LockoutPolicy`, `ExpirationPolicy`, `CompoundPolicy`)
- In-memory implementations (testing/prototyping)
- Drivers (Sql, Ldap, Passwd, etc.)

Core owns:
- Persistent storage adapters (SQL tracker, Horde_Lock wrapper)
- Factory/DI wiring from configuration
- Session management and login flow orchestration
- Hook system (preauthenticate/postauthenticate hooks)
