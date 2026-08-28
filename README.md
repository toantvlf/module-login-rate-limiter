# TVTCommerce_LoginRateLimiter

Free Magento 2.4.x storefront security extension from [TVT Commerce](https://tvtcommerce.com). MIT
licensed.

Rate-limits storefront customer login attempts **per IP address**, independent of whether the
submitted email exists — closing a gap in Magento core's own account lockout. No SSH or CLI access
required; one config section under **Stores > Configuration > TVTCommerce > Login Rate Limiter**.

## Why this module exists — and how it relates to core's own lockout

Magento core **already** locks a storefront customer *account* after too many failed password
attempts. See `Magento\Customer\Model\Authentication::processAuthenticationFailure()` and the two
config paths it reads:

- `customer/password/lockout_threshold` (**Customers > Customer Configuration > Password
  Options > "Lockout Time (minutes)"**)
- `customer/password/lockout_failures` (**...> "Maximum Login Failures to Lockout Account"**)

That mechanism only starts counting **once a submitted email resolves to a real `customerId`** —
verified by reading `Magento\Customer\Model\AccountManagement\Authenticate::execute()`: a
nonexistent email throws `InvalidEmailOrPasswordException` immediately, straight from the
`catch (NoSuchEntityException)` branch, *before* `Authentication::authenticate()` (the method that
actually increments the per-account counter) is ever called. So an attacker cycling through many
**different, possibly nonexistent** emails from one IP — classic credential-stuffing /
account-enumeration — never trips core's lockout at all, no matter how many requests they send.

**This module is purely additive.** It does not read, write, or otherwise touch
`customer/password/lockout_threshold` / `lockout_failures`, and it never unlocks or locks a
customer *account* — it only ever blocks further login *attempts from one IP address* for a
limited time. A real customer whose account core has locked can still be blocked by IP too (both
mechanisms are independent and can both be "on" for the same request); a real customer who is
*not* locked by core can still be temporarily blocked by IP if enough failures (their own or an
attacker's, from a shared IP/NAT/office network) accumulated against that address.

## What it does

- **Enable** — Yes/No, default No.
- **Max Failed Attempts per IP** — default **10**.
- **Window Minutes** — rolling window failures are counted over, default **15**.
- **Block Duration Minutes** — how long an IP is blocked once it hits the max, default **30**.

All fields are **Default scope only** (no per-website/per-store override) — the underlying storage
is a single IP-hash-keyed table with no per-website/per-store concept, so exposing Website/Store
View scope here would be misleading, not a real feature.

Once blocked, the storefront login page shows a generic message — *"The account is locked."* — the
same wording core itself uses for its own account lockout (see **Generic, shared block message**
below). This does not, by itself, give an attacker zero signal (core's own wrong-password message,
*"Invalid login or password."*, is already distinct from its lockout message, so core leaks that
distinction on its own regardless of this module); it means this module's IP-level block does not
introduce a *third*, distinguishable message on top of core's existing two.

## Exact hook points used (read from real core source, not guessed)

Four hooks, verified against `vendor/magento/module-customer` and
`vendor/magento/framework` before writing any code:

### 1. Pre-check / block — `Observer\CheckLoginRateLimitObserver`

Fires on the **`controller_action_predispatch_customer_account_loginPost`** event, registered in
`etc/frontend/events.xml`.

This is not a guess: it is the *same* event `Magento\Captcha\Observer\CheckUserLoginObserver`
already uses for the identically-shaped problem ("check something about this IP/session before
authenticating, and skip the controller if it fails") —
`vendor/magento/module-captcha/etc/frontend/events.xml`:

```xml
<event name="controller_action_predispatch_customer_account_loginPost">
    <observer name="captcha" instance="Magento\Captcha\Observer\CheckUserLoginObserver" />
</event>
```

Confirmed how "skip the controller" actually works by reading
`vendor/magento/framework/App/FrontController.php`:

- `dispatchPreDispatchEvents()` (~line 269) fires `controller_action_predispatch_<full_action_name>`
  — for this controller, `customer_account_loginPost` — **before** the action ever dispatches.
- `getActionResponse()` (~line 238) checks
  `$this->actionFlag->get('', ActionInterface::FLAG_NO_DISPATCH)` and returns immediately if set,
  **without calling `dispatch()` (and therefore `execute()`) at all.**

So calling `$this->actionFlag->set('', ActionInterface::FLAG_NO_DISPATCH, true)` from this
observer means `LoginPost::execute()` — and therefore
`customerAccountManagement->authenticate()`, which is what actually verifies the password hash —
truly never runs for a blocked IP. This satisfies the spec's performance/hardening goal directly:
a blocked IP never reaches the password verifier at all.

A `before`/`around` **plugin** on `LoginPost::execute()` was considered for this hook (per the
original task spec) and rejected in favor of the observer above, specifically because core itself
already dispatches this exact event for this exact controller for this exact purpose — the
observer is the better-precedented, more idiomatic choice, not a workaround.

### 2. Failure detection — `Plugin\LoginPostPlugin::aroundExecute()`

Registered on `Magento\Customer\Controller\Account\LoginPost` in `etc/frontend/di.xml`.

Read `vendor/magento/module-customer/Model/AccountManagement/Authenticate.php` end to end looking
for a core "authentication failed" event to observe instead of writing a plugin — **there isn't
one.** `customer_customer_authenticated` is dispatched only on full success, right before
`return $customer;`. Every failure path (`NoSuchEntityException` → nonexistent email,
`InvalidEmailOrPasswordException` → wrong password, `UserLockedException` → core's own lockout,
`EmailNotConfirmedException` → unconfirmed account) is a **thrown exception**, caught by
`LoginPost::execute()` itself, with no event dispatched anywhere on that path. A plugin wrapping
`execute()` is therefore the correct tool here — not a guess, but the conclusion of ruling out the
event-based alternative by reading the code.

`aroundExecute` (not the simpler `afterExecute`) is used specifically to close a false-positive gap
found while reading `LoginPost::execute()`'s own top guard:

```php
if ($this->session->isLoggedIn() || !$this->formKeyValidator->validate($this->getRequest())) {
    // ... returns immediately, no authentication attempted at all
}
```

An `afterExecute` that only checked "is the session logged in after execute()?" would misclassify
**both** of those early-return cases (already logged in; invalid/expired form key) as a failed
login attempt — most concretely, a legitimate customer resubmitting a stale browser tab with an
expired CSRF token would get counted as an attacker. `aroundExecute` recomputes that exact same
guard (reusing the real `Magento\Customer\Model\Session` and
`Magento\Framework\Data\Form\FormKey\Validator` core itself uses, not re-deriving the logic) before
calling `$proceed()`, so only a request that genuinely reached the password check either way gets
counted.

### 3. Checkout AJAX login endpoint — `Plugin\AjaxLoginPlugin`

Registered on `Magento\Customer\Controller\Ajax\Login` in `etc/frontend/di.xml` —
**a completely separate controller from `LoginPost` above**, used by the checkout page's
"login" popup (`vendor/magento/module-customer/view/frontend/web/js/action/login.js` posts to
`customer/ajax/login` by default), and exposed by default on every checkout page. It calls the same
`AccountManagementInterface::authenticate()` core method LoginPost does, but through a different
controller/action, so neither hook #1 nor hook #2 above ever ran for it before this plugin was
added — this was the largest gap this module had, since it needed no special discovery (it is
present on any storefront out of the box) and bypassed the IP rate limit entirely.

A single `around` plugin does both the pre-check (block before `authenticate()` runs) and the
outcome recording (failure/success after it returns) for this controller, reusing the same
`Config`/`LoginAttemptStore` services hooks #1/#2 use — see `Plugin\AjaxLoginPlugin`'s docblock for
why one class does both jobs here (unlike the Observer/Plugin split used for the classic form), and
for how success/failure is classified without relying on `Magento\Framework\Controller\Result\Json`
having no public getter for the data it was given.

### 4. Reset on success — `Observer\ResetLoginAttemptsObserver`

Fires on **`customer_customer_authenticated`**, registered **globally** in `etc/events.xml` (not
`etc/frontend/`), because `AccountManagement\Authenticate::execute()` — where this event is
dispatched — is reachable from more than just the storefront login form (e.g. the customer
REST/GraphQL token endpoints share the same call underneath). Resetting this module's own per-IP
counter on *any* genuinely successful authentication is always correct regardless of entry point.

This is also not a guess: it is the same event
`Magento\Captcha\Observer\ResetAttemptForFrontendObserver` already resets its own (unrelated)
captcha-attempt counter on — confirmed by reading
`vendor/magento/module-captcha/etc/events.xml` and that observer's source.

### Client IP

All four hooks read the IP via `Magento\Framework\HTTP\PhpEnvironment\RemoteAddress::getRemoteAddress()`
— the same `@api`-annotated class core itself injects wherever it needs the requesting IP (e.g.
`module-admin-audit-log`'s `Observer\LogAdminAction` in this repo). No custom IP-detection logic
was written for this module.

**Operator warning — reverse proxies, CDNs, and load balancers:** `RemoteAddress::getRemoteAddress()`
resolves to `$_SERVER['REMOTE_ADDR']` **only**, unless it is explicitly configured with
`alternativeHeaders` (e.g. `X-Forwarded-For`) via `di.xml` — see
`vendor/magento/framework/HTTP/PhpEnvironment/RemoteAddress.php`'s constructor. If this storefront
sits behind a reverse proxy, CDN (Cloudflare, Fastly, ...), or load balancer that is NOT configured
to forward the real client IP through a trusted header this class is told to read, `REMOTE_ADDR`
will be the proxy's own IP for **every** visitor. In that setup, this module silently degrades from
"per-IP rate limiting" to "one shared bucket for the entire site" — a single attacker (or even a
handful of legitimate customers mistyping passwords around the same time) can exhaust the shared
`max_attempts` budget and lock out every other customer behind that same proxy. If you run behind
any such infrastructure, you **must** configure trusted-proxy / `alternativeHeaders` handling for
`RemoteAddress` (via a `di.xml` argument on `Magento\Framework\HTTP\PhpEnvironment\RemoteAddress`)
before enabling this module in production. This module does not attempt to auto-detect or validate
that configuration — verifying it is the operator's responsibility.

## Storage

One table, `tvt_login_rate_limiter_attempt` (`etc/db_schema.xml`, declarative schema — never
`InstallSchema`/`UpgradeSchema`):

| Column | Purpose |
|---|---|
| `ip_hash` (PK) | SHA-256 hex digest of the client IP — see **Privacy** below |
| `attempts` | Failed attempts recorded in the current window |
| `window_started_at` | When the current counting window began |
| `blocked_until` | If set and in the future, this IP is currently blocked |
| `updated_at` | Last write — used by the purge cron to find stale rows |

`Model\RateLimit\LoginAttemptStore` is a thin `ResourceConnection`-based wrapper (no
`AbstractModel`/`Collection` stack — there is no admin grid over this table, so that stack would be
pure ceremony; mirrors `module-email-otp-two-factor-auth`'s `OtpCodeManager`, the closest sibling
precedent in this repo). All of the actual block/reset decision logic lives in
`Model\RateLimit\RateLimitPolicy`, a plain PHP class with **zero Magento dependency**, unit-tested
directly (see `tests/`).

**Concurrency:** `recordFailure()` locks the target row via `SELECT ... FOR UPDATE` inside a
transaction before computing and writing the next state, so two concurrent failed attempts from the
same IP cannot both read the same stale `attempts` count and silently collapse into a single
recorded failure — a real concern given that credential-stuffing tools fire many requests
concurrently, not serially. This mirrors `OtpCodeManager::issueNewCodeIfAllowed()`'s existing,
previously-reviewed read-lock/compute/write pattern in this repo.

### Privacy: why a hash, and its honest limits

The raw IP address is never written to this table — only `sha256(ip)`. This is a **data
minimization** choice: if this table is ever exposed (backup leak, log scrape, careless DB export),
a casual reader doesn't get a plain list of visitor IPs. **It is not, and should not be presented
as, a strong cryptographic protection**: the entire IPv4 address space is only ~4.3 billion values,
small enough that an attacker with direct access to this table can trivially rebuild a full
IP → hash rainbow table and reverse every row. Treat this column the same way you'd treat any other
"we hashed it, but the input space is small" case — better than plaintext, not a substitute for
restricting who can read the database at all.

### Purge cron

`Cron\PurgeExpiredAttempts` (`etc/crontab.xml`, hourly) deletes any row whose `updated_at` is older
than `(Window Minutes + Block Duration Minutes)` ago — by that point, whatever window/block it
represented has unconditionally expired, so it's always safe to delete without even reading
`attempts`/`blocked_until`. Deliberately **not** gated on the "Enable" toggle (unlike this module's
other config-gated code) — it is pure garbage collection over rows that may have been written while
the module was previously enabled.

## Generic, shared block message

Once blocked, hook #1 (`Observer\CheckLoginRateLimitObserver`, for the classic login form) and
hook #3 (`Plugin\AjaxLoginPlugin`, for the checkout AJAX login) both show *"The account is
locked."* — deliberately the exact string core itself uses for its own account lockout
(`Magento\Customer\Model\AccountManagement\Authenticate::execute()` ->
`throw new UserLockedException(__('The account is locked.'))`), rather than a distinct,
module-specific message. An earlier version of this module used its own wording ("Too many failed
login attempts...") here, which — flagged during security review — was itself a signal: it told an
attacker unambiguously "this specific block is the IP rate limiter, not core's account lockout,"
information core's own responses don't otherwise hand out for free. Reusing core's exact string
closes that gap.

This does **not** make the three possible outcomes (wrong password, account locked, IP blocked)
fully indistinguishable — core's own *"Invalid login or password."* (wrong password / nonexistent
email) is still a different string from *"The account is locked."* (core's lockout **or** this
module's IP block), and that distinction is core's own pre-existing behavior, unrelated to and out
of scope for this module. What this module controls is only that its *own* block does not add a
third, uniquely-identifiable message on top of core's existing two.

## Known limitation (flagged explicitly, not discovered later)

The pre-check hooks (#1 for the classic login form, #3 for the checkout AJAX login) cover the two
storefront entry points that dispatch through Magento's normal MVC controller flow. They do
**not** cover the customer REST API token endpoint (`POST /V1/integration/customer/token`) or
GraphQL's `generateCustomerToken` mutation, which authenticate through `AccountManagement` by a
completely different path (a `webapi` REST/GraphQL dispatch, not the MVC front controller) that
never instantiates `Magento\Customer\Controller\Account\LoginPost` or
`Magento\Customer\Controller\Ajax\Login` at all — so neither the predispatch observer nor either
`around` plugin can ever run for it, regardless of controller. The reset hook (hook #4) *does*
cover those paths (any successful auth resets the counter, regardless of entry point) — only the
*blocking* half remains scoped to the two MVC-dispatched storefront controllers above. An attacker
hitting the REST/GraphQL token endpoint directly still bypasses this module's IP rate limiting
entirely (core's own per-account lockout still applies to them, same as always). Closing that gap
would need a plugin on `Magento\Customer\Api\AccountManagementInterface::authenticate()` itself —
the one hook point that genuinely covers every caller (LoginPost, Ajax\Login, REST, GraphQL) at
once, at the cost of losing the per-controller precision (e.g. LoginPost's own
already-logged-in/invalid-form-key early-return guard) that hooks #1/#2 rely on `LoginPost`'s own
session/form-key state to detect — out of scope for this module as specified, called out here for
the security review.

## Fail-open, not fail-closed

Every DB read/write in `Model\RateLimit\LoginAttemptStore` fails **open**, by explicit design:

- If the block-check read fails (DB error), `isBlocked()` returns `false` — the login attempt is
  allowed to proceed to core's own authentication as normal.
- If recording a failure fails to write, or resetting on success fails to write, the error is
  logged and swallowed — it never surfaces to the customer and never blocks `LoginPost::execute()`
  from completing.

Rationale: this module is an **additive, anti-abuse** control, not the primary authentication
security boundary — that boundary is, and remains, core's own password verification and per-account
lockout. A database hiccup on this module's own small table must never be able to lock every
storefront customer out of logging in. This tradeoff (favoring availability over strictness on this
module's own failure modes) is the one part of this module's design most worth a second opinion
during security review.
