<?php

declare(strict_types=1);

namespace TVTCommerce\LoginRateLimiter\Model\RateLimit;

/**
 * Pure, Magento-independent decision logic for the per-IP login rate limiter — deliberately has
 * zero framework/DB dependency so it can be unit-tested directly (see
 * tests/Unit/Model/RateLimit/RateLimitPolicyTest.php) without bootstrapping Magento. Mirrors this
 * repo's established pattern of separating pure decision logic (here) from the thin
 * Magento-aware persistence wrapper that calls it (Model\RateLimit\LoginAttemptStore) — see
 * module-email-otp-two-factor-auth's OtpCodeVerifier / OtpCodeManager split, the closest sibling
 * precedent for this exact structure.
 *
 * All time-based decisions take "now" as an explicit parameter rather than calling time()
 * internally, specifically so tests can assert exact boundary behavior without any clock
 * flakiness — same reasoning as OtpCodeVerifier.
 *
 * State machine, in plain terms:
 *  - A "window" starts the moment an IP's first failure (in a while) is recorded.
 *  - Additional failures within windowSeconds of the window start increment the counter.
 *  - Reaching maxAttempts within the window blocks the IP for blockSeconds from that moment.
 *  - Once the window has elapsed (no block reached) OR a previous block has expired, the NEXT
 *    failure starts an entirely fresh window/counter rather than continuing the old one — an IP
 *    that failed once, waited out the window, and fails again is treated as attempt #1, not #2.
 */
class RateLimitPolicy
{
    public function __construct(
        private readonly int $maxAttempts,
        private readonly int $windowSeconds,
        private readonly int $blockSeconds
    ) {
    }

    /**
     * Whether $state currently blocks a login attempt at $now. This is the single choke point
     * the pre-authentication check (Observer\CheckLoginRateLimitObserver) calls — an IP is
     * blocked if and only if blockedUntil is set and still in the future.
     */
    public function isBlocked(LoginAttemptState $state, int $now): bool
    {
        return $state->blockedUntil !== null && $state->blockedUntil > $now;
    }

    /**
     * Compute the next state after ONE failed login attempt from this IP at $now.
     *
     * Still-blocked defensive branch: normally the caller (Observer\CheckLoginRateLimitObserver)
     * intercepts and skips authentication entirely while blocked, so Plugin\LoginPostPlugin's
     * afterFailure() call should never actually run against a still-blocked state in practice —
     * but if it ever did (e.g. a race between two concurrent requests, or the pre-check being
     * bypassed some other way), returning the state unchanged rather than extending the block or
     * double-incrementing is the safer, more predictable choice.
     */
    public function afterFailure(LoginAttemptState $state, int $now): LoginAttemptState
    {
        if ($this->isBlocked($state, $now)) {
            return $state;
        }

        $windowExpired = $state->windowStartedAt === null
            || ($now - $state->windowStartedAt) >= $this->windowSeconds;
        $blockJustExpired = $state->blockedUntil !== null && $state->blockedUntil <= $now;

        if ($windowExpired || $blockJustExpired) {
            // Fresh window: this failure is attempt #1 of a brand-new count.
            $attempts = 1;
            $windowStartedAt = $now;
        } else {
            $attempts = $state->attempts + 1;
            $windowStartedAt = $state->windowStartedAt;
        }

        $blockedUntil = $attempts >= $this->maxAttempts ? ($now + $this->blockSeconds) : null;

        return new LoginAttemptState($attempts, $windowStartedAt, $blockedUntil);
    }

    /**
     * The state after a SUCCESSFUL login from this IP — a full reset, regardless of how many
     * failures preceded it. Called by Observer\ResetLoginAttemptsObserver on core's own
     * `customer_customer_authenticated` event.
     */
    public function afterSuccess(): LoginAttemptState
    {
        return LoginAttemptState::empty();
    }
}
