<?php

declare(strict_types=1);

namespace TVTCommerce\LoginRateLimiter\Tests\Unit\Model\RateLimit;

use PHPUnit\Framework\TestCase;
use TVTCommerce\LoginRateLimiter\Model\RateLimit\LoginAttemptState;
use TVTCommerce\LoginRateLimiter\Model\RateLimit\RateLimitPolicy;

final class RateLimitPolicyTest extends TestCase
{
    private const MAX_ATTEMPTS = 3;
    private const WINDOW_SECONDS = 100;
    private const BLOCK_SECONDS = 200;

    private RateLimitPolicy $policy;

    protected function setUp(): void
    {
        $this->policy = new RateLimitPolicy(self::MAX_ATTEMPTS, self::WINDOW_SECONDS, self::BLOCK_SECONDS);
    }

    // --- LoginAttemptState::empty() -----------------------------------------------------------

    public function testEmptyStateHasZeroAttemptsAndNoTimestamps(): void
    {
        $state = LoginAttemptState::empty();

        self::assertSame(0, $state->attempts);
        self::assertNull($state->windowStartedAt);
        self::assertNull($state->blockedUntil);
    }

    // --- afterFailure(): first failure ---------------------------------------------------------

    public function testFirstFailureStartsANewWindowWithAttemptsOne(): void
    {
        $now = 1_000;

        $next = $this->policy->afterFailure(LoginAttemptState::empty(), $now);

        self::assertSame(1, $next->attempts);
        self::assertSame($now, $next->windowStartedAt);
        self::assertNull($next->blockedUntil);
        self::assertFalse($this->policy->isBlocked($next, $now));
    }

    // --- afterFailure(): threshold not yet reached ----------------------------------------------

    public function testFailureBelowThresholdIncrementsWithoutBlocking(): void
    {
        $windowStartedAt = 1_000;
        $state = new LoginAttemptState(1, $windowStartedAt, null);
        $now = $windowStartedAt + 50; // well within the 100s window

        $next = $this->policy->afterFailure($state, $now);

        self::assertSame(2, $next->attempts);
        self::assertSame($windowStartedAt, $next->windowStartedAt);
        self::assertNull($next->blockedUntil);
        self::assertFalse($this->policy->isBlocked($next, $now));
    }

    // --- afterFailure(): threshold reached -> blocked -------------------------------------------

    public function testReachingMaxAttemptsBlocksTheIp(): void
    {
        $windowStartedAt = 1_000;
        $state = new LoginAttemptState(self::MAX_ATTEMPTS - 1, $windowStartedAt, null);
        $now = $windowStartedAt + 60;

        $next = $this->policy->afterFailure($state, $now);

        self::assertSame(self::MAX_ATTEMPTS, $next->attempts);
        self::assertSame($now + self::BLOCK_SECONDS, $next->blockedUntil);
        self::assertTrue($this->policy->isBlocked($next, $now));
    }

    public function testAttemptsBeyondMaxStayBlockedAndAreLeftUnchanged(): void
    {
        $windowStartedAt = 1_000;
        $blockedUntil = 1_260;
        $state = new LoginAttemptState(self::MAX_ATTEMPTS, $windowStartedAt, $blockedUntil);
        $now = $blockedUntil - 50; // still inside the block

        $next = $this->policy->afterFailure($state, $now);

        // Defensive branch: a failure recorded while already blocked must not extend the block
        // or double-increment — see RateLimitPolicy::afterFailure()'s docblock.
        self::assertSame($state->attempts, $next->attempts);
        self::assertSame($state->windowStartedAt, $next->windowStartedAt);
        self::assertSame($state->blockedUntil, $next->blockedUntil);
    }

    // --- afterFailure(): block expired -> resets ------------------------------------------------

    public function testBlockExpiredResetsToFreshWindowOnNextFailure(): void
    {
        $blockedUntil = 1_260;
        $state = new LoginAttemptState(self::MAX_ATTEMPTS, 1_000, $blockedUntil);
        $now = $blockedUntil + 40; // after the block has lifted

        self::assertFalse($this->policy->isBlocked($state, $now), 'sanity check: block must read as expired');

        $next = $this->policy->afterFailure($state, $now);

        self::assertSame(1, $next->attempts);
        self::assertSame($now, $next->windowStartedAt);
        self::assertNull($next->blockedUntil);
    }

    // --- afterFailure(): window expired without reaching threshold -> resets --------------------

    public function testWindowExpiredWithoutReachingThresholdResetsOnNextFailure(): void
    {
        $windowStartedAt = 1_000;
        $state = new LoginAttemptState(self::MAX_ATTEMPTS - 1, $windowStartedAt, null);
        $now = $windowStartedAt + self::WINDOW_SECONDS + 10; // window has elapsed

        $next = $this->policy->afterFailure($state, $now);

        self::assertSame(1, $next->attempts);
        self::assertSame($now, $next->windowStartedAt);
        self::assertNull($next->blockedUntil);
    }

    public function testWindowExpiryBoundaryIsInclusive(): void
    {
        $windowStartedAt = 1_000;
        $state = new LoginAttemptState(1, $windowStartedAt, null);
        $now = $windowStartedAt + self::WINDOW_SECONDS; // exactly at the boundary

        $next = $this->policy->afterFailure($state, $now);

        // now - windowStartedAt >= windowSeconds (>=, not >) counts as expired.
        self::assertSame(1, $next->attempts);
        self::assertSame($now, $next->windowStartedAt);
    }

    // --- isBlocked() -----------------------------------------------------------------------------

    public function testIsBlockedReturnsFalseWhenBlockedUntilIsNull(): void
    {
        $state = new LoginAttemptState(2, 1_000, null);

        self::assertFalse($this->policy->isBlocked($state, 1_050));
    }

    public function testIsBlockedReturnsFalseExactlyAtTheBlockedUntilBoundary(): void
    {
        $blockedUntil = 1_260;
        $state = new LoginAttemptState(self::MAX_ATTEMPTS, 1_000, $blockedUntil);

        // blockedUntil > now (strict), so "now equal to blockedUntil" reads as no longer blocked.
        self::assertFalse($this->policy->isBlocked($state, $blockedUntil));
    }

    public function testIsBlockedReturnsTrueOneSecondBeforeTheBoundary(): void
    {
        $blockedUntil = 1_260;
        $state = new LoginAttemptState(self::MAX_ATTEMPTS, 1_000, $blockedUntil);

        self::assertTrue($this->policy->isBlocked($state, $blockedUntil - 1));
    }

    // --- afterSuccess() --------------------------------------------------------------------------

    public function testAfterSuccessReturnsAFullyEmptyState(): void
    {
        $next = $this->policy->afterSuccess();

        self::assertSame(0, $next->attempts);
        self::assertNull($next->windowStartedAt);
        self::assertNull($next->blockedUntil);
    }
}
