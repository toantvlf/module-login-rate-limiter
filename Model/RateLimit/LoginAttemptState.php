<?php

declare(strict_types=1);

namespace TVTCommerce\LoginRateLimiter\Model\RateLimit;

/**
 * Immutable, plain-PHP snapshot of one IP's row in tvt_login_rate_limiter_attempt, expressed as
 * Unix timestamps rather than DB date strings so RateLimitPolicy (the class that actually decides
 * what happens to this state) stays entirely framework/DB-format free and unit-testable — see
 * tests/Unit/Model/RateLimit/RateLimitPolicyTest.php.
 *
 * Deliberately has NO Magento dependency and NO behavior of its own beyond empty() — all
 * decision-making lives in RateLimitPolicy, which takes a LoginAttemptState and returns a new one
 * (immutability per this repo's coding-style rules: never mutate, always return a new instance).
 */
class LoginAttemptState
{
    public function __construct(
        public readonly int $attempts,
        public readonly ?int $windowStartedAt,
        public readonly ?int $blockedUntil
    ) {
    }

    /**
     * The state of an IP that has never failed a login (or whose row does not exist yet).
     */
    public static function empty(): self
    {
        return new self(0, null, null);
    }
}
