<?php

declare(strict_types=1);

namespace TVTCommerce\LoginRateLimiter\Model\RateLimit;

use Magento\Framework\App\ResourceConnection;
use Psr\Log\LoggerInterface;
use Throwable;
use TVTCommerce\LoginRateLimiter\Model\Config;

/**
 * Thin Magento-aware wrapper around the tvt_login_rate_limiter_attempt table (see
 * etc/db_schema.xml) — all of the actual block/reset decision logic lives in the
 * framework-independent RateLimitPolicy; this class only does DB reads/writes, IP hashing, and
 * DB-timestamp <-> Unix-timestamp conversion. Mirrors this repo's established "plain
 * ResourceConnection, no AbstractModel/Collection stack" pattern for a simple single-row-per-key
 * table with no admin grid over it (see module-email-otp-two-factor-auth's OtpCodeManager, the
 * closest sibling precedent).
 *
 * FAIL-OPEN on DB errors — this is a deliberate, explicitly-flagged security tradeoff, called out
 * again in README.md's "Fail-open, not fail-closed" section for the dedicated security review:
 *  - isBlocked() returns false (not blocked) if the row can't be read. A database hiccup on this
 *    ADDITIVE, anti-abuse table must never lock every storefront customer out of logging in —
 *    core's own per-account lockout (Magento\Customer\Model\Authentication) is a completely
 *    separate mechanism and is NOT affected by this module or this failure mode at all.
 *  - recordFailure() / reset() log and swallow DB errors rather than throwing — a failed write
 *    here just means this one attempt goes uncounted (or a reset doesn't happen), which degrades
 *    the rate limiter's precision but never blocks a real login and never breaks LoginPost's own
 *    control flow (see Plugin\LoginPostPlugin, which calls these from an aroundExecute plugin
 *    wrapping the real authentication attempt).
 *
 * CONCURRENCY: recordFailure() is race-free under concurrent requests for the same IP (flagged
 * explicitly per this module's security review) — it locks the existing row (if any) via
 * SELECT ... FOR UPDATE inside a transaction before computing/writing the next state, so a
 * concurrent recordFailure() call for the SAME ip blocks until the first commits, then re-reads
 * the now-current row, instead of both racing past the same stale "attempts" count. This mirrors
 * module-email-otp-two-factor-auth's OtpCodeManager::issueNewCodeIfAllowed(), the proven precedent
 * in this repo for this exact read-lock/compute/write TOCTOU fix.
 */
class LoginAttemptStore
{
    private const TABLE = 'tvt_login_rate_limiter_attempt';

    public function __construct(
        private readonly ResourceConnection $resourceConnection,
        private readonly Config $config,
        private readonly LoggerInterface $logger
    ) {
    }

    /**
     * Whether $ip is currently blocked from attempting a login, per the admin-configured
     * thresholds. Fails open (returns false) on any DB error — see class docblock.
     */
    public function isBlocked(string $ip): bool
    {
        try {
            $state = $this->loadState($ip);

            return $this->buildPolicy()->isBlocked($state, time());
        } catch (Throwable $e) {
            $this->logger->error(
                'TVTCommerce_LoginRateLimiter: failed to read attempt state, failing open (not blocked)',
                ['message' => $e->getMessage()]
            );

            return false;
        }
    }

    /**
     * Record one failed login attempt from $ip "now" and persist whatever RateLimitPolicy decides
     * the next state should be. Race-free under concurrent requests for the same IP — see class
     * docblock's CONCURRENCY note. A DB error here is logged and swallowed — see class docblock.
     */
    public function recordFailure(string $ip): void
    {
        $connection = $this->resourceConnection->getConnection();

        try {
            $connection->beginTransaction();

            // SELECT ... FOR UPDATE locks this IP's row (or, if it doesn't exist yet, gap-locks
            // the key) for the rest of this transaction — a concurrent recordFailure() for the
            // same IP blocks here until this transaction commits, then reads the now-current row.
            // That closes the TOCTOU race where two simultaneous failures both read the same stale
            // "attempts" count before either write lands.
            $state = $this->loadState($ip, true);
            $nextState = $this->buildPolicy()->afterFailure($state, time());

            $this->saveState($ip, $nextState);

            $connection->commit();
        } catch (Throwable $e) {
            $connection->rollBack();
            $this->logger->error(
                'TVTCommerce_LoginRateLimiter: failed to record failed login attempt',
                ['message' => $e->getMessage()]
            );
        }
    }

    /**
     * Reset (delete) $ip's row after a successful login — called from
     * Observer\ResetLoginAttemptsObserver on core's `customer_customer_authenticated` event. A DB
     * error here is logged and swallowed: worst case a stale counter lingers a little longer
     * (self-heals once its window/block expires, or via Cron\PurgeExpiredAttempts).
     */
    public function reset(string $ip): void
    {
        try {
            $connection = $this->resourceConnection->getConnection();
            $connection->delete(
                $this->resourceConnection->getTableName(self::TABLE),
                ['ip_hash = ?' => $this->hashIp($ip)]
            );
        } catch (Throwable $e) {
            $this->logger->error(
                'TVTCommerce_LoginRateLimiter: failed to reset attempt state after successful login',
                ['message' => $e->getMessage()]
            );
        }
    }

    private function buildPolicy(): RateLimitPolicy
    {
        return new RateLimitPolicy(
            $this->config->getMaxAttempts(),
            $this->config->getWindowMinutes() * 60,
            $this->config->getBlockMinutes() * 60
        );
    }

    private function loadState(string $ip, bool $forUpdate = false): LoginAttemptState
    {
        $connection = $this->resourceConnection->getConnection();
        $select = $connection->select()
            ->from($this->resourceConnection->getTableName(self::TABLE))
            ->where('ip_hash = ?', $this->hashIp($ip));

        if ($forUpdate) {
            $select->forUpdate(true);
        }

        $row = $connection->fetchRow($select);

        if ($row === false) {
            return LoginAttemptState::empty();
        }

        return new LoginAttemptState(
            (int) $row['attempts'],
            $this->parseTimestamp($row['window_started_at']),
            $this->parseTimestamp($row['blocked_until'])
        );
    }

    private function saveState(string $ip, LoginAttemptState $state): void
    {
        $connection = $this->resourceConnection->getConnection();
        $connection->insertOnDuplicate(
            $this->resourceConnection->getTableName(self::TABLE),
            [
                'ip_hash' => $this->hashIp($ip),
                'attempts' => $state->attempts,
                'window_started_at' => $this->formatTimestamp($state->windowStartedAt ?? time()),
                'blocked_until' => $state->blockedUntil !== null
                    ? $this->formatTimestamp($state->blockedUntil)
                    : null,
            ],
            ['attempts', 'window_started_at', 'blocked_until']
        );
    }

    /**
     * SHA-256 hex digest of the raw IP — see etc/db_schema.xml's ip_hash column comment for the
     * honest caveat that this is data minimization, not a cryptographic security control (the
     * IPv4 address space is small enough that this is reversible by brute force against a
     * rainbow table, unlike a salted password hash).
     */
    private function hashIp(string $ip): string
    {
        return hash('sha256', $ip);
    }

    private function parseTimestamp(?string $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }

        $timestamp = strtotime($value);

        return $timestamp !== false ? $timestamp : null;
    }

    private function formatTimestamp(int $timestamp): string
    {
        return date('Y-m-d H:i:s', $timestamp);
    }
}
