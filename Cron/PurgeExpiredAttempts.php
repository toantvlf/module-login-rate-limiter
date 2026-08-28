<?php

declare(strict_types=1);

namespace TVTCommerce\LoginRateLimiter\Cron;

use DateTimeImmutable;
use DateTimeZone;
use Magento\Framework\App\ResourceConnection;
use Psr\Log\LoggerInterface;
use Throwable;
use TVTCommerce\LoginRateLimiter\Model\Config;

/**
 * Hourly housekeeping (see etc/crontab.xml): deletes rows that can no longer be relevant to any
 * decision RateLimitPolicy could make, so tvt_login_rate_limiter_attempt does not grow unbounded
 * as distinct attacking/scanning IPs accumulate over time.
 *
 * Cutoff reasoning: a row's window_started_at defines when its current counting window began;
 * any block it could produce ends at most windowSeconds + blockSeconds after that. If a row's
 * last write (updated_at) is older than windowSeconds + blockSeconds ago, then whatever window
 * and/or block it represented has unconditionally expired by now, regardless of the specific
 * attempts/blocked_until values stored — so it is always safe to delete, without needing to read
 * or branch on those columns. Uses a direct ResourceConnection DELETE with a bound cutoff
 * timestamp rather than loading a Collection (mirrors module-admin-audit-log's
 * Cron\CleanupOldLogs) — no admin grid or Collection stack exists for this table at all (see
 * Model\RateLimit\LoginAttemptStore's docblock).
 *
 * Deliberately does NOT gate on Config::isEnabled(), unlike this repo's other per-module cleanup
 * crons (module-admin-audit-log's CleanupOldLogs, module-low-stock-alert's SendLowStockDigest) —
 * this job is pure garbage collection over rows that may have been written while the module WAS
 * enabled, before an admin later turned it off. Skipping it while disabled would let already-
 * written rows sit indefinitely instead of aging out on schedule.
 */
class PurgeExpiredAttempts
{
    private const TABLE_NAME = 'tvt_login_rate_limiter_attempt';

    public function __construct(
        private readonly Config $config,
        private readonly ResourceConnection $resourceConnection,
        private readonly LoggerInterface $logger
    ) {
    }

    public function execute(): void
    {
        try {
            $connection = $this->resourceConnection->getConnection();
            $table = $this->resourceConnection->getTableName(self::TABLE_NAME);
            $cutoffSeconds = ($this->config->getWindowMinutes() + $this->config->getBlockMinutes()) * 60;
            // Explicit UTC, NOT date()/time() (which format using PHP's configured default
            // timezone) — mirrors module-admin-audit-log's Cron\CleanupOldLogs. `updated_at` is a
            // `timestamp` column auto-populated by MySQL's CURRENT_TIMESTAMP, and Magento's own
            // Mysql adapter runs `SET time_zone = '+00:00'` on every connection (see
            // vendor/magento/framework/DB/Adapter/Pdo/Mysql.php), so that column is always UTC
            // regardless of server locale. If PHP's default timezone were anything other than UTC
            // (e.g. a server configured for a non-UTC locale), comparing a locally-formatted cutoff
            // string against a UTC column would shift the effective cutoff by the zone offset — for
            // a timezone ahead of UTC by more than this module's (windowMinutes + blockMinutes)
            // default of 45 minutes, every row, including ones representing a currently active
            // block, would satisfy `updated_at < $cutoff` and be deleted on every hourly run.
            $cutoff = (new DateTimeImmutable('now', new DateTimeZone('UTC')))
                ->modify(sprintf('-%d seconds', $cutoffSeconds))
                ->format('Y-m-d H:i:s');

            $connection->delete($table, ['updated_at < ?' => $cutoff]);
        } catch (Throwable $e) {
            // A broken purge job must never break the cron run itself — log and move on.
            $this->logger->error('TVTCommerce_LoginRateLimiter: purge cron failed', [
                'message' => $e->getMessage(),
            ]);
        }
    }
}
