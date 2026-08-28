<?php

declare(strict_types=1);

namespace TVTCommerce\LoginRateLimiter\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;

/**
 * Thin reader around this module's own config values (see etc/adminhtml/system.xml). Every field
 * is default-scope only (showInWebsite="0" showInStore="0" throughout system.xml), so — mirroring
 * module-maintenance-mode's Model\Config and module-admin-audit-log's Model\Config, the two
 * closest sibling precedents in this repo — values are read with getValue()/isSetFlag() and no
 * explicit scope type/code, which always resolves to the default value here since no
 * website/store override can exist for these fields.
 */
class Config
{
    private const PREFIX = 'tvtcommerce_login_rate_limiter';

    private const DEFAULT_MAX_ATTEMPTS = 10;
    private const DEFAULT_WINDOW_MINUTES = 15;
    private const DEFAULT_BLOCK_MINUTES = 30;

    public function __construct(
        private readonly ScopeConfigInterface $scopeConfig
    ) {
    }

    public function isEnabled(): bool
    {
        return $this->scopeConfig->isSetFlag(self::PREFIX . '/general/enabled');
    }

    /**
     * Failed attempts allowed from one IP within getWindowMinutes() before it is blocked
     * (see etc/adminhtml/system.xml's max_attempts field).
     */
    public function getMaxAttempts(): int
    {
        return $this->getPositiveInt('max_attempts', self::DEFAULT_MAX_ATTEMPTS);
    }

    /**
     * Length, in minutes, of the rolling window failed attempts are counted over (see
     * etc/adminhtml/system.xml's window_minutes field).
     */
    public function getWindowMinutes(): int
    {
        return $this->getPositiveInt('window_minutes', self::DEFAULT_WINDOW_MINUTES);
    }

    /**
     * How long, in minutes, an IP stays blocked once it reaches getMaxAttempts() (see
     * etc/adminhtml/system.xml's block_minutes field).
     */
    public function getBlockMinutes(): int
    {
        return $this->getPositiveInt('block_minutes', self::DEFAULT_BLOCK_MINUTES);
    }

    /**
     * Reads an integer config field, falling back to $default when unset, non-numeric, or not
     * strictly positive — protects Model\RateLimit\RateLimitPolicy from ever being constructed
     * with a zero/negative threshold from a blank or corrupted config value.
     */
    private function getPositiveInt(string $fieldId, int $default): int
    {
        $value = (int) $this->scopeConfig->getValue(self::PREFIX . '/general/' . $fieldId);

        return $value > 0 ? $value : $default;
    }
}
