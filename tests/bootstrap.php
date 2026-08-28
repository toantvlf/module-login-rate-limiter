<?php
declare(strict_types=1);

/**
 * Minimal PSR-4 autoloader for the module's own namespace — deliberately NOT the module's root
 * composer.json autoload, because that declares magento/module-* dependencies that require
 * repo.magento.com credentials and aren't needed to unit-test plain-PHP classes. The classes
 * under test (Model\RateLimit\LoginAttemptState, Model\RateLimit\RateLimitPolicy) have zero
 * Magento framework dependencies, so no stub classes/functions are needed here (mirrors
 * module-maintenance-mode's and module-email-otp-two-factor-auth's tests/bootstrap.php, which
 * are in the exact same position).
 */
spl_autoload_register(static function (string $class): void {
    $prefix  = 'TVTCommerce\\LoginRateLimiter\\';
    $baseDir = dirname(__DIR__) . '/';

    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $file     = $baseDir . str_replace('\\', '/', $relative) . '.php';

    if (is_file($file)) {
        require $file;
    }
});

require __DIR__ . '/vendor/autoload.php';
