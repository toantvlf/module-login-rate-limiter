<?php

declare(strict_types=1);

namespace TVTCommerce\LoginRateLimiter\Observer;

use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use TVTCommerce\LoginRateLimiter\Model\Config;
use TVTCommerce\LoginRateLimiter\Model\RateLimit\LoginAttemptStore;

/**
 * Resets (deletes) the current IP's failed-attempt counter after a genuinely successful customer
 * login. Fires on `customer_customer_authenticated` (see etc/events.xml — deliberately GLOBAL
 * scope, not etc/frontend/, because this event is dispatched from
 * \Magento\Customer\Model\AccountManagement\Authenticate::execute() [verified: real core source,
 * dispatched only AFTER the password hash has been verified AND any required email confirmation
 * check has passed — i.e. only on a genuine, complete success, never on a partial/failed
 * attempt], which is reachable from more than just the traditional storefront login form covered
 * by Observer\CheckLoginRateLimitObserver — e.g. the customer REST/GraphQL token endpoints share
 * the same AccountManagement::authenticate() call underneath. Resetting a rate limit on ANY
 * genuinely successful authentication, regardless of which door the customer came through, is
 * always safe/correct — unlike the pre-check block, which only actually protects the classic
 * LoginPost form (see README.md's "Known limitation" section for the explicit gap this leaves).
 *
 * This is the same event Magento\Captcha\Observer\ResetAttemptForFrontendObserver already resets
 * its own (unrelated) captcha-attempt counter on — verified against real core source
 * (vendor/magento/module-captcha/etc/events.xml +
 * vendor/magento/module-captcha/Observer/ResetAttemptForFrontendObserver.php) as the standard,
 * precedented "login succeeded" signal, not a guess.
 */
class ResetLoginAttemptsObserver implements ObserverInterface
{
    public function __construct(
        private readonly Config $config,
        private readonly RemoteAddress $remoteAddress,
        private readonly LoginAttemptStore $attemptStore
    ) {
    }

    public function execute(Observer $observer): void
    {
        if (!$this->config->isEnabled()) {
            return;
        }

        $ip = $this->remoteAddress->getRemoteAddress();
        if ($ip === false || $ip === '') {
            return;
        }

        $this->attemptStore->reset($ip);
    }
}
