<?php

declare(strict_types=1);

namespace TVTCommerce\LoginRateLimiter\Observer;

use Magento\Customer\Model\Url as CustomerUrl;
use Magento\Framework\App\ActionFlag;
use Magento\Framework\App\ActionInterface;
use Magento\Framework\App\Action\Action as CoreAction;
use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use Magento\Framework\Message\ManagerInterface;
use TVTCommerce\LoginRateLimiter\Model\Config;
use TVTCommerce\LoginRateLimiter\Model\RateLimit\LoginAttemptStore;

/**
 * The pre-authentication check: fires on `controller_action_predispatch_customer_account_loginPost`
 * (see etc/frontend/events.xml) — i.e. BEFORE
 * \Magento\Customer\Controller\Account\LoginPost::execute() runs at all, so a blocked IP's
 * `execute()` (and therefore the real `customerAccountManagement->authenticate()` call, which
 * verifies the submitted password hash) is skipped entirely — closing the module's core gap:
 * core's own per-account lockout (\Magento\Customer\Model\Authentication) never even sees an
 * attacker submitting many different/nonexistent emails from one IP, because it only tracks
 * failures once a submitted email resolves to a real customerId.
 *
 * This exact event/hook shape — a `controller_action_predispatch_customer_account_loginPost`
 * observer that can block the request and skip dispatch entirely via
 * ActionInterface::FLAG_NO_DISPATCH — is not a guess: it is the SAME mechanism core's own
 * Magento\Captcha module already uses for exactly this controller
 * (vendor/magento/module-captcha/Observer/CheckUserLoginObserver.php +
 * vendor/magento/module-captcha/etc/frontend/events.xml), verified by reading that real core
 * source before writing this class. Confirmed independently by reading
 * vendor/magento/framework/App/FrontController.php's getActionResponse()/dispatchPreDispatchEvents():
 * `controller_action_predispatch_<full_action_name>` fires BEFORE the action's dispatch() (and
 * therefore execute()) is ever called, and getActionResponse() checks FLAG_NO_DISPATCH before
 * calling dispatch() at all — so setting the flag here means execute() truly never runs, not just
 * an early return inside it.
 *
 * A `before`/`around` plugin on LoginPost::execute() was considered (per this module's original
 * task spec) but rejected in favor of this observer: core itself already dispatches this precise
 * event for this precise controller for this precise purpose, making the observer the more
 * idiomatic, better-precedented hook — not a guess or a workaround.
 *
 * Messages are added via an injected `\Magento\Framework\Message\ManagerInterface` rather than
 * the controller's own (protected, inaccessible from here) messageManager — this is the same
 * pattern Magento\Captcha\Observer\CheckUserLoginObserver uses, and works because
 * ManagerInterface is a shared (DI-singleton-per-request) service backed by the session, so a
 * message added here renders identically to one added by LoginPost::execute() itself.
 */
class CheckLoginRateLimitObserver implements ObserverInterface
{
    public function __construct(
        private readonly Config $config,
        private readonly RemoteAddress $remoteAddress,
        private readonly LoginAttemptStore $attemptStore,
        private readonly ActionFlag $actionFlag,
        private readonly ManagerInterface $messageManager,
        private readonly CustomerUrl $customerUrl
    ) {
    }

    public function execute(Observer $observer): void
    {
        if (!$this->config->isEnabled()) {
            return;
        }

        $controllerAction = $observer->getControllerAction();
        if (!$controllerAction instanceof CoreAction) {
            return;
        }

        $ip = $this->remoteAddress->getRemoteAddress();
        if ($ip === false || $ip === '') {
            // Can't identify the client IP at all — nothing to rate-limit against. Fails open;
            // core's own per-account lockout is unaffected either way. See LoginAttemptStore's
            // class docblock for this module's broader fail-open reasoning.
            return;
        }

        if (!$this->attemptStore->isBlocked($ip)) {
            return;
        }

        // Deliberately reuses core's OWN account-lockout wording
        // (Magento\Customer\Model\AccountManagement\Authenticate::execute() ->
        // `throw new UserLockedException(__('The account is locked.'))`) rather than a distinct
        // message — see README.md's "Generic, shared block message" section. A distinct message
        // here would itself be the signal this module's own README warned against: it would tell
        // an attacker "this specific block came from the IP rate limiter, not core's per-account
        // lockout," which core's own wrong-password message ("Invalid login or password.") does
        // NOT reveal on its own.
        $this->messageManager->addErrorMessage(__('The account is locked.'));

        // Prevents LoginPost::execute() from running at all for this request — verified against
        // real core source, see class docblock.
        $this->actionFlag->set('', ActionInterface::FLAG_NO_DISPATCH, true);

        $controllerAction->getResponse()->setRedirect($this->customerUrl->getLoginUrl());
    }
}
