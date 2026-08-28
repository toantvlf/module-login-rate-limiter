<?php

declare(strict_types=1);

namespace TVTCommerce\LoginRateLimiter\Plugin;

use Magento\Customer\Controller\Account\LoginPost;
use Magento\Customer\Model\Session as CustomerSession;
use Magento\Framework\Data\Form\FormKey\Validator as FormKeyValidator;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use TVTCommerce\LoginRateLimiter\Model\Config;
use TVTCommerce\LoginRateLimiter\Model\RateLimit\LoginAttemptStore;

/**
 * Detects a FAILED storefront login attempt (wrong password OR nonexistent email — both count,
 * per this module's spec) and records it against the requesting IP. Registered on
 * \Magento\Customer\Controller\Account\LoginPost::execute() (see etc/frontend/di.xml).
 *
 * WHY a plugin here, when Observer\CheckLoginRateLimitObserver/ResetLoginAttemptsObserver use core
 * events for the other two hooks: verified against real core source
 * (vendor/magento/module-customer/Model/AccountManagement/Authenticate.php) that core dispatches
 * `customer_customer_authenticated` ONLY on success — there is no equivalent
 * "authentication_failed" (or similarly-named) event anywhere in module-customer for the failure
 * side. LoginPost::execute() itself (vendor/magento/module-customer/Controller/Account/
 * LoginPost.php) catches EmailNotConfirmedException/AuthenticationException/LocalizedException/
 * generic \Exception inline and adds its own error message — there is no seam to observe a
 * failure signal from outside except wrapping execute() itself. An `around` plugin (rather than
 * `after`) is used specifically so the pre-call state (was the customer already logged in? was
 * the form key valid?) can be captured and compared against post-call state — see below for why
 * that precision matters.
 *
 * WHY `aroundExecute` and not the simpler `afterExecute`: LoginPost::execute() has an early-return
 * guard at its very top —
 *   `if ($this->session->isLoggedIn() || !$this->formKeyValidator->validate($this->getRequest()))`
 * — that skips authentication ENTIRELY (already logged in, or an invalid/missing form key/CSRF
 * token) without ever calling `customerAccountManagement->authenticate()`. An `afterExecute` that
 * only checked "is the session logged in after execute()?" would misclassify BOTH of those
 * early-return cases as a failed login attempt, even though no credential was ever actually
 * checked — most concretely, a legitimate customer resubmitting a stale page with an expired form
 * key would get counted as an attacker. Recomputing the exact same guard here before calling
 * $proceed() (reusing the real Session/Validator core also uses, not re-deriving the logic) closes
 * that gap at its source.
 *
 * Success handling: on success, `Observer\ResetLoginAttemptsObserver` already resets the counter
 * (via `customer_customer_authenticated`, dispatched from inside authenticate(), i.e. before this
 * plugin's $proceed() call even returns) — this plugin only ever increments, never resets, so
 * there is no double-handling between the two hooks.
 */
class LoginPostPlugin
{
    public function __construct(
        private readonly Config $config,
        private readonly CustomerSession $customerSession,
        private readonly FormKeyValidator $formKeyValidator,
        private readonly RemoteAddress $remoteAddress,
        private readonly LoginAttemptStore $attemptStore
    ) {
    }

    /**
     * @param callable(): mixed $proceed
     */
    public function aroundExecute(LoginPost $subject, callable $proceed)
    {
        if (!$this->config->isEnabled()) {
            return $proceed();
        }

        $request = $subject->getRequest();
        $wasAlreadyLoggedIn = $this->customerSession->isLoggedIn();
        $hadValidFormKey = $this->formKeyValidator->validate($request);
        $login = $request->getPost('login');
        $hadCredentials = is_array($login) && !empty($login['username']) && !empty($login['password']);

        $result = $proceed();

        // Mirrors LoginPost::execute()'s own top guard exactly: any of these three means core
        // never genuinely attempted authentication, so this request must not be counted either
        // way — see class docblock.
        if ($wasAlreadyLoggedIn || !$hadValidFormKey || !$hadCredentials) {
            return $result;
        }

        if ($this->customerSession->isLoggedIn()) {
            // Successful login — Observer\ResetLoginAttemptsObserver already handled the reset.
            return $result;
        }

        $ip = $this->remoteAddress->getRemoteAddress();
        if ($ip !== false && $ip !== '') {
            $this->attemptStore->recordFailure($ip);
        }

        return $result;
    }
}
