<?php

declare(strict_types=1);

namespace TVTCommerce\LoginRateLimiter\Plugin;

use Magento\Customer\Controller\Ajax\Login as AjaxLogin;
use Magento\Customer\Model\Session as CustomerSession;
use Magento\Framework\Controller\Result\Json as JsonResult;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Framework\Controller\ResultInterface;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use TVTCommerce\LoginRateLimiter\Model\Config;
use TVTCommerce\LoginRateLimiter\Model\RateLimit\LoginAttemptStore;

/**
 * Covers the SAME per-IP rate limit as Plugin\LoginPostPlugin + Observer\CheckLoginRateLimitObserver,
 * but for a completely different, unauthenticated JSON POST controller:
 * Magento\Customer\Controller\Ajax\Login (`customer/ajax/login`, full action name
 * `customer_ajax_login`) — the storefront checkout "login" popup's AJAX endpoint (verified wired via
 * vendor/magento/module-customer/view/frontend/web/js/action/login.js, which posts to
 * `customer/ajax/login` by default). Verified against real core source
 * (vendor/magento/module-customer/Controller/Ajax/Login.php) that this is a DIFFERENT controller
 * class with a DIFFERENT full action name than the classic login form's LoginPost, so neither
 * `controller_action_predispatch_customer_account_loginPost` (Observer\CheckLoginRateLimitObserver)
 * nor the di.xml plugin scoped to LoginPost (Plugin\LoginPostPlugin) ever run for it — this
 * controller calls the exact same `Magento\Customer\Api\AccountManagementInterface::authenticate()`
 * underneath, so it is just as capable of credential-stuffing/account-enumeration abuse as the main
 * form, and (unlike the main form) is exposed by default on every checkout page, not just the
 * dedicated login page.
 *
 * WHY an `around` plugin doing BOTH the pre-check AND the record-outcome step in one class (unlike
 * the classic form, which splits those two jobs across a predispatch-event Observer and a di.xml
 * Plugin): `controller_action_predispatch_<full_action_name>` is in fact dispatched generically by
 * \Magento\Framework\App\FrontController::dispatchPreDispatchEvents() for every controller,
 * including this one (verified by reading that method — `controller_action_predispatch_` .
 * $request->getFullActionName() fires unconditionally, not just for controllers that opt in), so a
 * `controller_action_predispatch_customer_ajax_login` observer was a viable alternative. A single
 * `around` plugin on Login::execute() was chosen instead because it keeps this entire integration
 * (block-check + outcome-recording) self-contained in one class reusing the exact same
 * Config/LoginAttemptStore services Plugin\LoginPostPlugin already uses, without adding a second
 * event-name dependency for a controller this module wasn't originally scoped to cover.
 *
 * Outcome classification mirrors Plugin\LoginPostPlugin's exact technique (compare
 * CustomerSession::isLoggedIn() before/after $proceed()) rather than trying to read
 * \Magento\Framework\Controller\Result\Json's data — that class deliberately has NO public getter
 * for the data it was given (Json::setData() immediately serializes to a private $json string with
 * no corresponding getData()), so re-deriving the outcome from session state (the same signal
 * LoginPostPlugin already trusts) is both simpler and avoids reflection into a framework internal:
 *  - Login::execute() returns a \Magento\Framework\Controller\Result\Raw (HTTP 400) when the
 *    request body isn't valid JSON, isn't a POST, or isn't XHR — i.e. authenticate() was NEVER
 *    called at all. That is treated the same as LoginPostPlugin's "no genuine attempt" cases.
 *  - Unlike LoginPost, Ajax\Login::execute() has no "already logged in" early-return guard of its
 *    own at all — verified against its real source — so this plugin applies that same skip here
 *    defensively: if the session was ALREADY logged in before $proceed(), the post-call
 *    isLoggedIn() check can no longer distinguish "still logged in because auth failed" from
 *    "still logged in because it was already true", so — exactly like LoginPostPlugin — that
 *    request is not counted either way.
 *  - Otherwise: Login::execute() only ever calls `$this->customerSession->setCustomerDataAsLoggedIn()`
 *    on a genuine successful authenticate() call (verified against its real source) — so
 *    isLoggedIn() being true only after $proceed() means success (reset already handled by
 *    Observer\ResetLoginAttemptsObserver, same as LoginPostPlugin), and still false means a
 *    genuine authentication failure worth recording.
 *
 * The blocked short-circuit response mirrors the shape Login::execute() itself returns on failure
 * (`{"errors": true, "message": ...}`), which is also the exact shape
 * vendor/magento/module-customer/view/frontend/web/js/action/login.js's `.done()` handler already
 * expects and passes straight to `messageContainer.addErrorMessage(response)` — verified against
 * that real core source, not guessed.
 */
class AjaxLoginPlugin
{
    public function __construct(
        private readonly Config $config,
        private readonly CustomerSession $customerSession,
        private readonly RemoteAddress $remoteAddress,
        private readonly LoginAttemptStore $attemptStore,
        private readonly JsonFactory $resultJsonFactory
    ) {
    }

    /**
     * @param callable(): ResultInterface $proceed
     */
    public function aroundExecute(AjaxLogin $subject, callable $proceed): ResultInterface
    {
        if (!$this->config->isEnabled()) {
            return $proceed();
        }

        $ip = $this->remoteAddress->getRemoteAddress();
        if ($ip === false || $ip === '') {
            // Can't identify the client IP — nothing to rate-limit against. Fails open, same
            // reasoning as Observer\CheckLoginRateLimitObserver for the main login form.
            return $proceed();
        }

        if ($this->attemptStore->isBlocked($ip)) {
            // Short-circuit BEFORE $proceed() — execute() (and therefore authenticate(), which
            // verifies the password hash) never runs for a blocked IP, exactly like
            // Observer\CheckLoginRateLimitObserver does for the main login form. Message text is
            // deliberately identical to that observer's (which itself reuses core's own
            // account-lockout wording) — see README.md's "Generic, shared block message" section.
            return $this->resultJsonFactory->create()->setData([
                'errors' => true,
                'message' => (string) __('The account is locked.'),
            ]);
        }

        $wasAlreadyLoggedIn = $this->customerSession->isLoggedIn();

        $result = $proceed();

        // Mirrors LoginPostPlugin's own guard: either this request never genuinely reached
        // authenticate() (Raw 400 from a malformed/non-XHR/non-POST body), or the session was
        // already logged in beforehand and the post-call state can no longer be trusted to mean
        // "authentication succeeded" — see class docblock.
        if ($wasAlreadyLoggedIn || !$result instanceof JsonResult) {
            return $result;
        }

        if ($this->customerSession->isLoggedIn()) {
            // Successful login — Observer\ResetLoginAttemptsObserver already handled the reset.
            return $result;
        }

        $this->attemptStore->recordFailure($ip);

        return $result;
    }
}
