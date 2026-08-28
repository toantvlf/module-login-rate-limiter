<?php

declare(strict_types=1);

namespace TVTCommerce\LoginRateLimiter\Tests\Unit\Plugin;

use Magento\Customer\Controller\Ajax\Login as AjaxLogin;
use Magento\Customer\Model\Session as CustomerSession;
use Magento\Framework\Controller\Result\Json as JsonResult;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Framework\Controller\Result\Raw as RawResult;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use PHPUnit\Framework\TestCase;
use TVTCommerce\LoginRateLimiter\Model\Config;
use TVTCommerce\LoginRateLimiter\Model\RateLimit\LoginAttemptStore;
use TVTCommerce\LoginRateLimiter\Plugin\AjaxLoginPlugin;

require_once __DIR__ . '/_MagentoStubs.php';

/**
 * Covers Plugin\AjaxLoginPlugin's pre-check/record behavior — the fix for the security review's
 * HIGH finding that Magento\Customer\Controller\Ajax\Login (the checkout AJAX login popup)
 * bypassed this module's rate limit entirely. See _MagentoStubs.php for why this test declares
 * its own minimal stand-ins for the handful of real Magento classes the plugin depends on, and
 * FakeConfig/FakeLoginAttemptStore below for why the two TVTCommerce collaborators are simple
 * hand-written fakes rather than PHPUnit mocks.
 */
final class AjaxLoginPluginTest extends TestCase
{
    private const IP = '203.0.113.7';

    public function testDisabledModuleAlwaysProceedsWithoutTouchingTheAttemptStore(): void
    {
        // Even a "blocked" store must be ignored while the module is disabled.
        $store = new FakeLoginAttemptStore(true);
        $plugin = $this->makePlugin(new FakeConfig(false), $store, new RemoteAddress(self::IP), new CustomerSession());

        $proceedCalled = false;
        $proceedResult = new JsonResult();
        $proceed = function () use (&$proceedCalled, $proceedResult) {
            $proceedCalled = true;

            return $proceedResult;
        };

        $result = $plugin->aroundExecute(new AjaxLogin(), $proceed);

        self::assertTrue($proceedCalled);
        self::assertSame($proceedResult, $result);
        self::assertSame([], $store->recordedFailures);
    }

    public function testUnresolvableIpAlwaysProceedsWithoutTouchingTheAttemptStore(): void
    {
        $store = new FakeLoginAttemptStore(true);
        $plugin = $this->makePlugin(new FakeConfig(true), $store, new RemoteAddress(false), new CustomerSession());

        $proceedCalled = false;
        $proceed = function () use (&$proceedCalled) {
            $proceedCalled = true;

            return new JsonResult();
        };

        $plugin->aroundExecute(new AjaxLogin(), $proceed);

        self::assertTrue($proceedCalled);
        self::assertSame([], $store->recordedFailures);
    }

    public function testBlockedIpShortCircuitsWithoutEverCallingProceed(): void
    {
        $store = new FakeLoginAttemptStore(true);
        $plugin = $this->makePlugin(new FakeConfig(true), $store, new RemoteAddress(self::IP), new CustomerSession());

        $proceedCalled = false;
        $proceed = function () use (&$proceedCalled) {
            $proceedCalled = true;

            return new JsonResult();
        };

        $result = $plugin->aroundExecute(new AjaxLogin(), $proceed);

        self::assertFalse($proceedCalled, 'authenticate() must never run for a blocked IP');
        self::assertInstanceOf(JsonResult::class, $result);
        self::assertTrue($result->data['errors']);
        self::assertSame([], $store->recordedFailures);
    }

    public function testAlreadyLoggedInSessionIsNeverCountedEitherWay(): void
    {
        $store = new FakeLoginAttemptStore(false);
        $session = new CustomerSession();
        $session->loggedIn = true; // already logged in before this request
        $plugin = $this->makePlugin(new FakeConfig(true), $store, new RemoteAddress(self::IP), $session);

        $proceedResult = new JsonResult();
        $proceed = function () use ($proceedResult) {
            return $proceedResult;
        };

        $result = $plugin->aroundExecute(new AjaxLogin(), $proceed);

        self::assertSame($proceedResult, $result);
        self::assertSame([], $store->recordedFailures);
    }

    public function testBadRequestRawResultIsNeverCountedEitherWay(): void
    {
        $store = new FakeLoginAttemptStore(false);
        $plugin = $this->makePlugin(new FakeConfig(true), $store, new RemoteAddress(self::IP), new CustomerSession());

        $rawResult = new RawResult();
        $proceed = function () use ($rawResult) {
            // Malformed JSON / non-POST / non-XHR body — authenticate() never ran.
            return $rawResult;
        };

        $result = $plugin->aroundExecute(new AjaxLogin(), $proceed);

        self::assertSame($rawResult, $result);
        self::assertSame([], $store->recordedFailures);
    }

    public function testSuccessfulLoginIsNotRecordedAsAFailure(): void
    {
        $store = new FakeLoginAttemptStore(false);
        $session = new CustomerSession();
        $plugin = $this->makePlugin(new FakeConfig(true), $store, new RemoteAddress(self::IP), $session);

        $proceed = function () use ($session) {
            // Mirrors the real Login::execute(): logs the session in as a side effect of a
            // genuinely successful authenticate() call.
            $session->loggedIn = true;

            return (new JsonResult())->setData(['errors' => false, 'message' => 'Login successful.']);
        };

        $result = $plugin->aroundExecute(new AjaxLogin(), $proceed);

        self::assertFalse($result->data['errors']);
        self::assertSame([], $store->recordedFailures);
    }

    public function testFailedLoginIsRecordedAgainstTheIp(): void
    {
        $store = new FakeLoginAttemptStore(false);
        $plugin = $this->makePlugin(new FakeConfig(true), $store, new RemoteAddress(self::IP), new CustomerSession());

        $proceed = function () {
            return (new JsonResult())->setData(['errors' => true, 'message' => 'Invalid login or password.']);
        };

        $result = $plugin->aroundExecute(new AjaxLogin(), $proceed);

        self::assertTrue($result->data['errors']);
        self::assertSame([self::IP], $store->recordedFailures);
    }

    private function makePlugin(
        Config $config,
        LoginAttemptStore $store,
        RemoteAddress $remoteAddress,
        CustomerSession $session
    ): AjaxLoginPlugin {
        return new AjaxLoginPlugin($config, $session, $remoteAddress, $store, new JsonFactory());
    }
}

/**
 * Hand-written fake rather than a PHPUnit mock: overrides the constructor entirely (never calls
 * parent::__construct()) so it never needs a real ScopeConfigInterface, which this isolated,
 * Magento-framework-free harness does not provide.
 */
final class FakeConfig extends Config
{
    public function __construct(private readonly bool $enabled)
    {
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }
}

/**
 * Hand-written fake rather than a PHPUnit mock — same reasoning as FakeConfig above: overrides
 * the constructor entirely so it never needs a real ResourceConnection/LoggerInterface.
 */
final class FakeLoginAttemptStore extends LoginAttemptStore
{
    /** @var string[] */
    public array $recordedFailures = [];

    public function __construct(private readonly bool $blocked)
    {
    }

    public function isBlocked(string $ip): bool
    {
        return $this->blocked;
    }

    public function recordFailure(string $ip): void
    {
        $this->recordedFailures[] = $ip;
    }
}
