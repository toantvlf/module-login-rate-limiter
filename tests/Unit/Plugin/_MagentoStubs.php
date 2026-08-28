<?php

declare(strict_types=1);

/**
 * Minimal, test-only stand-ins for the small slice of Magento framework surface
 * TVTCommerce\LoginRateLimiter\Plugin\AjaxLoginPlugin depends on. This isolated PHPUnit
 * environment deliberately has no real Magento framework installed (see tests/bootstrap.php,
 * which documents why every class tested so far has zero Magento dependency) — these are NOT
 * meant to be behaviorally faithful reimplementations of the real Magento classes, only
 * type-compatible stand-ins so a plugin that type-hints the REAL Magento class names can be
 * constructed and exercised directly in a plain unit test.
 *
 * Required explicitly by AjaxLoginPluginTest.php rather than autoloaded — this file is not
 * suffixed `Test.php`, so PHPUnit's own test-suite file discovery never touches it directly.
 */

namespace Magento\Customer\Controller\Ajax {
    class Login
    {
    }
}

namespace Magento\Customer\Model {
    class Session
    {
        public bool $loggedIn = false;

        public function isLoggedIn(): bool
        {
            return $this->loggedIn;
        }
    }
}

namespace Magento\Framework\HTTP\PhpEnvironment {
    class RemoteAddress
    {
        /**
         * @param string|false $address
         */
        public function __construct(private $address = false)
        {
        }

        /**
         * @return string|false
         */
        public function getRemoteAddress(bool $ipToLong = false)
        {
            return $this->address;
        }
    }
}

namespace Magento\Framework\Controller {
    interface ResultInterface
    {
    }
}

namespace Magento\Framework\Controller\Result {
    use Magento\Framework\Controller\ResultInterface;

    class Json implements ResultInterface
    {
        /** @var mixed */
        public $data = [];

        /**
         * @param mixed $data
         * @return $this
         */
        public function setData($data)
        {
            $this->data = $data;

            return $this;
        }
    }

    class Raw implements ResultInterface
    {
    }

    class JsonFactory
    {
        public function create(array $data = []): Json
        {
            return new Json();
        }
    }
}

namespace {
    if (!function_exists('__')) {
        /**
         * Minimal stand-in for Magento\Framework\Phrase's global __() translate helper —
         * AjaxLoginPlugin calls the real global __() when building its blocked-IP response, and
         * this isolated harness has no Magento framework loaded to provide it. Returns the raw
         * string unchanged, which is sufficient for asserting response shape/content in these
         * tests (they don't exercise Magento's actual translation pipeline).
         */
        function __($text, ...$args)
        {
            return $text;
        }
    }
}
