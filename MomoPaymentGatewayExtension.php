<?php
namespace Jankx\Extensions\Momo;

use Jankx\Extensions\AbstractExtension;
use Jankx\Extensions\Momo\Gateways\MomoGateway;
use Jankx\Extensions\PaymentSystem\Gateways\GatewayManager;

/**
 * MoMo Payment Gateway Extension.
 *
 * Registers the `momo` gateway channel with the payment-system extension:
 *
 *  1. purchase()          -> creates a MoMo `captureWallet` request and
 *                            redirects the customer to `payUrl`
 *  2. completePurchase()  -> verifies the MoMo signature on the return URL
 *                            and maps `resultCode` to a status
 *  3. queryStatus()       -> MoMo gateway query API (status reconciliation)
 *  4. refund()            -> MoMo refund API
 *  5. capture()/cancel()  -> MoMo confirm API (2-step flow, autoCapture=false)
 *
 * @package Jankx\Extensions\Momo
 */
class MomoPaymentGatewayExtension extends AbstractExtension
{
    protected static $instance;

    public function __construct()
    {
        $this->register_autoloader();
        parent::__construct();
    }

    protected function register_autoloader()
    {
        spl_autoload_register(function ($class) {
            $prefix = 'Jankx\\Extensions\\Momo\\';
            $base_dir = __DIR__ . '/src/';

            $len = strlen($prefix);
            if (strncmp($prefix, $class, $len) !== 0) {
                return;
            }

            $relative_class = substr($class, $len);
            $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

            if (file_exists($file)) {
                require $file;
            }
        });
    }

    public function init(): void
    {
        self::$instance = $this;
    }

    public static function get_instance(): ?self
    {
        return self::$instance;
    }

    public function register_hooks(): void
    {
        add_action('jankx/payment/register_gateways', [$this, 'registerGateways']);

        add_filter('jankx/payment/gateway/momo/default_config', [$this, 'defaultConfig']);

        add_action('admin_init', [$this, 'registerGatewaySettings']);
    }

    public function registerGatewaySettings(): void
    {
        register_setting('jankx_payment', 'jankx_payment_gateway_momo', [
            'type'              => 'array',
            'sanitize_callback' => [$this, 'sanitizeGatewaySettings'],
        ]);
    }

    public function sanitizeGatewaySettings($value): array
    {
        $value = is_array($value) ? $value : [];
        foreach ($value as $key => $item) {
            $value[$key] = is_string($item) ? sanitize_text_field($item) : $item;
        }
        return $value;
    }

    public function registerGateways(): void
    {
        GatewayManager::getInstance()->register('momo', MomoGateway::class);
    }

    public function defaultConfig(array $config): array
    {
        return array_merge($config, [
            'testMode'              => '1',
            'lang'                  => 'vi',
            'sandbox_partner_code' => '',
            'sandbox_access_key'   => '',
            'sandbox_secret_key'   => '',
        ]);
    }
}