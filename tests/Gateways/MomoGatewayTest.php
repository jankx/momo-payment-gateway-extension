<?php
namespace Jankx\Extensions\Momo\Tests\Gateways;

use PHPUnit\Framework\TestCase;
use Brain\Monkey;
use Brain\Monkey\Functions;
use Jankx\Extensions\Momo\Gateways\MomoGateway;

class TestMomoGateway extends MomoGateway
{
    public function setConfig(array $config): void
    {
        $this->config = $config;
    }

    public function getConfigValue(): array
    {
        return $this->config;
    }

    public function setCredentials(array $credentials): void
    {
        $this->credentials = $credentials;
    }

    public function getCredentials(): array
    {
        return $this->credentials;
    }

    public function exposeSign(string $raw): string
    {
        return $this->sign($raw);
    }

    public function exposeBuildOrderId(string $transactionId): string
    {
        return $this->buildOrderId($transactionId);
    }

    public function exposeBuildRequestId(): string
    {
        return $this->buildRequestId();
    }

    public function exposeNormalizeOrderInfo(string $description, string $orderId): string
    {
        return $this->normalizeOrderInfo($description, $orderId);
    }

    public function exposeToAscii(string $value): string
    {
        return $this->toAscii($value);
    }

    public function exposeNormalizePhone(string $phone): string
    {
        return $this->normalizePhone($phone);
    }

    public function exposeGetLang(): string
    {
        return $this->getLang();
    }

    public function exposeIsTestMode(): bool
    {
        return $this->isTestMode();
    }

    public function exposeGetApiUrl(string $path): string
    {
        return $this->getApiUrl($path);
    }

    public function exposeGetResultCodeMessage(int $code): string
    {
        return $this->getResultCodeMessage($code);
    }

    public function exposePersistOrderRef(string $transactionId, string $orderId): void
    {
        $this->persistOrderRef($transactionId, $orderId);
    }
}

class MomoGatewayTest extends TestCase
{
    const TEST_PARTNER = 'MOMOT5BZ20231213_TEST';
    const TEST_ACCESS_KEY = 'ACCESS_TEST';
    const TEST_SECRET_KEY = 'SECRET_TEST';

    protected function setUp(): void
    {
        parent::setUp();
        Monkey\setUp();
        momo_test_stub_wp_functions();
        $GLOBALS['__post_meta'] = [];
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['__post_meta']);
        $_SERVER = [];
        Monkey\tearDown();
        parent::tearDown();
    }

    protected function sandboxConfig(array $overrides = []): array
    {
        return array_merge([
            'testMode' => true,
            'lang' => 'vi',
            'sandbox_partner_code' => self::TEST_PARTNER,
            'sandbox_access_key' => self::TEST_ACCESS_KEY,
            'sandbox_secret_key' => self::TEST_SECRET_KEY,
        ], $overrides);
    }

    protected function productionConfig(): array
    {
        return array_merge($this->sandboxConfig(), [
            'testMode' => false,
            'production_partner_code' => 'PROD-PARTNER',
            'production_access_key' => 'PROD-ACCESS',
            'production_secret_key' => 'PROD-SECRET',
        ]);
    }

    protected function newGateway(): TestMomoGateway
    {
        $gateway = new TestMomoGateway();
        $gateway->initialize($this->sandboxConfig());
        return $gateway;
    }

    // ------------------------------------------------------------------
    // Independent re-implementations of the MoMo signature specs.
    // ------------------------------------------------------------------

    protected function hmac(string $raw): string
    {
        return hash_hmac('sha256', $raw, self::TEST_SECRET_KEY);
    }

    /**
     * Create signature: accessKey&amount&extraData&ipnUrl&orderId&orderInfo
     * &partnerCode&redirectUrl&requestId&requestType (fixed order).
     */
    protected function expectedCreateSignature(array $f): string
    {
        $raw = 'accessKey=' . $f['accessKey']
            . '&amount=' . $f['amount']
            . '&extraData=' . $f['extraData']
            . '&ipnUrl=' . $f['ipnUrl']
            . '&orderId=' . $f['orderId']
            . '&orderInfo=' . $f['orderInfo']
            . '&partnerCode=' . $f['partnerCode']
            . '&redirectUrl=' . $f['redirectUrl']
            . '&requestId=' . $f['requestId']
            . '&requestType=' . MomoGateway::REQUEST_TYPE_CAPTURE_WALLET;
        return $this->hmac($raw);
    }

    protected function expectedQuerySignature(string $orderId, string $requestId): string
    {
        $raw = 'accessKey=' . self::TEST_ACCESS_KEY
            . '&orderId=' . $orderId
            . '&partnerCode=' . self::TEST_PARTNER
            . '&requestId=' . $requestId;
        return $this->hmac($raw);
    }

    protected function expectedRefundSignature(int $amount, string $description, string $orderId, string $requestId, string $transId): string
    {
        $raw = 'accessKey=' . self::TEST_ACCESS_KEY
            . '&amount=' . $amount
            . '&description=' . $description
            . '&orderId=' . $orderId
            . '&partnerCode=' . self::TEST_PARTNER
            . '&requestId=' . $requestId
            . '&transId=' . $transId;
        return $this->hmac($raw);
    }

    protected function expectedConfirmSignature(int $amount, string $description, string $orderId, string $requestId, string $requestType): string
    {
        $raw = 'accessKey=' . self::TEST_ACCESS_KEY
            . '&amount=' . $amount
            . '&description=' . $description
            . '&orderId=' . $orderId
            . '&partnerCode=' . self::TEST_PARTNER
            . '&requestId=' . $requestId
            . '&requestType=' . $requestType;
        return $this->hmac($raw);
    }

    /**
     * Callback verification signature: sort all params a-z (URL-encode
     * non-ASCII values), join as key=value&key=value.
     */
    protected function expectedVerifySignature(array $params): string
    {
        unset($params['signature']);
        ksort($params);

        $pairs = [];
        foreach ($params as $key => $value) {
            $value = (string) $value;
            if (!preg_match('/^[\x20-\x7E]*$/', $value)) {
                $value = rawurlencode($value);
            }
            $pairs[] = $key . '=' . $value;
        }

        return $this->hmac(implode('&', $pairs));
    }

    protected function signedResultParams(array $overrides = []): array
    {
        $params = array_merge([
            'partnerCode' => self::TEST_PARTNER,
            'orderId' => 'MO0000004243242424',
            'requestId' => 'RQ4242424242424242',
            'amount' => 100000,
            'orderInfo' => 'Order MO0000004243242424',
            'orderType' => 'momo_wallet',
            'transId' => 4088878653,
            'resultCode' => 0,
            'message' => 'Successful.',
            'payType' => 'qr',
            'responseTime' => 1721720663942,
            'extraData' => '',
        ], $overrides);

        $params['signature'] = $this->expectedVerifySignature($params);
        return $params;
    }

    protected function mockRemoteApi($body, &$captured = null): void
    {
        Functions\when('wp_remote_post')->alias(function ($url, $args) use (&$captured, $body) {
            $captured = ['url' => $url, 'args' => $args];
            return ['body' => $body];
        });
        Functions\when('wp_remote_retrieve_body')->alias(function ($response) {
            return $response['body'] ?? '';
        });
        Functions\when('is_wp_error')->justReturn(false);
    }

    protected function mockRemoteApiJson(array $body, &$captured = null): void
    {
        $this->mockRemoteApi(json_encode($body), $captured);
    }

    // ------------------------------------------------------------------
    // initialize()
    // ------------------------------------------------------------------

    public function test_initialize_merges_defaults()
    {
        $gateway = new TestMomoGateway();
        $gateway->initialize([
            'testMode' => true,
            'sandbox_partner_code' => 'PARTNER-X',
        ]);

        $config = $gateway->getConfigValue();
        $this->assertEquals('vi', $config['lang']);
        $this->assertEquals('PARTNER-X', $config['sandbox_partner_code']);
    }

    public function test_initialize_sandbox_mode_uses_sandbox_credentials()
    {
        $gateway = new TestMomoGateway();
        $gateway->initialize($this->sandboxConfig(['testMode' => true]));

        $this->assertEquals([
            'partner_code' => self::TEST_PARTNER,
            'access_key' => self::TEST_ACCESS_KEY,
            'secret_key' => self::TEST_SECRET_KEY,
        ], $gateway->getCredentials());
    }

    public function test_initialize_production_mode_uses_production_credentials()
    {
        $gateway = new TestMomoGateway();
        $gateway->initialize($this->productionConfig());

        $this->assertEquals([
            'partner_code' => 'PROD-PARTNER',
            'access_key' => 'PROD-ACCESS',
            'secret_key' => 'PROD-SECRET',
        ], $gateway->getCredentials());
    }

    public function test_initialize_missing_credentials_defaults_to_empty_string()
    {
        $gateway = new TestMomoGateway();
        $gateway->initialize(['testMode' => true]);

        $this->assertEquals([
            'partner_code' => '',
            'access_key' => '',
            'secret_key' => '',
        ], $gateway->getCredentials());
    }

    // ------------------------------------------------------------------
    // isAvailable()
    // ------------------------------------------------------------------

    public function test_isAvailable_true_when_all_required_credentials_present()
    {
        $this->assertTrue($this->newGateway()->isAvailable());
    }

    public function test_isAvailable_false_when_partner_code_missing()
    {
        $gateway = $this->newGateway();
        $gateway->setCredentials(['partner_code' => '', 'access_key' => 'X', 'secret_key' => 'Y']);
        $this->assertFalse($gateway->isAvailable());
    }

    public function test_isAvailable_false_when_access_key_missing()
    {
        $gateway = $this->newGateway();
        $gateway->setCredentials(['partner_code' => 'X', 'access_key' => '', 'secret_key' => 'Y']);
        $this->assertFalse($gateway->isAvailable());
    }

    public function test_isAvailable_false_when_secret_key_missing()
    {
        $gateway = $this->newGateway();
        $gateway->setCredentials(['partner_code' => 'X', 'access_key' => 'Y', 'secret_key' => '']);
        $this->assertFalse($gateway->isAvailable());
    }

    // ------------------------------------------------------------------
    // getName() / endpoints
    // ------------------------------------------------------------------

    public function test_getName_returns_display_name()
    {
        $gateway = new TestMomoGateway();
        $this->assertEquals('MoMo', $gateway->getName());
    }

    public function test_api_urls_resolve_per_mode()
    {
        $this->assertEquals(MomoGateway::API_URL_TEST . MomoGateway::PATH_CREATE, $this->newGateway()->exposeGetApiUrl(MomoGateway::PATH_CREATE));

        $gateway = new TestMomoGateway();
        $gateway->initialize($this->productionConfig());
        $this->assertEquals(MomoGateway::API_URL_PROD . MomoGateway::PATH_CREATE, $gateway->exposeGetApiUrl(MomoGateway::PATH_CREATE));
    }

    // ------------------------------------------------------------------
    // purchase()
    // ------------------------------------------------------------------

    public function test_purchase_posts_capture_wallet_request()
    {
        $gateway = $this->newGateway();
        $captured = null;
        $this->mockRemoteApiJson([
            'resultCode' => 0,
            'message' => 'Successful.',
            'payUrl' => 'https://payment.momo.vn/pay/rq/123',
            'requestId' => 'RQ123',
            'orderId' => 'MO0000004243242424',
            'amount' => 100000,
        ], $captured);

        $result = $gateway->purchase([
            'transactionId' => '42',
            'amount' => 100000,
            'returnUrl' => 'https://example.com/payment/return/42',
            'description' => 'Order #42',
        ]);

        $this->assertNotNull($captured);
        $this->assertEquals(MomoGateway::API_URL_TEST . MomoGateway::PATH_CREATE, $captured['url']);
        $this->assertSame('application/json; charset=UTF-8', $captured['args']['headers']['Content-Type']);
        $this->assertEquals(30, $captured['args']['timeout']);

        $body = json_decode($captured['args']['body'], true);
        $this->assertSame(self::TEST_PARTNER, $body['partnerCode']);
        $this->assertSame('captureWallet', $body['requestType']);
        $this->assertSame(100000, $body['amount']);
        $this->assertSame('vi', $body['lang']);
        $this->assertSame('https://example.com/payment/return/42', $body['redirectUrl']);

        $expectedSig = $this->expectedCreateSignature([
            'accessKey' => self::TEST_ACCESS_KEY,
            'amount' => $body['amount'],
            'extraData' => $body['extraData'],
            'ipnUrl' => $body['ipnUrl'],
            'orderId' => $body['orderId'],
            'orderInfo' => $body['orderInfo'],
            'partnerCode' => $body['partnerCode'],
            'redirectUrl' => $body['redirectUrl'],
            'requestId' => $body['requestId'],
        ]);
        $this->assertSame($expectedSig, $body['signature']);
    }

    public function test_purchase_returns_redirect_payload()
    {
        $gateway = $this->newGateway();
        $this->mockRemoteApiJson([
            'resultCode' => 0,
            'message' => 'Successful.',
            'payUrl' => 'https://payment.momo.vn/pay/abc',
            'requestId' => 'RQ1',
            'orderId' => 'MO0000004243242424',
            'amount' => 100000,
        ]);

        $result = $gateway->purchase([
            'transactionId' => '42',
            'amount' => 100000,
            'returnUrl' => 'https://example.com/return',
        ]);

        $this->assertEquals('redirect', $result['status']);
        $this->assertEquals('GET', $result['redirectMethod']);
        $this->assertEquals('https://payment.momo.vn/pay/abc', $result['redirectUrl']);
        $this->assertMatchesRegularExpression('/^MO[A-Za-z0-9]{1,38}$/', $result['transactionId']);
        $this->assertEquals(
            $result['transactionId'],
            $GLOBALS['__post_meta']['_transaction_id']
        );
    }

    public function test_purchase_rejects_amount_out_of_range()
    {
        $gateway = $this->newGateway();

        $result = $gateway->purchase(['transactionId' => '1', 'amount' => 500]);
        $this->assertEquals('failed', $result['status']);
        $this->assertEquals('AMOUNT_INVALID', $result['code']);

        $result = $gateway->purchase(['transactionId' => '1', 'amount' => 60000000]);
        $this->assertEquals('failed', $result['status']);
        $this->assertEquals('AMOUNT_INVALID', $result['code']);
    }

    public function test_purchase_returns_failed_on_error_result_code()
    {
        $gateway = $this->newGateway();
        $this->mockRemoteApiJson([
            'resultCode' => 1017,
            'message' => 'System is busy, try again later.',
        ]);

        $result = $gateway->purchase(['transactionId' => '1', 'amount' => 10000]);

        $this->assertEquals('failed', $result['status']);
        $this->assertEquals('1017', $result['code']);
        $this->assertStringContainsString('busy', strtolower($result['message']));
    }

    public function test_purchase_adds_auto_capture_when_passed()
    {
        $gateway = $this->newGateway();
        $captured = null;
        $this->mockRemoteApiJson(['resultCode' => 0, 'payUrl' => 'https://payment.momo.vn/pay/1'], $captured);

        $gateway->purchase([
            'transactionId' => '1',
            'amount' => 10000,
            'autoCapture' => false,
        ]);

        $body = json_decode($captured['args']['body'], true);
        $this->assertFalse($body['autoCapture']);
    }

    public function test_purchase_adds_user_info_and_ipn_url()
    {
        $gateway = $this->newGateway();
        $captured = null;
        $this->mockRemoteApiJson(['resultCode' => 0, 'payUrl' => 'https://payment.momo.vn/pay/1'], $captured);

        $gateway->purchase([
            'transactionId' => '1',
            'amount' => 10000,
            'customer_name' => 'Nguyen Van A',
            'customer_email' => 'customer@example.com',
            'customer_phone' => '+84 912 345 678',
            'ipnUrl' => 'https://example.com/momo/ipn',
        ]);

        $body = json_decode($captured['args']['body'], true);
        $this->assertSame('Nguyen Van A', $body['userInfo']['name']);
        $this->assertSame('customer@example.com', $body['userInfo']['email']);
        $this->assertSame('84912345678', $body['userInfo']['phoneNumber']);
        $this->assertSame('https://example.com/momo/ipn', $body['ipnUrl']);
    }

    public function test_purchase_persists_order_reference()
    {
        $gateway = $this->newGateway();
        $this->mockRemoteApiJson(['resultCode' => 0, 'payUrl' => 'https://payment.momo.vn/pay/1']);

        $result = $gateway->purchase([
            'transactionId' => '42',
            'amount' => 10000,
            'returnUrl' => 'https://example.com/return',
        ]);

        $this->assertEquals(
            $result['transactionId'],
            $GLOBALS['__post_meta']['_transaction_id']
        );
    }

    public function test_purchase_posts_to_production_url_in_production_mode()
    {
        $gateway = new TestMomoGateway();
        $gateway->initialize($this->productionConfig());
        $captured = null;
        $this->mockRemoteApiJson(['resultCode' => 0, 'payUrl' => 'https://payment.momo.vn/pay/1'], $captured);

        $gateway->purchase(['transactionId' => '1', 'amount' => 10000]);

        $this->assertEquals(MomoGateway::API_URL_PROD . MomoGateway::PATH_CREATE, $captured['url']);
    }

    public function test_purchase_order_id_is_unique_alphanumeric()
    {
        $gateway = $this->newGateway();

        $refA = $gateway->exposeBuildOrderId('42');
        $refB = $gateway->exposeBuildOrderId('42');

        $this->assertLessThanOrEqual(40, strlen($refA));
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9]{1,40}$/', $refA);
        $this->assertStringStartsWith('MO', $refA);
        $this->assertNotSame($refA, $refB);
    }

    public function test_purchase_request_id_is_unique_alphanumeric()
    {
        $gateway = $this->newGateway();

        $a = $gateway->exposeBuildRequestId();
        $b = $gateway->exposeBuildRequestId();

        $this->assertMatchesRegularExpression('/^[A-Za-z0-9]{1,40}$/', $a);
        $this->assertNotSame($a, $b);
    }

    // ------------------------------------------------------------------
    // completePurchase()
    // ------------------------------------------------------------------

    public function test_completePurchase_success()
    {
        $gateway = $this->newGateway();
        $params = $this->signedResultParams(['resultCode' => 0]);
        $params['transId'] = 4088878653;

        $result = $gateway->completePurchase($params);

        $this->assertEquals('success', $result['status']);
        $this->assertEquals('4088878653', $result['transactionId']);
    }

    public function test_completePurchase_success_with_request_params_wrapper()
    {
        $gateway = $this->newGateway();
        $params = $this->signedResultParams(['resultCode' => 0]);
        $params['transId'] = 4088878653;

        $result = $gateway->completePurchase(['request_params' => $params]);

        $this->assertEquals('success', $result['status']);
        $this->assertEquals('4088878653', $result['transactionId']);
    }

    public function test_completePurchase_authorized_pending_on_9000()
    {
        $gateway = $this->newGateway();
        $params = $this->signedResultParams(['resultCode' => 9000]);
        $params['transId'] = 4088878653;

        $result = $gateway->completePurchase($params);

        $this->assertEquals('pending', $result['status']);
        $this->assertEquals('9000', $result['code']);
        $this->assertStringContainsString('authorized', strtolower($result['message']));
    }

    public function test_completePurchase_failed_code()
    {
        $gateway = $this->newGateway();
        $params = $this->signedResultParams(['resultCode' => 1001, 'message' => '']);

        $result = $gateway->completePurchase($params);

        $this->assertEquals('failed', $result['status']);
        $this->assertEquals('1001', $result['code']);
    }

    public function test_completePurchase_uses_result_message_when_present()
    {
        $gateway = $this->newGateway();
        $params = $this->signedResultParams(['resultCode' => 1004, 'message' => 'Customer ordered product is not in stock']);

        $result = $gateway->completePurchase($params);

        $this->assertEquals('failed', $result['status']);
        $this->assertStringContainsString('not in stock', $result['message']);
    }

    public function test_completePurchase_rejects_invalid_signature()
    {
        $gateway = $this->newGateway();
        $params = $this->signedResultParams(['resultCode' => 0]);
        $params['amount'] = 99999;

        $result = $gateway->completePurchase($params);

        $this->assertEquals('failed', $result['status']);
        $this->assertEquals('HASH_MISMATCH', $result['code']);
    }

    public function test_completePurchase_rejects_partner_code_mismatch()
    {
        $gateway = $this->newGateway();
        $params = $this->signedResultParams(['resultCode' => 0, 'partnerCode' => 'OTHER_PARTNER']);

        $result = $gateway->completePurchase($params);

        $this->assertEquals('failed', $result['status']);
        $this->assertEquals('PARTNER_MISMATCH', $result['code']);
    }

    // ------------------------------------------------------------------
    // verifySignature()
    // ------------------------------------------------------------------

    public function test_verifySignature_accepts_valid_callback()
    {
        $gateway = $this->newGateway();
        $params = $this->signedResultParams([]);
        $this->assertTrue($gateway->verifySignature($params));
    }

    public function test_verifySignature_rejects_tampered_params()
    {
        $gateway = $this->newGateway();
        $params = $this->signedResultParams([]);
        $params['amount'] = '999';
        $this->assertFalse($gateway->verifySignature($params));
    }

    public function test_verifySignature_rejects_when_signature_missing()
    {
        $gateway = $this->newGateway();
        $params = $this->signedResultParams([]);
        unset($params['signature']);
        $this->assertFalse($gateway->verifySignature($params));
    }

    public function test_verifySignature_rejects_when_secret_key_empty()
    {
        $gateway = new TestMomoGateway();
        $gateway->initialize(['testMode' => true, 'sandbox_secret_key' => '']);
        $params = $this->signedResultParams([]);
        $this->assertFalse($gateway->verifySignature($params));
    }

    public function test_verifySignature_url_encodes_non_ascii_values()
    {
        $gateway = $this->newGateway();
        $params = [
            'message' => 'Giao dịch thành công',
            'orderInfo' => 'Thanh toán đơn hàng',
            'transId' => 4088878653,
            'resultCode' => 0,
        ];

        $test = $params;
        $test['signature'] = $this->expectedVerifySignature($params);

        $this->assertTrue($gateway->verifySignature($test));
    }

    // ------------------------------------------------------------------
    // queryStatus()
    // ------------------------------------------------------------------

    protected function signedQueryResponse(array $overrides = [], int $code = 0)
    {
        $result = array_merge([
            'partnerCode' => self::TEST_PARTNER,
            'requestId' => 'RQ4242424242424242',
            'orderId' => 'MO0000004243242424',
            'amount' => 100000,
            'transId' => 4088878653,
            'payType' => 'web',
            'resultCode' => $code,
            'message' => $code === 0 ? 'Successful.' : 'Failed.',
            'responseTime' => 1721720663942,
        ], $overrides);

        $result['signature'] = $this->expectedVerifySignature($result);
        return $result;
    }

    public function test_queryStatus_returns_completed_on_code_0()
    {
        $gateway = $this->newGateway();
        $this->mockRemoteApiJson($this->signedQueryResponse([], 0));
        $this->assertEquals('completed', $gateway->queryStatus('MO0000004243242424'));
    }

    public function test_queryStatus_returns_pending_on_authorized_and_pending_codes()
    {
        $gateway = $this->newGateway();

        $this->mockRemoteApiJson($this->signedQueryResponse([], 9000));
        $this->assertEquals('pending', $gateway->queryStatus('MO0000004243242424'));

        $this->mockRemoteApiJson($this->signedQueryResponse([], 7002));
        $this->assertEquals('pending', $gateway->queryStatus('MO0000004243242424'));
    }

    public function test_queryStatus_returns_failed_on_error_code()
    {
        $gateway = $this->newGateway();
        $this->mockRemoteApiJson($this->signedQueryResponse([], 1001));
        $this->assertEquals('failed', $gateway->queryStatus('MO0000004243242424'));
    }

    public function test_queryStatus_returns_failed_on_invalid_response_signature()
    {
        $gateway = $this->newGateway();
        $body = $this->signedQueryResponse([], 0);
        $body['amount'] = 99999;
        $this->mockRemoteApiJson($body);
        $this->assertEquals('failed', $gateway->queryStatus('MO0000004243242424'));
    }

    public function test_queryStatus_returns_failed_on_wp_error()
    {
        $gateway = $this->newGateway();
        Functions\when('wp_remote_post')->justReturn(new \WP_Error('http_error', 'boom'));
        Functions\when('wp_remote_retrieve_body')->justReturn('');
        Functions\when('is_wp_error')->justReturn(true);

        $this->assertEquals('failed', $gateway->queryStatus('MO0000004243242424'));
    }

    public function test_queryStatus_posts_to_query_endpoint()
    {
        $gateway = $this->newGateway();
        $captured = null;
        $this->mockRemoteApiJson($this->signedQueryResponse([], 0), $captured);

        $gateway->queryStatus('MO0000004243242424');

        $this->assertEquals(MomoGateway::API_URL_TEST . MomoGateway::PATH_QUERY, $captured['url']);
        $body = json_decode($captured['args']['body'], true);
        $this->assertSame('MO0000004243242424', $body['orderId']);
        $expected = $this->expectedQuerySignature($body['orderId'], $body['requestId']);
        $this->assertSame($expected, $body['signature']);
    }

    // ------------------------------------------------------------------
    // refund()
    // ------------------------------------------------------------------

    public function test_refund_posts_refund_request_with_valid_signature()
    {
        $gateway = $this->newGateway();
        $captured = null;
        $this->mockRemoteApiJson(['resultCode' => 0, 'message' => 'Refund successful.'], $captured);

        $result = $gateway->refund([
            'transId' => '4088878653',
            'amount' => 100000,
            'description' => 'Hoan tra don hang',
        ]);

        $this->assertEquals('success', $result['status']);

        $body = json_decode($captured['args']['body'], true);
        $this->assertSame('4088878653', $body['transId']);
        $this->assertStringStartsWith('MO', $body['orderId']);
        $expected = $this->expectedRefundSignature((int) $body['amount'], $body['description'], $body['orderId'], $body['requestId'], $body['transId']);
        $this->assertSame($expected, $body['signature']);
    }

    public function test_refund_returns_failed_on_error_result()
    {
        $gateway = $this->newGateway();
        $this->mockRemoteApiJson(['resultCode' => 1017, 'message' => 'System is busy, try again later.']);

        $result = $gateway->refund(['transId' => '4088878653', 'amount' => 100000]);

        $this->assertEquals('failed', $result['status']);
        $this->assertEquals('1017', $result['code']);
    }

    public function test_refund_requires_trans_id()
    {
        $gateway = $this->newGateway();

        $result = $gateway->refund(['amount' => 100000]);

        $this->assertEquals('failed', $result['status']);
        $this->assertEquals('MISSING_TRANS_ID', $result['code']);
    }

    public function test_refund_posts_to_refund_endpoint()
    {
        $gateway = $this->newGateway();
        $captured = null;
        $this->mockRemoteApiJson(['resultCode' => 0, 'message' => 'OK'], $captured);

        $gateway->refund(['transId' => '4088878653', 'amount' => 100000]);

        $this->assertEquals(MomoGateway::API_URL_TEST . MomoGateway::PATH_REFUND, $captured['url']);
    }

    // ------------------------------------------------------------------
    // confirm() / capture() / cancel()
    // ------------------------------------------------------------------

    public function test_capture_posts_capture_request()
    {
        $gateway = $this->newGateway();
        $captured = null;
        $this->mockRemoteApiJson(['resultCode' => 0, 'message' => 'Captured.'], $captured);

        $result = $gateway->capture([
            'orderId' => 'MO0000004243242424',
            'amount' => 100000,
        ]);

        $this->assertEquals('success', $result['status']);

        $body = json_decode($captured['args']['body'], true);
        $this->assertSame('capture', $body['requestType']);
        $this->assertSame('MO0000004243242424', $body['orderId']);
        $expected = $this->expectedConfirmSignature((int) $body['amount'], $body['description'], $body['orderId'], $body['requestId'], $body['requestType']);
        $this->assertSame($expected, $body['signature']);
    }

    public function test_cancel_posts_cancel_request()
    {
        $gateway = $this->newGateway();
        $captured = null;
        $this->mockRemoteApiJson(['resultCode' => 0, 'message' => 'Cancelled.'], $captured);

        $result = $gateway->cancel([
            'orderId' => 'MO0000004243242424',
            'amount' => 100000,
            'description' => 'Cannot fulfill order',
        ]);

        $this->assertEquals('success', $result['status']);

        $body = json_decode($captured['args']['body'], true);
        $this->assertSame('cancel', $body['requestType']);
        $this->assertSame('Cannot fulfill order', $body['description']);
        $expected = $this->expectedConfirmSignature((int) $body['amount'], $body['description'], $body['orderId'], $body['requestId'], $body['requestType']);
        $this->assertSame($expected, $body['signature']);
    }

    public function test_confirm_returns_failed_on_error_result()
    {
        $gateway = $this->newGateway();
        $this->mockRemoteApiJson(['resultCode' => 1001, 'message' => 'Capture failed.']);

        $result = $gateway->capture(['orderId' => 'MO0000004243242424', 'amount' => 100000]);

        $this->assertEquals('failed', $result['status']);
        $this->assertEquals('1001', $result['code']);
    }

    public function test_confirm_posts_to_confirm_endpoint()
    {
        $gateway = $this->newGateway();
        $captured = null;
        $this->mockRemoteApiJson(['resultCode' => 0, 'message' => 'OK'], $captured);

        $gateway->capture(['orderId' => 'MO0000004243242424', 'amount' => 100000]);

        $this->assertEquals(MomoGateway::API_URL_TEST . MomoGateway::PATH_CONFIRM, $captured['url']);
    }

    // ------------------------------------------------------------------
    // getSettingsFields()
    // ------------------------------------------------------------------

    public function test_getSettingsFields_contains_all_expected_keys()
    {
        $fields = $this->newGateway()->getSettingsFields();

        foreach ([
            'testMode', 'lang',
            'sandbox_partner_code', 'sandbox_access_key', 'sandbox_secret_key',
            'production_partner_code', 'production_access_key', 'production_secret_key',
        ] as $key) {
            $this->assertArrayHasKey($key, $fields);
        }
    }

    public function test_getSettingsFields_field_types()
    {
        $fields = $this->newGateway()->getSettingsFields();

        $this->assertEquals('checkbox', $fields['testMode']['type']);
        $this->assertEquals('select', $fields['lang']['type']);
        $this->assertEquals('text', $fields['sandbox_partner_code']['type']);
        $this->assertEquals('password', $fields['sandbox_secret_key']['type']);
        $this->assertEquals('password', $fields['production_secret_key']['type']);
    }

    public function test_getSettingsFields_defaults()
    {
        $fields = $this->newGateway()->getSettingsFields();

        $this->assertEquals('1', $fields['testMode']['default']);
        $this->assertEquals('vi', $fields['lang']['default']);
        $this->assertArrayNotHasKey('default', $fields['production_partner_code']);
        $this->assertArrayNotHasKey('default', $fields['production_secret_key']);
    }

    // ------------------------------------------------------------------
    // Helpers (orderInfo sanitization)
    // ------------------------------------------------------------------

    public function test_order_info_is_sanitized_and_truncated()
    {
        $gateway = $this->newGateway();

        $info = $gateway->exposeNormalizeOrderInfo(str_repeat('A', 300), 'MO123');
        $this->assertLessThanOrEqual(255, strlen($info));

        $this->assertSame('Order MO123', $gateway->exposeNormalizeOrderInfo('', 'MO123'));
        $this->assertSame('Order MO123', $gateway->exposeNormalizeOrderInfo('  ', 'MO123'));

        $stripped = $gateway->exposeToAscii('Pay & <b>#1</b>');
        $this->assertStringNotContainsString('&', $stripped);
        $this->assertStringNotContainsString('<', $stripped);
        $this->assertStringNotContainsString('>', $stripped);
    }

    public function test_order_info_strips_vietnamese_accents()
    {
        $gateway = $this->newGateway();

        $info = $gateway->exposeToAscii('Thanh toán đơn hàng #42');
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9 _.-]+$/', $info);
        $this->assertStringContainsString('Thanh toan', $info);
        $this->assertStringContainsString('42', $info);
    }

    public function test_phone_is_normalized_to_digits()
    {
        $gateway = $this->newGateway();

        $this->assertSame('84912345678', $gateway->exposeNormalizePhone('+84 912 345 678'));
        $this->assertSame('', $gateway->exposeNormalizePhone('abc'));
    }
}