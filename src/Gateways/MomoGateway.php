<?php
namespace Jankx\Extensions\Momo\Gateways;

use Jankx\Extensions\PaymentSystem\Gateways\AbstractGateway;
use Jankx\Extensions\PaymentSystem\Models\Transaction;

/**
 * MoMo (e-wallet) gateway.
 *
 * Implements the MoMo M4B API ({@see https://developers.momo.vn}) hosted-
 * redirect flow:
 *
 *  - Payment request : POST /v2/gateway/api/create (requestType=captureWallet)
 *  - Return flow     : verify `signature` (HMAC-SHA256) + `resultCode`
 *  - Status query    : POST /v2/gateway/api/query
 *  - Refund          : POST /v2/gateway/api/refund
 *  - Capture/Cancel  : POST /v2/gateway/api/confirm (2-step flow)
 *
 * Request signatures use the exact ordered raw string defined per endpoint
 * (`accessKey&amount&...&requestType`). Callback (return URL) signatures are
 * verified over all received params sorted a-z (values URL-encoded when they
 * contain non-ASCII characters).
 *
 * @package Jankx\Extensions\Momo
 */
class MomoGateway extends AbstractGateway
{
    const API_URL_TEST = 'https://test-payment.momo.vn';
    const API_URL_PROD = 'https://payment.momo.vn';

    const PATH_CREATE = '/v2/gateway/api/create';
    const PATH_QUERY = '/v2/gateway/api/query';
    const PATH_REFUND = '/v2/gateway/api/refund';
    const PATH_CONFIRM = '/v2/gateway/api/confirm';

    const REQUEST_TYPE_CAPTURE_WALLET = 'captureWallet';
    const REQUEST_TYPE_CAPTURE = 'capture';
    const REQUEST_TYPE_CANCEL = 'cancel';

    const MIN_AMOUNT = 1000;
    const MAX_AMOUNT = 50000000;

    /**
     * Gateway slug registered in the GatewayManager (used in filter tags).
     *
     * @var string
     */
    protected $slug = 'momo';

    /**
     * Human readable name shown in checkout / admin.
     *
     * @var string
     */
    protected $displayName = 'MoMo';

    /**
     * Resolved gateway configuration.
     *
     * @var array
     */
    protected $config = [];

    /**
     * Resolved live credentials after initialize().
     *
     * @var array
     */
    protected $credentials = [
        'partner_code' => '',
        'access_key'   => '',
        'secret_key'   => '',
    ];

    public function getName(): string
    {
        return $this->displayName;
    }

    public function initialize(array $parameters): void
    {
        $this->config = wp_parse_args($parameters, [
            'testMode'               => false,
            'lang'                   => 'vi',
            'sandbox_partner_code'   => '',
            'sandbox_access_key'     => '',
            'sandbox_secret_key'     => '',
            'production_partner_code' => '',
            'production_access_key'   => '',
            'production_secret_key'   => '',
        ]);

        $isTest = !empty($this->config['testMode']);
        $prefix = $isTest ? 'sandbox' : 'production';

        $this->credentials = [
            'partner_code' => (string) ($this->config["{$prefix}_partner_code"] ?? ''),
            'access_key'   => (string) ($this->config["{$prefix}_access_key"] ?? ''),
            'secret_key'   => (string) ($this->config["{$prefix}_secret_key"] ?? ''),
        ];
    }

    /**
     * Whether the gateway can be used (needs a partner code, access key and
     * secret key for the active environment).
     */
    public function isAvailable(): bool
    {
        return $this->credentials['partner_code'] !== ''
            && $this->credentials['access_key'] !== ''
            && $this->credentials['secret_key'] !== '';
    }

    /**
     * Create a MoMo `captureWallet` payment and return a redirect payload.
     *
     * @return array{status: string, redirectUrl: string, redirectMethod: string, redirectData: array, transactionId: string}
     */
    public function purchase(array $parameters): array
    {
        $transactionId = (string) ($parameters['transactionId'] ?? '');
        $orderId = $this->buildOrderId($transactionId);
        $requestId = $this->buildRequestId();
        $amount = (int) round((float) ($parameters['amount'] ?? 0));

        if ($amount < self::MIN_AMOUNT || $amount > self::MAX_AMOUNT) {
            return [
                'status'  => 'failed',
                'message' => __('MoMo amount must be between 1,000 and 50,000,000 VND.', 'jankx'),
                'code'    => 'AMOUNT_INVALID',
            ];
        }

        $redirectUrl = (string) ($parameters['returnUrl'] ?? '');
        $orderInfo = $this->normalizeOrderInfo($parameters['description'] ?? '', $orderId);

        $extraData = '';
        if (!empty($parameters['extraData']) && is_array($parameters['extraData'])) {
            $extraData = base64_encode(json_encode($parameters['extraData']));
        }

        $body = [
            'partnerCode'  => $this->credentials['partner_code'],
            'requestId'    => $requestId,
            'amount'       => $amount,
            'orderId'      => $orderId,
            'orderInfo'    => $orderInfo,
            'redirectUrl'  => $redirectUrl,
            'ipnUrl'       => (string) ($parameters['ipnUrl'] ?? ''),
            'extraData'    => $extraData,
            'requestType'  => self::REQUEST_TYPE_CAPTURE_WALLET,
            'lang'         => $this->getLang(),
        ];

        if (array_key_exists('autoCapture', $parameters)) {
            $body['autoCapture'] = (bool) $parameters['autoCapture'];
        }

        foreach (['subPartnerCode', 'storeName', 'storeId'] as $key) {
            if (!empty($parameters[$key])) {
                $body[$key] = (string) $parameters[$key];
            }
        }

        $userInfo = array_filter([
            'name'        => (string) ($parameters['customer_name'] ?? ''),
            'phoneNumber' => $this->normalizePhone((string) ($parameters['customer_phone'] ?? '')),
            'email'       => (string) ($parameters['customer_email'] ?? ''),
        ]);
        if (!empty($userInfo)) {
            $body['userInfo'] = $userInfo;
        }

        if (!empty($parameters['items']) && is_array($parameters['items'])) {
            $body['items'] = array_slice($parameters['items'], 0, 50);
        }

        $body['signature'] = $this->sign($this->rawCreateSignature(
            $amount,
            $extraData,
            (string) $body['ipnUrl'],
            $orderId,
            $orderInfo,
            $redirectUrl,
            $requestId
        ));

        $response = $this->apiRequest(self::PATH_CREATE, $body);

        $this->persistOrderRef($transactionId, $orderId);

        $resultCode = (int) ($response['resultCode'] ?? -1);
        if ($resultCode !== 0) {
            return [
                'status'  => 'failed',
                'message' => (string) ($response['message'] ?? __('MoMo payment could not be created.', 'jankx')),
                'code'    => (string) ($response['resultCode'] ?? ''),
                'raw'     => $response,
            ];
        }

        return [
            'status'         => 'redirect',
            'redirectUrl'    => (string) ($response['payUrl'] ?? ''),
            'redirectMethod' => 'GET',
            'redirectData'   => $response,
            'transactionId'  => $orderId,
        ];
    }

    /**
     * Verify the MoMo return URL response and map it to a status.
     *
     * @return array{status: string, transactionId: string, message: string, code?: string, raw?: array}
     */
    public function completePurchase(array $parameters): array
    {
        $params = is_array($parameters['request_params'] ?? null) ? $parameters['request_params'] : $parameters;

        if (!$this->verifySignature($params)) {
            return [
                'status'        => 'failed',
                'transactionId' => (string) ($params['transId'] ?? ''),
                'message'       => __('Invalid signature from MoMo.', 'jankx'),
                'code'          => 'HASH_MISMATCH',
                'raw'           => $params,
            ];
        }

        if ((string) ($params['partnerCode'] ?? '') !== $this->credentials['partner_code']) {
            return [
                'status'        => 'failed',
                'transactionId' => (string) ($params['transId'] ?? ''),
                'message'       => __('Partner code does not match.', 'jankx'),
                'code'          => 'PARTNER_MISMATCH',
                'raw'           => $params,
            ];
        }

        $resultCode = (int) ($params['resultCode'] ?? -1);
        $transactionId = (string) ($params['transId'] ?? '');

        if ($resultCode === 0) {
            return [
                'status'        => 'success',
                'transactionId' => $transactionId,
                'message'       => __('Payment successful.', 'jankx'),
                'code'          => '0',
                'raw'           => $params,
            ];
        }

        if ($resultCode === 9000) {
            return [
                'status'        => 'pending',
                'transactionId' => $transactionId,
                'message'       => __('Payment authorized, awaiting capture.', 'jankx'),
                'code'          => '9000',
                'raw'           => $params,
            ];
        }

        return [
            'status'        => 'failed',
            'transactionId' => $transactionId,
            'message'       => (string) ($params['message'] ?? $this->getResultCodeMessage($resultCode)),
            'code'          => (string) $resultCode,
            'raw'           => $params,
        ];
    }

    /**
     * Refund a paid transaction.
     *
     * @param array $parameters Required: `transId` (or `transactionId`, the
     *                          MoMo transaction id), `amount`, `description`.
     * @return array{status: string, message: string, code?: string, raw?: array}
     */
    public function refund(array $parameters): array
    {
        $transId = (string) ($parameters['transId'] ?? ($parameters['transactionId'] ?? ''));
        if ($transId === '') {
            return [
                'status'  => 'failed',
                'message' => __('MoMo transId is required to refund.', 'jankx'),
                'code'    => 'MISSING_TRANS_ID',
            ];
        }

        $orderId = $this->buildOrderId('RF' . $transId);
        $requestId = $this->buildRequestId();
        $amount = (int) round((float) ($parameters['amount'] ?? 0));
        $description = $this->normalizeOrderInfo($parameters['description'] ?? '', $orderId);

        $body = [
            'partnerCode' => $this->credentials['partner_code'],
            'orderId'     => $orderId,
            'requestId'   => $requestId,
            'amount'      => $amount,
            'transId'     => $transId,
            'lang'        => $this->getLang(),
            'description' => $description,
            'signature'   => $this->sign($this->rawRefundSignature($amount, $description, $orderId, $requestId, $transId)),
        ];

        $response = $this->apiRequest(self::PATH_REFUND, $body);

        $resultCode = (int) ($response['resultCode'] ?? -1);
        if ($resultCode === 0) {
            return [
                'status'  => 'success',
                'message' => (string) ($response['message'] ?? __('Refund successful.', 'jankx')),
                'code'    => '0',
                'raw'     => $response,
            ];
        }

        return [
            'status'  => 'failed',
            'message' => (string) ($response['message'] ?? $this->getResultCodeMessage($resultCode)),
            'code'    => (string) ($response['resultCode'] ?? ''),
            'raw'     => $response,
        ];
    }

    /**
     * Capture an authorized (resultCode 9000) transaction.
     */
    public function capture(array $parameters): array
    {
        return $this->confirm($parameters, self::REQUEST_TYPE_CAPTURE);
    }

    /**
     * Cancel an authorized (resultCode 9000) transaction.
     */
    public function cancel(array $parameters): array
    {
        return $this->confirm($parameters, self::REQUEST_TYPE_CANCEL);
    }

    /**
     * MoMo confirm API (capture / cancel of an authorized transaction).
     *
     * @return array{status: string, message: string, code?: string, raw?: array}
     */
    public function confirm(array $parameters, string $requestType): array
    {
        if (!in_array($requestType, [self::REQUEST_TYPE_CAPTURE, self::REQUEST_TYPE_CANCEL], true)) {
            $requestType = self::REQUEST_TYPE_CANCEL;
        }

        $orderId = (string) ($parameters['orderId'] ?? ($parameters['transactionId'] ?? ''));
        $requestId = $this->buildRequestId();
        $amount = (int) round((float) ($parameters['amount'] ?? 0));
        $description = (string) ($parameters['description'] ?? '');

        $body = [
            'partnerCode' => $this->credentials['partner_code'],
            'requestId'   => $requestId,
            'orderId'     => $orderId,
            'requestType' => $requestType,
            'amount'      => $amount,
            'lang'        => $this->getLang(),
            'description' => $description,
            'signature'   => $this->sign($this->rawConfirmSignature($amount, $description, $orderId, $requestId, $requestType)),
        ];

        $response = $this->apiRequest(self::PATH_CONFIRM, $body);

        $resultCode = (int) ($response['resultCode'] ?? -1);
        if ($resultCode === 0) {
            return [
                'status'  => 'success',
                'message' => (string) ($response['message'] ?? __('Confirm successful.', 'jankx')),
                'code'    => '0',
                'raw'     => $response,
            ];
        }

        return [
            'status'  => 'failed',
            'message' => (string) ($response['message'] ?? $this->getResultCodeMessage($resultCode)),
            'code'    => (string) ($response['resultCode'] ?? ''),
            'raw'     => $response,
        ];
    }

    /**
     * MoMo gateway query API: reconcile the payment status.
     *
     * @return string 'completed' | 'pending' | 'failed'
     */
    public function queryStatus(string $transactionId): string
    {
        $requestId = $this->buildRequestId();

        $body = [
            'partnerCode' => $this->credentials['partner_code'],
            'requestId'   => $requestId,
            'orderId'     => $transactionId,
            'lang'        => $this->getLang(),
            'signature'   => $this->sign($this->rawQuerySignature($transactionId, $requestId)),
        ];

        $response = $this->apiRequest(self::PATH_QUERY, $body);

        if (isset($response['signature']) && !$this->verifySignature($response)) {
            return 'failed';
        }

        $resultCode = (int) ($response['resultCode'] ?? -1);

        if ($resultCode === 0) {
            return 'completed';
        }
        if (in_array($resultCode, [9000, 7000, 7002], true)) {
            return 'pending';
        }

        return 'failed';
    }

    /**
     * Admin settings fields (keys map to the saved option array).
     */
    public function getSettingsFields(): array
    {
        return [
            'testMode' => [
                'label'       => __('Test mode (MoMo sandbox)', 'jankx'),
                'type'        => 'checkbox',
                'description' => __('Enable to use the MoMo test environment (test-payment.momo.vn).', 'jankx'),
                'default'     => '1',
            ],
            'lang' => [
                'label'   => __('Message language (lang)', 'jankx'),
                'type'    => 'select',
                'options' => ['vi' => 'Tiếng Việt', 'en' => 'English'],
                'default' => 'vi',
            ],
            'sandbox_partner_code' => [
                'label'   => __('Partner Code (test)', 'jankx'),
                'type'    => 'text',
                'default' => '',
            ],
            'sandbox_access_key' => [
                'label'   => __('Access Key (test)', 'jankx'),
                'type'    => 'text',
                'default' => '',
            ],
            'sandbox_secret_key' => [
                'label'   => __('Secret Key (test)', 'jankx'),
                'type'    => 'password',
                'default' => '',
            ],
            'production_partner_code' => [
                'label' => __('Partner Code (production)', 'jankx'),
                'type'  => 'text',
            ],
            'production_access_key' => [
                'label' => __('Access Key (production)', 'jankx'),
                'type'  => 'text',
            ],
            'production_secret_key' => [
                'label' => __('Secret Key (production)', 'jankx'),
                'type'  => 'password',
            ],
        ];
    }

    /**
     * Sign a raw parameter string with the MoMo secret key.
     */
    protected function sign(string $raw): string
    {
        return hash_hmac('sha256', $raw, $this->credentials['secret_key']);
    }

    /**
     * Verify an incoming MoMo callback signature (return URL, query response).
     *
     * All received params (except `signature`) are sorted a-z and joined as
     * `key=value&key=value`; values containing non-ASCII characters are
     * URL-encoded before hashing.
     */
    public function verifySignature(array $params): bool
    {
        $signature = (string) ($params['signature'] ?? '');
        if ($signature === '' || $this->credentials['secret_key'] === '') {
            return false;
        }

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

        return hash_equals($signature, $this->sign(implode('&', $pairs)));
    }

    /**
     * POST a JSON body to a MoMo gateway endpoint.
     */
    protected function apiRequest(string $path, array $body): array
    {
        $response = wp_remote_post($this->getApiUrl($path), [
            'headers' => ['Content-Type' => 'application/json; charset=UTF-8'],
            'body'    => json_encode($body),
            'timeout' => 30,
        ]);

        if (is_wp_error($response)) {
            return [
                'success' => false,
                'message' => $response->get_error_message(),
            ];
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);
        if (!is_array($data)) {
            return [
                'success' => false,
                'message' => __('Invalid response from MoMo.', 'jankx'),
            ];
        }

        return $data;
    }

    protected function getApiUrl(string $path): string
    {
        return ($this->isTestMode() ? self::API_URL_TEST : self::API_URL_PROD) . $path;
    }

    protected function isTestMode(): bool
    {
        return !empty($this->config['testMode']);
    }

    protected function getLang(): string
    {
        return (string) ($this->config['lang'] ?? 'vi') === 'en' ? 'en' : 'vi';
    }

    /**
     * Raw create signature string (fixed order from the MoMo spec).
     */
    protected function rawCreateSignature(int $amount, string $extraData, string $ipnUrl, string $orderId, string $orderInfo, string $redirectUrl, string $requestId): string
    {
        return 'accessKey=' . $this->credentials['access_key']
            . '&amount=' . $amount
            . '&extraData=' . $extraData
            . '&ipnUrl=' . $ipnUrl
            . '&orderId=' . $orderId
            . '&orderInfo=' . $orderInfo
            . '&partnerCode=' . $this->credentials['partner_code']
            . '&redirectUrl=' . $redirectUrl
            . '&requestId=' . $requestId
            . '&requestType=' . self::REQUEST_TYPE_CAPTURE_WALLET;
    }

    /**
     * Raw query signature string (fixed order from the MoMo spec).
     */
    protected function rawQuerySignature(string $orderId, string $requestId): string
    {
        return 'accessKey=' . $this->credentials['access_key']
            . '&orderId=' . $orderId
            . '&partnerCode=' . $this->credentials['partner_code']
            . '&requestId=' . $requestId;
    }

    /**
     * Raw refund signature string (fixed order from the MoMo spec).
     */
    protected function rawRefundSignature(int $amount, string $description, string $orderId, string $requestId, string $transId): string
    {
        return 'accessKey=' . $this->credentials['access_key']
            . '&amount=' . $amount
            . '&description=' . $description
            . '&orderId=' . $orderId
            . '&partnerCode=' . $this->credentials['partner_code']
            . '&requestId=' . $requestId
            . '&transId=' . $transId;
    }

    /**
     * Raw confirm signature string (fixed order from the MoMo spec).
     */
    protected function rawConfirmSignature(int $amount, string $description, string $orderId, string $requestId, string $requestType): string
    {
        return 'accessKey=' . $this->credentials['access_key']
            . '&amount=' . $amount
            . '&description=' . $description
            . '&orderId=' . $orderId
            . '&partnerCode=' . $this->credentials['partner_code']
            . '&requestId=' . $requestId
            . '&requestType=' . $requestType;
    }

    /**
     * Build a unique, non-obvious MoMo orderId (max 40 chars, alphanumeric).
     */
    protected function buildOrderId(string $transactionId): string
    {
        $ref = 'MO' . str_pad((string) $transactionId, 8, '0', STR_PAD_LEFT) . substr(md5(uniqid('', true)), 0, 12);
        return substr($ref, 0, 40);
    }

    /**
     * Build a unique requestId used for idempotency.
     */
    protected function buildRequestId(): string
    {
        return 'RQ' . substr(md5(uniqid('', true)), 0, 16);
    }

    protected function normalizeOrderInfo(string $description, string $orderId): string
    {
        $info = trim($this->toAscii($description));
        if ($info === '') {
            $info = 'Order ' . $orderId;
        }
        return substr($info, 0, 255);
    }

    protected function normalizePhone(string $phone): string
    {
        return substr(preg_replace('/[^0-9]/', '', $phone), 0, 16);
    }

    protected function toAscii(string $value): string
    {
        if (function_exists('normalizer_normalize')) {
            $value = normalizer_normalize($value, \Normalizer::FORM_D);
            $value = preg_replace('/\p{Mn}/u', '', (string) $value);
            $value = str_replace(['Đ', 'đ'], ['D', 'd'], (string) $value);
        } else {
            $value = strtr($value, $this->getVietnameseTransliterationMap());
        }
        return preg_replace('/[^A-Za-z0-9 _.-]/', '', $value) ?? '';
    }

    protected function getVietnameseTransliterationMap(): array
    {
        return [
            'á' => 'a', 'à' => 'a', 'ả' => 'a', 'ã' => 'a', 'ạ' => 'a',
            'â' => 'a', 'ấ' => 'a', 'ầ' => 'a', 'ẩ' => 'a', 'ẫ' => 'a', 'ậ' => 'a',
            'ă' => 'a', 'ắ' => 'a', 'ằ' => 'a', 'ẳ' => 'a', 'ẵ' => 'a', 'ặ' => 'a',
            'đ' => 'd',
            'é' => 'e', 'è' => 'e', 'ẻ' => 'e', 'ẽ' => 'e', 'ẹ' => 'e',
            'ê' => 'e', 'ế' => 'e', 'ề' => 'e', 'ể' => 'e', 'ễ' => 'e', 'ệ' => 'e',
            'í' => 'i', 'ì' => 'i', 'ỉ' => 'i', 'ĩ' => 'i', 'ị' => 'i',
            'ó' => 'o', 'ò' => 'o', 'ỏ' => 'o', 'õ' => 'o', 'ọ' => 'o',
            'ô' => 'o', 'ố' => 'o', 'ồ' => 'o', 'ổ' => 'o', 'ỗ' => 'o', 'ộ' => 'o',
            'ơ' => 'o', 'ớ' => 'o', 'ờ' => 'o', 'ở' => 'o', 'ỡ' => 'o', 'ợ' => 'o',
            'ú' => 'u', 'ù' => 'u', 'ủ' => 'u', 'ũ' => 'u', 'ụ' => 'u',
            'ư' => 'u', 'ứ' => 'u', 'ừ' => 'u', 'ử' => 'u', 'ữ' => 'u', 'ự' => 'u',
            'ý' => 'y', 'ỳ' => 'y', 'ỷ' => 'y', 'ỹ' => 'y', 'ỵ' => 'y',
            'Á' => 'A', 'À' => 'A', 'Ả' => 'A', 'Ã' => 'A', 'Ạ' => 'A',
            'Â' => 'A', 'Ấ' => 'A', 'Ầ' => 'A', 'Ẩ' => 'A', 'Ẫ' => 'A', 'Ậ' => 'A',
            'Ă' => 'A', 'Ắ' => 'A', 'Ằ' => 'A', 'Ẳ' => 'A', 'Ẵ' => 'A', 'Ặ' => 'A',
            'Đ' => 'D',
            'É' => 'E', 'È' => 'E', 'Ẻ' => 'E', 'Ẽ' => 'E', 'Ẹ' => 'E',
            'Ê' => 'E', 'Ế' => 'E', 'Ề' => 'E', 'Ể' => 'E', 'Ễ' => 'E', 'Ệ' => 'E',
            'Í' => 'I', 'Ì' => 'I', 'Ỉ' => 'I', 'Ĩ' => 'I', 'Ị' => 'I',
            'Ó' => 'O', 'Ò' => 'O', 'Ỏ' => 'O', 'Õ' => 'O', 'Ọ' => 'O',
            'Ô' => 'O', 'Ố' => 'O', 'Ồ' => 'O', 'Ổ' => 'O', 'Ỗ' => 'O', 'Ộ' => 'O',
            'Ơ' => 'O', 'Ớ' => 'O', 'Ờ' => 'O', 'Ở' => 'O', 'Ỡ' => 'O', 'Ợ' => 'O',
            'Ú' => 'U', 'Ù' => 'U', 'Ủ' => 'U', 'Ũ' => 'U', 'Ụ' => 'U',
            'Ư' => 'U', 'Ứ' => 'U', 'Ừ' => 'U', 'Ử' => 'U', 'Ữ' => 'U', 'Ự' => 'U',
            'Ý' => 'Y', 'Ỳ' => 'Y', 'Ỷ' => 'Y', 'Ỹ' => 'Y', 'Ỵ' => 'Y',
        ];
    }

    protected function persistOrderRef(string $transactionId, string $orderId): void
    {
        if (!is_numeric($transactionId) || (int) $transactionId <= 0) {
            return;
        }

        $transaction = new Transaction((int) $transactionId);
        if ($transaction->getId()) {
            $transaction->setTransactionId($orderId);
        }
    }

    protected function getResultCodeMessage(int $code): string
    {
        $messages = [
            0    => __('Success.', 'jankx'),
            9000 => __('Payment authorized.', 'jankx'),
            1001 => __('Payment failed.', 'jankx'),
            1002 => __('Payment failed.', 'jankx'),
            1004 => __('Payment failed.', 'jankx'),
            1006 => __('Payment quota exceeded, try again later.', 'jankx'),
            1017 => __('System is busy, try again later.', 'jankx'),
            11   => __('MoMo system is under maintenance, try again later.', 'jankx'),
            99   => __('MoMo system is unavailable, try again later.', 'jankx'),
        ];

        return $messages[$code] ?? __('Payment failed.', 'jankx');
    }

    protected function getDefaultIcon(): string
    {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16v12H4z"/><path d="M8 10h3"/><path d="M13 10h3"/><circle cx="12" cy="14.5" r="1.5"/></svg>';
    }

    protected function getDefaultText(): string
    {
        return $this->displayName;
    }
}