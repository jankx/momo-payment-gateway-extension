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
        return '<svg width="64" height="60" viewBox="0 0 64 60" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M50.2913 27.6316C57.9682 27.6316 64 21.5526 64 13.8158C64 6.07895 57.9682 0 50.2913 0C42.6144 0 36.5826 6.07895 36.5826 13.8158C36.5826 21.5526 42.6144 27.6316 50.2913 27.6316ZM50.2913 7.57895C53.7381 7.57895 56.1665 10.3421 56.1665 13.8158C56.1665 17.2895 53.7381 20.0526 50.2913 20.0526C46.8445 20.0526 44.4161 17.2895 44.4161 13.8158C44.4161 10.3421 46.8445 7.57895 50.2913 7.57895Z" fill="#A50064"/><path d="M22.1689 0C19.9528 0 17.696 0.831314 15.9953 2.07079C14.4192 0.831314 12.3433 0 10.1836 0C4.46512 0 0 3.63158 0 10.6579V27.2368H7.83354V9.94737C7.83354 8.60526 8.77356 7.6579 10.0269 7.6579C11.2803 7.6579 12.2203 8.60526 12.2203 9.94737V27.2368H20.0539V9.94737C20.0539 8.60526 20.9939 7.6579 22.2472 7.6579C23.5006 7.6579 24.4406 8.60526 24.4406 9.94737V27.2368H32.2742V10.6579C32.2742 3.63158 27.7307 0 22.1689 0Z" fill="#A50064"/><path d="M50.2913 32.3684C42.6144 32.3684 36.5826 38.4474 36.5826 46.1842C36.5826 53.921 42.6144 60 50.2913 60C57.9682 60 64 53.921 64 46.1842C64 38.4474 57.9682 32.3684 50.2913 32.3684ZM50.2913 52.421C46.8445 52.421 44.4161 49.6579 44.4161 46.1842C44.4161 42.7105 46.8445 39.9474 50.2913 39.9474C53.7381 39.9474 56.1665 42.7105 56.1665 46.1842C56.1665 49.6579 53.7381 52.421 50.2913 52.421Z" fill="#A50064"/><path d="M22.1689 32.3684C19.9528 32.3684 17.696 33.1997 15.9953 34.4392C14.4192 33.1997 12.3433 32.3684 10.1836 32.3684C4.46512 32.3684 0 36 0 43.0263V59.6053H7.83354V42.3158C7.83354 40.9737 8.77356 40.0263 10.0269 40.0263C11.2803 40.0263 12.2203 40.9737 12.2203 42.3158V59.6053H20.0539V42.3158C20.0539 40.9737 20.9939 40.0263 22.2472 40.0263C23.5006 40.0263 24.4406 40.9737 24.4406 42.3158V59.6053H32.2742V43.0263C32.2742 36 27.7307 32.3684 22.1689 32.3684Z" fill="#A50064"/></svg>';
    }

    protected function getDefaultText(): string
    {
        return $this->displayName;
    }
}