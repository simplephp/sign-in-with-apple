<?php

namespace Simplephp\Apple;
use \UnexpectedValueException;

/**
 * JSON Web Token implementation, based on this spec:
 * https://tools.ietf.org/html/rfc7519
 *
 * PHP version 5
 *
 * @category Authentication
 * @package  Authentication_JWT
 * @author   Neuman Vong <neuman@twilio.com>
 * @author   Anant Narayanan <anant@php.net>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/firebase/php-jwt
 */
class AppleJWT extends JWT
{
    /**
     * Undocumented function
     *
     * @param [type] $payload
     * @param [type] $key
     * @param [type] $header
     * @return void
     */
    public static function encodeAppleJWT($payload, $key, $header)
    {
        $privateKey = openssl_pkey_get_private($key);
        if (!$privateKey) {
            throw new UnexpectedValueException('获取私钥失败');
        }
        $payload = self::urlsafeB64Encode(static::jsonEncode($header)).'.'.self::urlsafeB64Encode(static::jsonEncode($payload));
        $signature = '';
        $success = openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        if (!$success) {
            throw new UnexpectedValueException('生成签名失败');
        }
        $rawSignature = self::fromDER($signature, 64);
        return $payload.'.'.self::urlsafeB64Encode($rawSignature);
    }

    /**
     * Undocumented function
     *
     * @param string $JWTData
     * @return void
     */
    public static function decodeAppleJWT(string $JWTData)
    {
        $publicKeyKid = self::getPublicKeyKid($JWTData);
        $publicKeyData = self::fetchPublicKey($publicKeyKid);
        $publicKey = $publicKeyData['publicKey'];
        $alg = $publicKeyData['alg'];
        $payload = self::decode($JWTData, $publicKey, [$alg]);
        return $payload;
    }

        /**
     * Fetch Apple's public key from the auth/keys REST API to use to decode
     * the Sign In JWT.
     *
     * @param $kid
     * @return array
     * @throws Exception
     */
    public static function fetchPublicKey(string $kid)
    {
        $decodedPublicKeys = self::httpRequest('https://appleid.apple.com/auth/keys');
        if(!isset($decodedPublicKeys['keys']) || count($decodedPublicKeys['keys']) < 1) {
            throw new \Exception('Invalid key format.');
        }
        $kids = array_column($decodedPublicKeys['keys'], 'kid');
        $parsedKeyData = $decodedPublicKeys['keys'][array_search($kid, $kids)];
        $parsedPublicKey = JWK::parseKey($parsedKeyData);
        $publicKeyDetails = openssl_pkey_get_details($parsedPublicKey);

        if(!isset($publicKeyDetails['key'])) {
            throw new \Exception('Invalid public key details.');
        }
        return [
            'publicKey' => $publicKeyDetails['key'],
            'alg' => $parsedKeyData['alg']
        ];
    }

    /**
     * @param string $jwt
     * @return mixed
     */
    public static function getPublicKeyKid(string $jwt)
    {
        $tks = explode('.', $jwt);
        if (count($tks) != 3) {
            throw new \UnexpectedValueException('Wrong number of segments');
        }
        list($headb64, $bodyb64, $cryptob64) = $tks;
        if (null === ($header = static::jsonDecode(static::urlsafeB64Decode($headb64)))) {
            throw new \UnexpectedValueException('Invalid header encoding');
        }
        return $header->kid;
    }
    
    /**
     * @param string $der
     * @param int    $partLength
     *
     * @return string
     */
    public static function fromDER(string $der, int $partLength)
    {
        $hex = unpack('H*', $der)[1];
        if ('30' !== mb_substr($hex, 0, 2, '8bit')) { // SEQUENCE
            throw new \RuntimeException();
        }
        if ('81' === mb_substr($hex, 2, 2, '8bit')) { // LENGTH > 128
            $hex = mb_substr($hex, 6, null, '8bit');
        } else {
            $hex = mb_substr($hex, 4, null, '8bit');
        }
        if ('02' !== mb_substr($hex, 0, 2, '8bit')) { // INTEGER
            throw new \RuntimeException();
        }
        $Rl = hexdec(mb_substr($hex, 2, 2, '8bit'));
        $R = self::retrievePositiveInteger(mb_substr($hex, 4, $Rl * 2, '8bit'));
        $R = str_pad($R, $partLength, '0', STR_PAD_LEFT);
        $hex = mb_substr($hex, 4 + $Rl * 2, null, '8bit');
        if ('02' !== mb_substr($hex, 0, 2, '8bit')) { // INTEGER
            throw new \RuntimeException();
        }
        $Sl = hexdec(mb_substr($hex, 2, 2, '8bit'));
        $S = self::retrievePositiveInteger(mb_substr($hex, 4, $Sl * 2, '8bit'));
        $S = str_pad($S, $partLength, '0', STR_PAD_LEFT);
        return pack('H*', $R.$S);
    }

    /**
     * @param string $data
     *
     * @return string
     */
    private static function retrievePositiveInteger(string $data)
    {
        while ('00' === mb_substr($data, 0, 2, '8bit') && mb_substr($data, 2, 2, '8bit') > '7f') {
            $data = mb_substr($data, 2, null, '8bit');
        }
        return $data;
    }

    /**
     * http 请求
     * @param $url
     * @param array $data
     * @param int $second
     * @return bool|mixed
     */
    public static function httpRequest($url, $data = [], $header = [], $second = 30)
    {
        $curlHandle = curl_init();
        curl_setopt($curlHandle, CURLOPT_TIMEOUT, $second);
        curl_setopt($curlHandle, CURLOPT_URL, $url);
        curl_setopt($curlHandle, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curlHandle, CURLOPT_HEADER, 0);
        if (!empty($header)) {
            curl_setopt($curlHandle, CURLOPT_HTTPHEADER, $header);
        }
        if (!empty($data)) {
            curl_setopt($curlHandle, CURLOPT_POST, 1);
            curl_setopt($curlHandle, CURLOPT_POSTFIELDS, http_build_query($data));
        }
        curl_setopt($curlHandle, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($curlHandle, CURLOPT_SSL_VERIFYPEER, 0);
        $response = curl_exec($curlHandle);
        if (false !== $response) {
            curl_close($curlHandle);
            $data = json_decode($response, true);
            if(json_last_error() == JSON_ERROR_NONE) {
                return $data;
            }
            return [];
        } else {
            curl_close($curlHandle);
            return false;
        }
    }
}