<?php
namespace Simplephp\Apple;
/**
 * Authorize class
 * 可用的验证参数有 userID、authorizationCode、identityToken，需要iOS客户端传过来
 * Apple 下载的 .p8 密钥 转化为 .pem 密钥
 * openssl pkcs8 -in AuthKey_KEY_ID.p8 -nocrypt -out AuthKey_KEY_ID.pem
 * 验证方式：
 *      1. 验证 identityToken
 *      2. 验证 authorizationCode
 */
class Authorize {

    /**
     * Undocumented variable
     *
     * @var [type]
     */
    private $clientID;


    /**
     * Undocumented variable
     *
     * @var [type]
     */
    private $teamID;

    /**
     * Undocumented variable
     *
     * @var [type]
     */
    private $keyID;

    /**
     * Undocumented variable
     *
     * @var string
     */
    private $grantType = 'authorization_code';

    /**
     *   -----BEGIN PRIVATE KEY-----
     *   xxxxxxxxxxxxxxxxx
     *   xxxxxxxxxxxxxxxxxxxxx
     *   xxxxxxxx
     *  -----END PRIVATE KEY-----
     **/
    private $privateKey;


    /**
     * Undocumented variable
     *
     * @var string
     */
    private $err;

    /**
     * Undocumented function
     *
     * @param [type] $clientID
     * @param [type] $teamID
     * @param [type] $keyID
     */
    public function __construct($clientID, $teamID, $keyID, $privateKey)
    {
        if(empty($clientID)) {
            throw new \InvalidArgumentException('clientID may not be empty');
        }
        $this->clientID = $clientID;
        if(empty($teamID)) {
            throw new \InvalidArgumentException('teamID may not be empty');
        }
        $this->teamID = $teamID;
        if(empty($keyID)) {
            throw new \InvalidArgumentException('keyID may not be empty');
        }
        $this->keyID = $keyID;
        if(empty($privateKey)) {
            throw new \InvalidArgumentException('privateKey may not be empty');
        }
        $this->privateKey = $privateKey;
    }

    /**
     * 远程验证
     * @param string $authCode
     * @return void
     */
    public function remoteAuthCode(string $authCode) {

        try {
            $params = [
                'client_id' => $this->clientID,
                'client_secret' => $this->generateClientSecret(),
                'code' => $authCode,
                'grant_type' => $this->grantType
            ];
            $header = [
                'Content-Type: application/x-www-form-urlencoded'
            ];
            $verifyRes = AppleJWt::httpRequest('https://appleid.apple.com/auth/token', $params, $header);
            if(isset($verifyRes['error'])) {
                $this->err = $verifyRes['error_description'] ?? $verifyRes['error'];
                return false;
            } else {
                if (isset($verifyRes['id_token'])) {
                    $verifyRes['id_token'] = (array) AppleJWt::decodeAppleJWT($verifyRes['id_token']);
                    return $verifyRes;
                } else {
                    $this->err = 'The field "id_token" not found.';
                    return false;
                }
            }   
        } catch(\Exception $e) {
            $this->err = $e->getMessage();
            return false;
        }
    }

    /**
     * 移除授权
     * @param string $token  refresh_token 或 access_token 类型和值一一对应(remoteAuthCode)
     * @return void
     */
    public function revokeToken(string $tokenx, $type = 'refresh_token') {
        try {
            $params = [
                'client_id' => $this->clientID,
                'client_secret' => $this->generateClientSecret(),
                'token' => $tokenx,
                'token_type_hint' => $type,
            ];
            $header = [
                'Content-Type: application/x-www-form-urlencoded'
            ];
            $verifyRes = AppleJWt::httpRequest('https://appleid.apple.com/auth/revoke', $params, $header);
            return $verifyRes;
        } catch(\Exception $e) {
            $this->err = $e->getMessage();
            return false;
        }
    }

    /**
     * 刷新 access_token
     *
     * @param [type] $clientID
     * @param [type] $refreshToken
     * @return void
     */
    public function refreshAccessToken($refreshToken) {

        try {
            $params = [
                'grant_type' => 'refresh_token',
                'client_id'  => $this->clientID,
                'client_secret' => $this->generateClientSecret(),
                'refresh_token' => $refreshToken,
            ];
            $res = AppleJWt::httpRequest('https://appleid.apple.com/auth/token', $params);
            if(isset($res['error'])) {
                $this->err = $res['error_description'] ?? $res['error'];
                return false;
            } else {
                if (isset($res['id_token'])) {
                    $res['id_token'] = (array) AppleJWt::decodeAppleJWT($res['id_token']);
                    return $res;
                } else {
                    $this->err = 'The field "id_token" not found.';
                    return false;
                }
            }   
        } catch(\Exception $e) {
            $this->err = $e->getMessage();
            return false;
        }
    }

    /**
     * Undocumented function
     *
     * @return void
     */
    public function generateClientSecret() {

       $payload = [
            "iss" => $this->teamID,
            'iat' => time(),
            'exp' => time() + 3600,
            "aud" => "https://appleid.apple.com", // 常数
            "sub" => $this->clientID,
        ];

        $JWTHeader = [
            'alg' => 'ES256',
            'kid' => $this->keyID,
        ];
        return AppleJWT::encodeAppleJWT($payload, $this->privateKey, $JWTHeader);
    }

    /**
     * 本地验证(本身并不做校验)
     * @param string $identityToken
     * @return void
     */
    public function localAuthCode(string $identityToken) {
        try {
        	return (array) AppleJWT::decodeAppleJWT($identityToken);
         } catch(\Exception $e) {
            $this->err = $e->getMessage();
            return false;
        }
    }

    /**
     * Undocumented function
     *
     * @return void
     */
    public function getErrMessage() {
        return $this->err;
    }
}