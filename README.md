### 食用

```php
<?php
// 通过 authorizationCode 远程校验，另外通过identityToken 可以使用 localAuthCode 方法来本地验证（本地验证无法拿到 access_token/refresh_token等信息）

$authorizationCode = 'xxxx';
$clientID = 'com.xxxx.xxx';// app bundle id
$teamID  = 'xxxxxxxxxxx';       // 苹果开发中心(https://developer.apple.com/) => Membership => team ID
$keyID  = 'xxxxxxxxxxxx';        //  苹果开发中心(https://developer.apple.com/) => 在“Certificates, Identifiers & Profiles (英文)”(证书、标识符和描述文件) 中，从侧边栏中选择“Identifiers”(标识符), 在证书配置管理中心，配置Sign In with Apple功能 => 创建则会得到一个私钥，该文件为”AuthKey_{Kid}.p8”，注意保存，其中页面中还有 Key ID

// AuthKey_{Kid}.p8 密钥 转化为 .pem 格式密钥， openssl pkcs8 -in AuthKey_KEY_ID.p8 -nocrypt -out AuthKey_KEY_ID.pem
$privateKey = <<<EOD
-----BEGIN PRIVATE KEY-----
xxxxx+9hwuxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
gHr0Wf+7X8Zr2i8XjxxLFY4U/9j/x/xx+cQl7OA/oQaV
AUaUQ8mo
-----END PRIVATE KEY-----
EOD;
$authorize = new \Simplephp\Apple\Authorize($clientID, $teamID, $keyID, $privateKey);
$data = $authorize->remoteAuthCode($authorizationCode);
```

```php
###结果

array(5) {
  ["access_token"]=>
  string(64) "xxx.0.rrvqv.xxxxx"
  ["token_type"]=>
  string(6) "Bearer"
  ["expires_in"]=>
  int(3600)
  ["refresh_token"]=>
  string(64) "xxxx.0.rrvqv.xxxx"
  ["id_token"]=>
  array(11) {
    ["iss"]=>
    string(25) "https://appleid.apple.com"
    ["aud"]=>
    string(23) "com.xxxx.weather"
    ["exp"]=>
    int(1656395054)
    ["iat"]=>
    int(1656308654)
    ["sub"]=>
    string(44) "001505.xxx.0209"
    ["at_hash"]=>
    string(22) "xx-vw"
    ["email"]=>
    string(21) "xxxx@gmail.com"
    ["email_verified"]=>
    string(4) "true"
    ["auth_time"]=>
    int(1656308611)
    ["nonce_supported"]=>
    bool(true)
    ["real_user_status"]=>
    int(2)
  }
}

```


```php
<?php
// 通过 accessToken (通过remoteAuthCode方法而来) 移除远程授权，移除后前端将收到 Notify 通知

$accessToken = 'xxxx';
$clientID = 'com.xxxx.221';// app bundle id
$teamID  = 'xxxxxxxxx';       // 苹果开发中心(https://developer.apple.com/) => Membership => team ID
$keyID  = 'xxxxxxxxx';        //  苹果开发中心(https://developer.apple.com/) => 在“Certificates, Identifiers & Profiles (英文)”(证书、标识符和描述文件) 中，从侧边栏中选择“Identifiers”(标识符), 在证书配置管理中心，配置Sign In with Apple功能 => 创建则会得到一个私钥，该文件为”AuthKey_{Kid}.p8”，注意保存，其中页面中还有 Key ID

// AuthKey_{Kid}.p8 密钥 转化为 .pem 格式密钥， openssl pkcs8 -in AuthKey_KEY_ID.p8 -nocrypt -out AuthKey_KEY_ID.pem
$privateKey = <<<EOD
-----BEGIN PRIVATE KEY-----
xxxxx+9hwuxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
gHr0Wf+7X8Zr2i8XjxxLFY4U/9j/x/xx+cQl7OA/oQaV
AUaUQ8mo
-----END PRIVATE KEY-----
EOD;
$authorize = new \Simplephp\Apple\Authorize($clientID, $teamID, $keyID, $privateKey);
$data = $authorize->revokeToken($accessToken);
```

```php
###结果
// 请求apple成功后，不管apple 取消授权成功或失败都是返回空数组 无法判定（可忽略）
array(0) {
}
```


```php
<?php
// 通过 refresh_token (通过remoteAuthCode方法而来) 刷新 accessToken （注意最多刷新一次，多了就封了）

$refreshToken = 'xxxx';
$clientID = 'com.xxxx.221';// app bundle id
$teamID  = 'xxxxxxxxx';       // 苹果开发中心(https://developer.apple.com/) => Membership => team ID
$keyID  = 'xxxxxxxxx';        //  苹果开发中心(https://developer.apple.com/) => 在“Certificates, Identifiers & Profiles (英文)”(证书、标识符和描述文件) 中，从侧边栏中选择“Identifiers”(标识符), 在证书配置管理中心，配置Sign In with Apple功能 => 创建则会得到一个私钥，该文件为”AuthKey_{Kid}.p8”，注意保存，其中页面中还有 Key ID

// AuthKey_{Kid}.p8 密钥 转化为 .pem 格式密钥， openssl pkcs8 -in AuthKey_KEY_ID.p8 -nocrypt -out AuthKey_KEY_ID.pem
$privateKey = <<<EOD
-----BEGIN PRIVATE KEY-----
xxxxx+9hwuxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
gHr0Wf+7X8Zr2i8XjxxLFY4U/9j/x/xx+cQl7OA/oQaV
AUaUQ8mo
-----END PRIVATE KEY-----
EOD;
$authorize = new \Simplephp\Apple\Authorize($clientID, $teamID, $keyID, $privateKey);
$data = $authorize->refreshAccessToken($refreshToken);
```

```php
###结果
// 请求apple成功后，不管apple 取消授权成功或失败都是返回空数组 无法判定（可忽略）
array(4) {
  ["access_token"]=>
  string(64) "xx.0.rrvqv.xx"
  ["token_type"]=>
  string(6) "Bearer"
  ["expires_in"]=>
  int(3600)
  ["id_token"]=>
  string(713) "xxxx.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmlyZWFkZXJjaXR5LndlYXRoZXIiLCJleHAiOjE2NTYzOTUwNzQsImlhdCI6MTY1NjMwODY3NCwic3ViIjoiMDAxNTA1LjE1Yzc2NjJkYTg3YzQ4Y2NhMzI4ZmJhMmY2MzA0MDg4LjAyMDkiLCJhdF9oYXNoIjoiWUtLdUJvdnRqUF9CSnZ6UFBQazF3USIsImVtYWlsIjoidHpxaWFuZzExMThAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOiJ0cnVlIn0.OCyYQimgi9OEq_dknLTBngFapwTBHVQbLG08zl0OUZVvy7rCx8MmEq32ASwNRbv4OWwXMDPtqsXt8hxJwcb94cJmuIft260eu1DKPn7IeVWUCDiqb2i966wtS2V_tM5AYyWve7jelzz1v9KPb8r_8z72Uda3eFLkJKcOkRmxfiMuvFlaqy71iRnVvDyLeCed6bitC7Li7P92-gv9wu41y19P24ditxlaLD076_JcyBbYxHeIoXg3LWTFbAOuiO3zIo_cttOcmqmTDZRqmHGiFclejjSwv8Np4U_Go_MC92CgbmhU1gswYBOgCOJRuQiQRb2nipqH2UdKVEea-qG0tQ"
}
array(4) {
  ["access_token"]=>
  string(64) "xx.0.rrvqv.xx"
  ["token_type"]=>
  string(6) "Bearer"
  ["expires_in"]=>
  int(3600)
  ["id_token"]=>
  array(8) {
    ["iss"]=>
    string(25) "https://appleid.apple.com"
    ["aud"]=>
    string(23) "com.xxx.weather"
    ["exp"]=>
    int(1656395074)
    ["iat"]=>
    int(1656308674)
    ["sub"]=>
    string(44) "001505.xxx.0209"
    ["at_hash"]=>
    string(22) "YKKuBovtjP_BJvzPPPk1wQ"
    ["email"]=>
    string(21) "xxx@gmail.com"
    ["email_verified"]=>
    string(4) "true"
  }
}

```