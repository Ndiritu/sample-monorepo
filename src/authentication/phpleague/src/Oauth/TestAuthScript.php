<?php

use Microsoft\Kiota\Authentication\Oauth\AuthorizationCodeContext;
use Microsoft\Kiota\Authentication\Oauth\OnBehalfOfContext;
use Microsoft\Kiota\Authentication\Oauth\ProviderFactory;
use Microsoft\Kiota\Authentication\PhpLeagueAccessTokenProvider;

set_include_path(__DIR__);

require '../../vendor/autoload.php';

function getUser($accessToken) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "https://graph.microsoft.com/v1.0/me");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "GET");

    $headers = array();
    $headers[] = "Authorization: Bearer $accessToken";
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $result = curl_exec($ch);
    if (curl_errno($ch)) {
        echo 'Error:' . curl_error($ch);
    }
    curl_close ($ch);
    return $result;
}

$tenantId = getenv("delegated_tenant_id");
$clientId = getenv("delegated_client_id");
$clientSecret = getenv("delegated_client_secret");
$redirectUri = "http://localhost:8080/";

$oAuthClient = ProviderFactory::create(new AuthorizationCodeContext($tenantId, $clientId, $clientSecret, "", $redirectUri));
$authorizationUrl = $oAuthClient->getAuthorizationUrl();

$code = "1.AUYAZG0ApN7aLUSmlVk08UpBUDxBq8iBz_dJhBVInVj4W2BUAe1GAA.AgABBAIAAADW6jl31mB3T7ugrWTT8pFeAwDs_wUA9P8UdOFcrBrRwtfS4WheYeOJ6y5erit3PIbqTfs820GiCLw9brwZjsgZ2vjCvazb_cubDSSxgIpHWH1tE6KULlVVWFPidWsbRoHF4R54lwX0O3dj45q5Z7tbVKzSaobdpTb2fVMs915j676hWv-BLM2qCkZQW3yWKyZuF5NLW4-5P_Gh-1LeEKYWBifa9SMd8_JWDbHd6eXzdWSYcmcIljZWjRKPdJK1FdLBpoKzEJ7FArzMLpglwDtgyLHzG0_B4QMvKIeh_1iVv0wEbV6kFUXhGIeQwshr4d6kVzk4oF8D4S-x0NOetWBbhD4nS31lB4LY5Hg987kKmO7MBeBpnqv-0UTj0pv7QVyiz_dHksACUsP0luoWxThhKO4shCH4cLF5Ju2DyzWArI7FY7XLU9ysW9Q41Wtr5N6EoJqZvFfiHMHCh7BwTGT1K8Q4R2_4cI45zzcYIvaHGRUfpqX1rSnWiVAewdVthQ_AuijRDXYtxvDzcNXX66igH1MjnMMIMK5mW1OhPcg0awymXDhdRnaXxe-rHJU5HxI4LxXeuSMO2ncjK2Vy7K8EV0mHAs2PctTJ2_kHQlAbbWBri7l8U3LYdBilLZyV1ktZGzE31hD-or55938EwDG-blA9U6f_OnFVfkt_Da2g86BfWm_DplMMmbPVcYdePhd8LgCYAR42DHf0SL_pdtdbeSWjrreHrY6VFwKzEDe45g";

$authCodeContext = new AuthorizationCodeContext(
    $tenantId,
    $clientId,
    $clientSecret,
    $code,
    $redirectUri
);


$scopesForMyApp = ["api://c8ab413c-cf81-49f7-8415-489d58f85b60/.default"];

$tokenProvider = new PhpLeagueAccessTokenProvider($authCodeContext, $scopesForMyApp);

try {
    $accessToken = $tokenProvider->getAuthorizationTokenAsync("https://graph.microsoft.com/me")->wait();
    // getUser($accessToken);
} catch (Exception $e) {
    echo $e->getMessage();
    print_r($e);
}


$parts = explode(".", $accessToken);
$isJWT = $parts && count($parts) == 3;

$oboContext = new OnBehalfOfContext($tenantId, $clientId, $clientSecret, $accessToken);
$scopes =  ["https://graph.microsoft.com/User.ReadWrite"];
$oboTokenProvider = new PhpLeagueAccessTokenProvider($oboContext, $scopes);

try {
    $oboAccessToken = $oboTokenProvider->getAuthorizationTokenAsync("https://graph.microsoft.com/me")->wait();
    echo "OBO access token: $oboAccessToken\n";
    $user = json_decode(json_encode(getUser($oboAccessToken)), true);
    var_dump($user);

} catch (Exception $e) {
    echo $e->getMessage();
    print_r($e);
}
