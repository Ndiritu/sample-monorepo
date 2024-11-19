<?php

use League\OAuth2\Client\Token\AccessToken;
use Microsoft\Kiota\Authentication\Oauth\BaseSecretContext;
use Microsoft\Kiota\Authentication\Oauth\DelegatedPermissionTrait;

class RefreshTokenContext extends BaseSecretContext {

    use DelegatedPermissionTrait;

    /**
     * @var string refresh token
     */
    private string $refreshToken;

    /**
     * Initializes the RefreshTokenContext with the tenantId, clientId, clientSecret and refreshToken
     *
     * @param string $tenantId
     * @param string $clientId
     * @param string $clientSecret
     * @param string $refreshToken
     */
    public function __construct(string $tenantId, string $clientId, string $clientSecret, string $refreshToken) {
        if (!$refreshToken) {
            throw new \InvalidArgumentException("Refresh token cannot be empty");
        }
        parent::__construct($tenantId, $clientId, $clientSecret);
        $this->refreshToken = $refreshToken;

        // Initialise cache key
        $this->setCacheKey(new AccessToken([
            'access_token' => '',
            'refresh_token' => $refreshToken,
            'expires' => 0,
            'expires_in' => 0,
            'resource_owner_id' => '',
            'token_type' => 'Bearer',
            'scope' => '',
            'meta' => []
        ]));
    }

    /**
     * Default params for the refresh token request
     *
     * @return array<string, string>
     */
    public function getParams(): array {
        return $this->getRefreshTokenParams($this->refreshToken);
    }

    /**
     * Uses the refresh token hash as a unique identifier for the cache key if the access token is not available
     * otherwise it defaults to using the access token hash in the cache key
     *
     * @param AccessToken|null $accessToken
     * @return void
     */
    public function setCacheKey(?AccessToken $accessToken = null): void
    {
        if ($accessToken) {
            if (!$accessToken->getToken() && $accessToken->getRefreshToken()) {
                $uniqueIdentifier = password_hash($accessToken->getRefreshToken(), PASSWORD_DEFAULT);
                $this->cacheKey = "{$this->getTenantId()}-{$this->getClientId()}-{$uniqueIdentifier}";
            }
            $this->setCacheKey($accessToken);
            return;
        }
    }
}
