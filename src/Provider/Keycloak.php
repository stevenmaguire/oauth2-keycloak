<?php

namespace Raehalme\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Keycloak extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * Keycloak URL, eg. http://localhost:8080/auth.
     *
     * @var string
     */
    public $authServerUrl = null;

    /**
     * Realm name, eg. demo.
     *
     * @var string
     */
    public $realm = null;

    /**
     * Get authorization url to begin OAuth flow
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->getBaseUrlWithRealm().'/protocol/openid-connect/auth';
    }

    /**
     * Get access token url to retrieve token
     *
     * @param  array $params
     *
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->getBaseUrlWithRealm().'/protocol/openid-connect/token';
    }

    /**
     * Get provider url to fetch user details
     *
     * @param  AccessToken $token
     *
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->getBaseUrlWithRealm().'/protocol/openid-connect/userinfo';
    }

    /**
     * Creates base url from provider configuration.
     *
     * @return string
     */
    protected function getBaseUrlWithRealm()
    {
        return $this->authServerUrl.'/realms/'.$this->realm;
    }

    /**
     * Get the default scopes used by this provider.
     *
     * This should not be a complete list of all scopes, but the minimum
     * required for the provider user interface!
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return [ 'name', 'email' ];
    }

    /**
     * Check a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  string $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (!empty($data['error'])) {
            $error = $data['error'].': '.$data['error_description'];
            throw new IdentityProviderException($error, 0, $data);
        }
    }

    /**
     * Generate a user object from a successful user details request.
     *
     * @param array $response
     * @param AccessToken $token
     * @return League\OAuth2\Client\Provider\ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new KeycloakResourceOwner($response);
    }
}
