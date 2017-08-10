<?php
/**
 * Created by IntelliJ IDEA.
 * User: jgreen
 * Date: 10/08/2017
 * Time: 11:43 AM
 */

namespace Stevenmaguire\OAuth2\Client\Provider;


use Firebase\JWT\JWT;
use League\OAuth2\Client\Token\AccessToken;

/**
 * Class KeycloakRoles
 *
 * Container for the two known sets of roles that can be detected inside an access token.
 *
 * There are roles, which are within the realm, then roles specific within individual named resources.
 *
 * @package Stevenmaguire\OAuth2\Client\Provider
 */
class KeycloakRoles
{

    protected $realmAccess;
    /**
     * @var array An associative array of KeyCloakResourceRoles keyed by resource name
     */
    protected $resourcesAndRoles;

    /**
     * KeycloakRoles constructor.
     *
     * Will decode the JWT access token hidden within this OAuth `AccessToken` yielding additional information
     * provided by KeyCloak.
     *
     * @param AccessToken $accessToken The token received within which the `access_token` exists (yes, really)
     * @param string $encryptionKey For signature checking purposes
     * @param string $encryptionAlgorithm For signature checking purposes
     */
    public function __construct(AccessToken $accessToken, $encryptionKey, $encryptionAlgorithm)
    {
        $obj = JWT::decode($accessToken->getToken(), $encryptionKey, $encryptionAlgorithm);
        $this->realmAccess = $obj->realm_access;
        $this->resourcesAndRoles = [];
        foreach ($this->resource_access as $resource => $roles) {
            $list = [];
            foreach ($roles as $role) {
                $list[] = $role;
            }
            $resourceRoles = new KeyCloakResourceRoles($resource, $list);
            $this->resourcesAndRoles[$resource] = $resourceRoles;
        }
    }

    public function hasResourceNamed($name) {
        return $this->resourcesAndRoles != null && array_key_exists($name, $this->resourcesAndRoles);
    }
    public function getResourceNamesFound() {
        return array_keys($this->resourcesAndRoles);
    }

    public function hasRealmRoleNamed($name) {
        return $this->realmAccess != null && in_array($name, $this->realmAccess);
    }
    public function getRealmRoles() {
        return $this->realmAccess;
    }
    public function getRolesOfResourceNamed($name) {
        return $this->resourcesAndRoles[$name];
    }
}