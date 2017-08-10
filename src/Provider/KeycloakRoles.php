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

    /**
     * @var array a list of roles associated with the realm
     */
    protected $realmAccess = [];
    /**
     * @var array An associative array of KeyCloakResourceRoles keyed by resource name
     */
    protected $resourcesAndRoles = [];

    /**
     * KeycloakRoles constructor.
     *
     * Will decode the JWT access token hidden within this OAuth `AccessToken` yielding additional information
     * provided by KeyCloak.
     *
     */
    public function __construct($obj)
    {
        if (isset($obj->realm_access->roles)) {
            $this->realmAccess = $obj->realm_access->roles;
        }
        if (isset($obj->resource_access)) {
            foreach ($obj->resource_access as $resource => $roles) {
                $list = [];
                foreach ($roles->roles as $role) {
                    $list[] = $role;
                }
                $resourceRoles = new KeyCloakResourceRoles($resource, $list);
                $this->resourcesAndRoles[$resource] = $resourceRoles;
            }
        }
    }

    /**
     *
     * @param AccessToken $accessToken The token received within which the `access_token` exists (yes, really)
     * @param string $encryptionKey For signature checking purposes
     * @param string $encryptionAlgorithm For signature checking purposes
     * @return KeycloakRoles
     */
    public static function fromToken(AccessToken $accessToken, $encryptionKey, $encryptionAlgorithm) {
        $obj = JWT::decode($accessToken->getToken(), $encryptionKey, array($encryptionAlgorithm));
        return new KeycloakRoles($obj);
    }

    public function hasResourceNamed($name) {
        return $this->resourcesAndRoles != null && array_key_exists($name, $this->resourcesAndRoles);
    }
    public function getResourceNamesFound() {
        return array_keys($this->resourcesAndRoles);
    }

    public function hasRealmRoleNamed($name) {
        return $this->realmAccess != null && in_array($name, $this->realmAccess->roles);
    }
    public function getRealmRoles() {
        return $this->realmAccess;
    }

    /**
     * @param $name
     * @return KeyCloakResourceRoles
     */
    public function getRolesOfResourceNamed($name) {
        return $this->resourcesAndRoles[$name];
    }
}