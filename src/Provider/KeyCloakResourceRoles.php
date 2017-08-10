<?php
/**
 * Created by IntelliJ IDEA.
 * User: jgreen
 * Date: 10/08/2017
 * Time: 11:45 AM
 */

namespace Stevenmaguire\OAuth2\Client\Provider;


class KeyCloakResourceRoles
{

    protected $resourceName = null;
    protected $roles = null;

    /**
     * KeyCloakResourceRoles constructor.
     * @param string $resourceName Name of the resource
     * @param array $roles List of roles
     */
    public function __construct($resourceName, array $roles)
    {
        $this->resourceName = $resourceName;
        $this->roles = $roles;
    }

    /**
     * @return string
     */
    public function getResourceName()
    {
        return $this->resourceName;
    }

    public function hasRoleNamed($name) {
        return $this->roles != null && in_array($name, $this->roles);
    }
    public function getRoles() {
        return $this->roles;
    }
}