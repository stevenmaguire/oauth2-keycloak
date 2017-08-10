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

    protected $resourceName;
    protected $roles;

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


}