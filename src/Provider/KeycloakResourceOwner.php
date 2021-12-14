<?php

namespace Stevenmaguire\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class KeycloakResourceOwner implements ResourceOwnerInterface
{
    /**
     * Raw response
     *
     * @var array
     */
    protected $response;

    /**
     * Creates new resource owner.
     *
     * @param array  $response
     */
    public function __construct(array $response = array())
    {
        $this->response = $response;
    }

    /**
     * Get resource owner id
     *
     * @return string|null
     */
    public function getId()
    {
        return $this->response['sub'] ?: null;
    }

    /**
     * Get resource owner email
     *
     * @return string|null
     */
    public function getEmail()
    {
        return $this->response['email'] ?: null;
    }

    /**
     * Get resource owner name
     *
     * @return string|null
     */
    public function getName()
    {
        return $this->response['name'] ?: null;
    }

    /**
     * Get resource owner email verification
     *
     * @return bool
     */
    public function getEmailVerified()
    {
       return $this->response['email_verified'] ?? false;
    }

    /**
     * Get resource owner family name
     *
     * @return string|null
     */
    public function getFamilyName()
    {
        return $this->response['family_name'] ?: null;
    }

    /**
     * Get resource owner given name
     *
     * @return string|null
     */
    public function getGivenName()
    {
       return $this->response['given_name'] ?: null;
    }

    /**
     * Get resource owner preferred username
     *
     * @return string|null
     */
    public function getPreferredUsername()
    {
        return $this->response['preferred_username'] ?? null;
    }

    /**
     * Get resource owner picture
     *
     * @return string|null
     */
    public function getPicture()
    {
        return $this->response['picture'] ?? null;
    }

    /**
     * Return all of the owner details available as an array.
     *
     * @return array
     */
    public function toArray()
    {
        return $this->response;
    }
}
