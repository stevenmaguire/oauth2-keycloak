<?php

namespace Ubitransport\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class KeycloakResourceOwner implements ResourceOwnerInterface
{
    protected array $response;

    public function __construct(array $response = [])
    {
        $this->response = $response;
    }

    /**
     * Get resource owner id
     */
    public function getId(): ?string
    {
        return \array_key_exists('sub', $this->response) ? $this->response['sub'] : null;
    }

    /**
     * Get resource owner email
     */
    public function getEmail(): ?string
    {
        return \array_key_exists('email', $this->response) ? $this->response['email'] : null;
    }

    /**
     * Get resource owner name
     */
    public function getName(): ?string
    {
        return \array_key_exists('name', $this->response) ? $this->response['name'] : null;
    }

    /**
     * Get resource owner username
     *
     * @return string|null
     */
    public function getUsername()
    {
        return \array_key_exists('preferred_username', $this->response) ? $this->response['preferred_username'] : null;
    }

    /**
     * Get resource owner first name
     *
     * @return string|null
     */
    public function getFirstName()
    {
        return \array_key_exists('given_name', $this->response) ? $this->response['given_name'] : null;
    }

    /**
     * Get resource owner last name
     *
     * @return string|null
     */
    public function getLastName()
    {
        return \array_key_exists('family_name', $this->response) ? $this->response['family_name'] : null;
    }

    /**
     * Return all of the owner details available as an array.
     */
    public function toArray(): array
    {
        return $this->response;
    }
}
