<?php

namespace Stevenmaguire\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class KeycloakResourceOwner implements ResourceOwnerInterface
{
    /**
     * Raw response
     *
     * @var array<string, mixed>
     */
    protected $response;

    /**
     * Creates new resource owner.
     *
     * @param array<string, mixed>  $response
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
    public function getId(): ?string
    {
        if (!\array_key_exists('sub', $this->response)) {
            return null;
        }
        if (!is_scalar($this->response['sub'])) {
            return null;
        }

        return (string) $this->response['sub'];
    }

    /**
     * Get resource owner email
     *
     * @return string|null
     */
    public function getEmail(): ?string
    {
        if (!\array_key_exists('email', $this->response) || !is_string($this->response['email'])) {
            return null;
        }

        return $this->response['email'];
    }

    /**
     * Get resource owner name
     *
     * @return string|null
     */
    public function getName(): ?string
    {
        if (!\array_key_exists('name', $this->response) || !is_string($this->response['name'])) {
            return null;
        }

        return $this->response['name'];
    }

    /**
     * Get resource owner username
     *
     * @return string|null
     */
    public function getUsername(): ?string
    {
        if (!\array_key_exists('preferred_username', $this->response) || !is_string($this->response['preferred_username'])) {
            return null;
        }

        return $this->response['preferred_username'];
    }

    /**
     * Get resource owner first name
     *
     * @return string|null
     */
    public function getFirstName(): ?string
    {
        if (!\array_key_exists('given_name', $this->response) || !is_string($this->response['given_name'])) {
            return null;
        }

        return $this->response['given_name'];
    }

    /**
     * Get resource owner last name
     *
     * @return string|null
     */
    public function getLastName(): ?string
    {
        if (!\array_key_exists('family_name', $this->response) || !is_string($this->response['family_name'])) {
            return null;
        }

        return $this->response['family_name'];
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
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->response;
    }
}
