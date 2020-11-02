<?php
namespace Stevenmaguire\OAuth2\Client\Test\Provider;

use Stevenmaguire\OAuth2\Client\Provider\KeycloakResourceOwner;

class KeycloakResourceOwnerTest extends \PHPUnit_Framework_TestCase
{
    public function testGetId()
    {
        $ownerId = '123456-id';
        $owner = new KeycloakResourceOwner(['sub' => $ownerId]);

        $this->assertEquals($ownerId, $owner->getId());
    }

    public function testGetEmail()
    {
        $ownerEmail = 'some@test.com';
        $owner = new KeycloakResourceOwner(['email' => $ownerEmail]);

        $this->assertEquals($ownerEmail, $owner->getEmail());
    }

    public function testGetName()
    {
        $ownerName = 'First Last';
        $owner = new KeycloakResourceOwner(['name' => $ownerName]);

        $this->assertEquals($ownerName, $owner->getName());
    }

    public function testGetResponseField()
    {
        $ownerInfo = [
            'sub' => 'id-987654321',
            'email' => 'email@test.com',
            'name' => 'Firstname LastName',
        ];
        $owner = new KeycloakResourceOwner($ownerInfo);

        foreach ($ownerInfo as $key => $value) {
            $this->assertEquals($value, $owner->getResponseField($key));
        }
    }

    public function testToArray()
    {
        $ownerInfo = [
            'sub' => 'id-987654321',
            'email' => 'email@test.com',
            'name' => 'Firstname LastName',
        ];
        $owner = new KeycloakResourceOwner($ownerInfo);

        self::assertEquals($ownerInfo, $owner->toArray());
    }
}
