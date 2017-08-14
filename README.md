# Keycloak Provider for OAuth 2.0 Client
[![Latest Version](https://img.shields.io/github/release/stevenmaguire/oauth2-keycloak.svg?style=flat-square)](https://github.com/stevenmaguire/oauth2-keycloak/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/stevenmaguire/oauth2-keycloak/master.svg?style=flat-square)](https://travis-ci.org/stevenmaguire/oauth2-keycloak)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/stevenmaguire/oauth2-keycloak.svg?style=flat-square)](https://scrutinizer-ci.com/g/stevenmaguire/oauth2-keycloak/code-structure)
[![Quality Score](https://img.shields.io/scrutinizer/g/stevenmaguire/oauth2-keycloak.svg?style=flat-square)](https://scrutinizer-ci.com/g/stevenmaguire/oauth2-keycloak)
[![Total Downloads](https://img.shields.io/packagist/dt/stevenmaguire/oauth2-keycloak.svg?style=flat-square)](https://packagist.org/packages/stevenmaguire/oauth2-keycloak)

This package provides Keycloak OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

## Installation

To install, use composer:

```
composer require stevenmaguire/oauth2-keycloak
```

## Usage

Usage is the same as The League's OAuth client, using `\Stevenmaguire\OAuth2\Client\Provider\Keycloak` as the provider.

Use `authServerUrl` to specify the Keycloak server URL. You can lookup the correct value from the Keycloak client installer JSON under `auth-server-url`, eg. `http://localhost:8080/auth`.

Use `realm` to specify the Keycloak realm name. You can lookup the correct value from the Keycloak client installer JSON under `resource`, eg. `master`.

### Authorization Code Flow

The following fragment should be part of your code's initialization. `$provider` should therefore be available within the code handling at least the login page.

```php
$provider = new Stevenmaguire\OAuth2\Client\Provider\Keycloak([
    'authServerUrl'         => '{keycloak-server-url}',
    'realm'                 => '{keycloak-realm}',
    'clientId'              => '{keycloak-client-id}',
    'clientSecret'          => '{keycloak-client-secret}',
    'redirectUri'           => 'https://example.com/callback-url',
    'encryptionAlgorithm'   => 'RS256',                             // optional
    'encryptionKeyPath'     => '../key.pem'                         // optional
    'encryptionKey'         => 'contents_of_key_or_certificate'     // optional
]);
```

Next, where you wish someone to log in, place the following code. In summary:

1. If no `code` is present (which it won't be to begin with), forward the web browser to Keycloak
2. Once credentials are entered and validated by Keycloak, return to this page with the temporary `code`
3. We will check the Keycloak server with this `code` for an access token
4. If the response is positive and has a valid access token, we can proceed as authenticated

```php
if (!isset($_GET['code'])) {

    // If we don't have an authorization code then get one
    $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->getState();
    header('Location: '.$authUrl);
    exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {

    unset($_SESSION['oauth2state']);
    exit('Invalid state, make sure HTTP sessions are enabled.');

} else {

    // Try to get an access token (using the authorization coe grant)
    try {
        $token = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code']
        ]);
    } catch (Exception $e) {
        exit('Failed to get access token: '.$e->getMessage());
    }

    // Optional: Now you have a token you can look up a users profile data
    try {

        // We got an access token, let's now get the user's details
        $user = $provider->getResourceOwner($token);

        // Use these details to create a new profile
        printf('Hello %s!', $user->getName());

    } catch (Exception $e) {
        exit('Failed to get resource owner: '.$e->getMessage());
    }

    // Use this to interact with an API on the users behalf
    echo $token->getToken();
}
```

### Obtaining Realm Roles and Resources, and Roles within Realm Resources

_Note: You need to supply your realm's RSA public key as the `encryptionKey` wrapped in standard `-----BEGIN PUBLIC KEY-----` and `-----BEGIN PUBLIC KEY-----` lines along with the algorithm (try `RS256`) for this to work. See below for more information._

Once you have a valid access token, you can check for the roles provided to the user:

```php
$provider->checkForKeycloakRoles();
```

The above call unpacks some Keycloak extensions found inside the access token held inside the `$provider`. Next, list the roles:

```php
$provider->getKeycloakRoles()->getRealmRoles(); // Returns a list of named roles
```

You can also list which resources within this realm this user has access to:

```php
$provider->getKeycloakRoles()->getResourceNamesFound(); // Returns a list of named resources
```

You can list the Roles within the above Resource this user has access to:
```php
$provider->getKeycloakRoles()->getRolesOfResourceNamed('account')->getRoles() 
```

Where `account` is one of the resource names found.

### Obtaining Entitlements

Your web application is a Resource Server - it defines Resources that you want to allow users access to. Define these both in your server software and as Resources under _Your Realm_ > Clients > _Your Client_ > Authorization > Resources and use the tools provided to grant your users (or more likely roles) access.

The result of you granting access to Resources are Entitlements. To ask Keyloak to compute the complete set of Entitlements for a user to your client's Resources we can call:

```php
$entitlements = $provider->getEntitlements();
```

This performs a one-time request to Keycloak using the access token previously obtained. Additional calls to this method will return a cached result for this user - *tip* in an interactive session-based site you will likely want to cache this result inside the session to avoid repeat round-trips across page views.

The result can now be queried for individual Entitlements. Each Resource within Keycloak is named by you and gets a UUID.

You can now ask if the user has a specific named entitlement:

```php
$entitlements->hasResourceSetName('Hello world B')
```

Or by ID, in case the name gets changed:

```php
$entitlements->hasResourceSetId('d2fe9843-6462-4bfc-baba-b5787bb6e0e7')
```

You can also list the IDs and names:
```php
$entitlements->listResourcesById(); // List of IDs
$entitlements->listResourcesByName(); // List of names
```

### Refreshing a Token

```php
$provider = new Stevenmaguire\OAuth2\Client\Provider\Keycloak([
    'authServerUrl'     => '{keycloak-server-url}',
    'realm'             => '{keycloak-realm}',
    'clientId'          => '{keycloak-client-id}',
    'clientSecret'      => '{keycloak-client-secret}',
    'redirectUri'       => 'https://example.com/callback-url',
]);

$token = $provider->getAccessToken('refresh_token', ['refresh_token' => $token->getRefreshToken()]);
```

### Logging out

1. Wipe any application local data (sessions, etc) about currently logged-in user
2. Redirect the browser to log out of your Keycloak server (see below)

```php
$url = $provider->getLogoutUrl();
header('Location: '.$url);
```

### Handling encryption

If you've configured your Keycloak instance to use encryption, there are some advanced options available to you.

#### Configure the provider to use the same encryption algorithm

```php
$provider = new Stevenmaguire\OAuth2\Client\Provider\Keycloak([
    // ...
    'encryptionAlgorithm'   => 'RS256',
]);
```

or

```php
$provider->setEncryptionAlgorithm('RS256');
```

#### Configure the provider to use the expected decryption public key or certificate

##### By key value

```php
$key = "-----BEGIN PUBLIC KEY-----\n....\n-----END PUBLIC KEY-----";
// or
// $key = "-----BEGIN CERTIFICATE-----\n....\n-----END CERTIFICATE-----";

$provider = new Stevenmaguire\OAuth2\Client\Provider\Keycloak([
    // ...
    'encryptionKey'   => $key,
]);
```

or

```php
$provider->setEncryptionKey($key);
```

##### By key path

```php
$keyPath = '../key.pem';

$provider = new Stevenmaguire\OAuth2\Client\Provider\Keycloak([
    // ...
    'encryptionKeyPath'   => $keyPath,
]);
```

or

```php
$provider->setEncryptionKeyPath($keyPath);
```

## Testing

``` bash
$ ./vendor/bin/phpunit
```

## Contributing

Please see [CONTRIBUTING](https://github.com/stevenmaguire/oauth2-keycloak/blob/master/CONTRIBUTING.md) for details.


## Credits

- [Steven Maguire](https://github.com/stevenmaguire)
- [All Contributors](https://github.com/stevenmaguire/oauth2-keycloak/contributors)


## License

The MIT License (MIT). Please see [License File](https://github.com/stevenmaguire/oauth2-keycloak/blob/master/LICENSE) for more information.
