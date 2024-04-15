# HybridAuth

Authentication framework extension for MediaWiki that allows for hybrid (local *and* remote) authentication and authorization scenarios,
with various ways of mapping and synchronizing local and remote users.

## Operation

HybridAuth is a framework, and requires *providers* to implement the required *back-end* functionality to integrate with a remote system.
An authentication and authorization method using a specific provider with specific configuration is referred to as an auth *domain*.

### Authentication

The basic authentication flow consists of three steps: authentication, mapping, and synchronization.

#### 1. Authentication

When logging in, the user is explicitly prompted for the domain they would like to authenticate in, in order to avoid cross-domain credential leaking.
The domain provider specifies a set of form fields that are presented to the user to complete authentication.

#### 2. Mapping

After the user has authenticated themselves in a domain, HybridAuth will attempt to map the remote user to a local user.
By which criteria this is exactly done is configurable, refer to the `map_*` configuration parameters below.

If mapping succeeds, a *link* will be established between the remote and local user.
Mapping will not take place again for users with a link in place, unless the remote user is explicitly unlinked.

Otherwise, if no local user can be mapped to the remote user, HybridAuth will attempt to look up a hint local user.
By which criteria this is exactly done is configurable, refer to the `hint_*` configuration parameters below.

What happens next depends on whether `auto_create` is enabled:
- If `auto_create` is enabled and the hint user does not exist, it will be created and linked;
- In all other cases, the user will be prompted to either login as a local user to confirm the link, or to create a new user to link to;
  Details of the hint user, if present, will be used to pre-fill in form fields. Once either of these actions succeeds,
  the remote user will be linked to this local user.

#### 3. Synchronization

When both a remote and local user are present, attributes between them are synchronized according to the user configuration;
refer to the `push_attributes` and `pull_attributes` configuration parameters below.

### Authorization

TBD

### Management

HybridAuth integrates with MediaWiki's standard AuthenticationProvider framework, and reuses its primitives for user management:

- Remote accounts can be explicity linked to the logged-in user through `Special:LinkAccounts`;
- Linked remote accounts can be unlinked through `Special:RemoveCredentials`;
- Attributes of linked remote accounts can be changed through `Special:ChangeCredentials`;

## Configuration

Global configuration parameters are as follows:

### `$wgHybridEnableLocal`

Whether to enable local login as fallback. Default: `true`.

### `$wgHybridDomains`

Auth domains are added by way of entries in this associative array. The key of the entry should be the name of the domain,
and the value an associative array with the domain configuration. A reference of domain configuration parameters follows:

* `provider`: The name of the provider to use for this domain;
* `config`: An associative array to pass to the provider for its own configuration;
* `auto_create`: Whether to automatically create local equivalents of remote entities. Acts as default fallback for `user.auto_create` and `group.auto_create` (default: `false`);

#### `user`

* `map_type`: How to map remote users to local users, can be one of the following values (default: `username`):
  - `username`: Match usernames;
  - `email`: Match e-mail addresses;
  - `realname`: Match realnames;
* `auto_create`: If user mapping fails, automatically create a new user according to `hint_type` (see below):
* `hint_type`: If user mapping fails, depending on `auto_create`, a new account will be created or the user will be prompted to link their account manually.
  This parameter specifies how to look up a user that could be used to pre-fill values as a hint and can be one of the following values (default: `username`):
  - `username`

* `pull_attributes`: Array specifying user attributes to sync *from* the provider *to* the local user;
* `push_attributes`: Array specifying user attributes to sync *to* the provider *from* the local user;

Entries in the `push_attributes` and `pull_attributes` can be one of the following:
- `"username"`, `"email"`, `"realname"`: Short-hand for `[ "attribute" => "username/email/realname", overwrite => true ]`;
- An associative array. Push requires either `attribute`, or both `provider_attribute` and one of `preference` or `value`. Pull requires either `attribute`, or both `preference` and one of `provider-attribute` or `value`. The following keys are valid:
  * `attribute`: Wiki user attribute name, possible values:
    - `username`
    - `email`
    - `realname`
  * `preference`: Wiki [user preference](https://www.mediawiki.org/wiki/Manual:User_preferences) name;
  * `provider_attribute`: Provider user attribute name, optional if `attribute` is given;
  * `value`: Fixed value to set to;
  * `overwrite`: Whether to overwrite if the target is already set;
  * `delete`: Whether to remove the target if the source does not exist;
  * `callback`: Function called with value before synchronizing with the following signature: `bool callback( &$value )`.
    If the callback returns `false`, the attribute will not be synchronized;

Some examples:

```php
# Synchronize local e-mail address with provider e-mail address
"pull_attributes" => [ "email" ],
# Synchronize provider e-mail address with local e-mail address
"push_attributes" => [ "email" ],
# Synchronize provider user attribute with local e-mail address
"push_attributes" => [
  [ "attribute" => "email", "provider_attribute" => "businessEmail" ],
],
# Synchronize preference with provider user attribute, modifying the destination value
function encodePronouns( &$value ): bool {
  switch ( $value ) {
  case null:
    return true;
  case "male":
    $value = "he/him";
    return true;
  case "female":
    $value = "she/her";
    return true;
  case "unknown": /* backend software can't handle that yet */
  default:
    return false; 
  }
}
"push_attributes" => [
  [ "provider_attribute" => "pronouns", "preference" => "gender", "callback" => "encodePronouns" ],
]
# Force preference to value
"pull_attributes" => [
  [ "preference" => "disablemail", "value" => 1, "overwrite" => true ],
]
```

#### `group`

TBD

## Providers

New providers can be added by implementing the `HybridAuthProvider` and `HybridAuthSession` abstract classes.
Extension can registered a provider with HybridAuth through a new `HybridAuth` attribute entry in the extension's own `extension.json`.
This entry should contain keys corresponding to MediaWiki [ObjectFactory](https://www.mediawiki.org/wiki/ObjectFactory)'s standard specification.
The object will always be constructed with `string $domainName` and `Config $domainConfig` prepended to the parameter list.

Example:
```json
{
	/* ... */
	"attributes": {
		"HybridAuth": {
			"HybridAuth-LDAP": {
				"class": "MediaWiki\\Extension\\HybridAuthLDAP\\LDAPHybridAuthProvider"
			}
		}
	}
}
```

### Known providers

* LDAP: [HybridAuth-LDAP](https://github.com/revspace/mediawiki-HybridAuth-LDAP)

## License

GNU General Public License, version 2; see `COPYING` for details.
