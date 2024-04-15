# HybridAuth

MediaWiki extension for a pluggable authentication framework that allows for hybrid (local *and* remote) authentication and authorization scenarios,
with various ways of mapping and syncing local and remote users.

## Operation

HybridAuth is a framework, and requires *providers* to implement the needed back-end functionality to integrate with a remote system.
An authentication and authorization method using a specific provider with specific configuration is referred to as an auth *domain*.

### Authentication

The basic authentication flow consists of three steps: authentication, mapping, and synchronization.

#### 1. Authentication

When logging in, the user is explicitly prompted for the domain they would like to authenticate in, in order to mitigate cross-domain credential leaking.
The domain provider specifies a set of form fields that are presented to the user to complete authentication.

#### 2. Mapping

After the user has authenticated themselves in a domain, HybridAuth will attempt to map the domain user to a local user.
By which criteria this is exactly done is configurable, refer to the `map_*` configuration parameters below.

If mapping succeeds, a *link* will be established between the remote and local user.
Mapping will not take place again for users with a link in place, unless the remote user is explicitly unlinked.

Otherwise, if no local user can be mapped to the remote user, HybridAuth will attempts to look up a hint local user.
By which criteria this is exactly done is configurable, refer to the `hint_*` configuration parameters below.

What happens next depends on whether `auto_create` is enabled:
- If `auto_create` is enabled and the hint user does not exist, it will be created and linked;
- In all other cases, the user will be prompted to either login as a local user to confirm the link, or to create a new user to link to;
  Details of the hint user, if present, will be used to pre-fill in form fields. Once either of these actions succeeds,
  the remote user will be linked to this local user.

#### 3. Synchronization

TBD

### Authorization

TBD

### Management

HybridAuth integrates with MediaWiki's standard AuthenticationProvider framework, and uses its primitives for user management:

- Remote accounts can be explicity linked to the logged-in user through `Special:LinkAccounts`;
- Linked remote accounts can be unlinked through `Special:RemoveCredentials`;
- Attributes of linked remote accounts can be changed through `Special:ChangeCredentials`;

## Configuration

Global configuration parameters are as follows:

### `$wgHybridEnableLocal`

Whether to enable local login as fallback. Default: `true`.

### `$wgHybridDomains`

Auth domains are added by way of entries in this associate array. The key of the entry should be the name of the domain,
and the value an associative array with the domain configuration. A reference of domain configuration parameters follows:

* `provider`: The name of the provider to use for this domain;
* `config`: An associative array to pass to the provider for its own configuration;
* `auto_create`: Whether to automatically create local equivalents of remote entities. Acts as default fallback for `user.auto_create` and `group.auto_create` (default: `false`);

#### `user`

* `map_type`: How to map remote users to local users, can be one of the followin values (default: `username`):
  - `username`: Match usernames;
  - `email`: Match e-mail addresses;
  - `realname`: Match realnames;
* `auto_create`: If user mapping fails, automatically create a new user according to `hint_type` (see below):
* `hint_type`: If user mapping fails, depending on `auto_create`, a new account will be created or the user will be prompted to link their account manually.
  This parameter specifies how to look up a user that could be used to pre-fill values as a hint and can be one of the following values (default: `username`):
  - `username`

#### `group`

## Providers

New providers can be added by implementing the `HybridAuthProvider` and `HybridAuthSession` abstract classes.
A new provider can be registered with `HybridAuth` through a new entry in the `HybridAuth` attribute in the extension's `extension.json`.
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
