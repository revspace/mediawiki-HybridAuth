# HybridAuth

MediaWiki extension for a pluggable authentication framework that allows for hybrid (local *and* remote) authentication and authorization scenarios,
with various ways of mapping and syncing local and remote users.

## Configuration

HybridAuth is a framework, and requires *providers* to implement the needed back-end functionality to integrate with a remote system.
An authentication and authorization method using a specific provider with specific configuration is referred to as an authentication *domain*.
Domains can be added by way of entries in the `$wgHybridAuthDomains` configuration parameters. The key of the entry is the name of the domain,
and the value is an associative array with its configuration. A reference of configuration parameters follows:

* `provider`: The name of the provider to use for this domain;
* `config`: An associative array to pass to the provider for its own configuration;

### `user`

* `map_type`: How to map remote users to local users, can be one of the followin values (default: `username`):
  - `username`: Match usernames;
  - `email`: Match e-mail addresses;
  - `realname`: Match realnames;
* `auto_create`: If user mapping fails, automatically create a new user according to `hint_type` (see below, default: `false`):
* `hint_type`: If user mapping fails, depending on `auto_create`, a new account will be created or the user will be prompted to link their account manually.
  This parameter specifies how to look up a user that could be used to pre-fill values as a hint and can be one of the following values (default: `username`):
  - `username`

### `group`

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

## License

GNU General Public License, version 2; see `COPYING` for details.
