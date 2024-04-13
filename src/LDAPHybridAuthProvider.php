<?php

namespace MediaWiki\Extension\HybridLDAPAuth;

use Config;
use HashConfig;
use User;
use MediaWiki\User\UserIdentity;

use MediaWiki\Extension\HybridLDAPAuth\Lib\LDAPClient;

class LDAPHybridAuthProvider extends HybridAuthProvider {
	const CONFIG_CONNECTION = 'connection';
	const CONFIG_USER = 'user';

	const USERCONFIG_BASE_DN       = 'base_dn';
	const USERCONFIG_BASE_RDN      = 'base_rdn';
	const USERCONFIG_NAME_ATTR     = 'name_attr';
	const USERCONFIG_REALNAME_ATTR = 'realname_attr';
	const USERCONFIG_EMAIL_ATTR    = 'email_attr';
	const USERCONFIG_SEARCH_FILTER = 'search_filter';
	const USERCONFIG_SEARCH_ATTR   = 'search_attr';
	const USERCONFIG_BIND_ATTR     = 'bind_attr';

	/**
	 * @var string
	 */
	protected $domain;

	/**
	 * @var Config
	 */
	protected $config;

	/**
	 * @var LDAPClient
	 */
	protected $ldapClient;

	/**
	 * @var Config
	 */
	protected $userConfig;

	/**
	 * @var Config
	 */
	protected $groupConfig;

	public function __construct( string $domain, Config $config ) {
		$this->domain = $domain;
		$this->config = $config;

		$connConfig = new HashConfig( $this->getConfig( static::CONFIG_CONNECTION, [] ) );
		$this->ldapClient = new LDAPClient( $connConfig );
		$this->userConfig = new HashConfig( $this->getConfig( static::CONFIG_USER, [] ) );
		$this->groupConfig = new HashConfig( $this->getConfig( static::CONFIG_GROUP. [] ) );
	}

	public function getConfig( string $key, $default = null ) {
		return $this->config->has( $key ) ? $this->config->get( $key ) : $default;
	}

	public function getUserConfig( string $key, $default = null ) {
		return $this->userConfig->has( $key ) ? $this->userConfig->get( $key ) : $default;
	}

	public function getGroupConfig( string $key, $default = null ) {
		return $this->groupConfig->has( $key ) ? $this->groupConfig->get( $key ) : $default;
	}

	/* HybridAuthProvider API */
	public function getDomainDescription(): string {
		return "LDAP: {$this->domain}";
	}

	public function getAuthenticationFields(): array {
		return [
			'username' => [
				'type' => 'string',
				'label' => wfMessage( 'userlogin-yourname' ),
				'help' => wfMessage( 'authmanager-username-help' ),
			],
			'password' => [
				'type' => 'password',
				'label' => wfMessage( 'userlogin-yourpassword' ),
				'help' => wfMessage( 'authmanager-password-help' ),
				'sensitive' => true,
			],
		];
	}

	public function authenticate( array $values, string &$errorMessage ): ?string {
		$errorMessage = null;
		$username = $values['username'] ?? null;
		$password = $values['password'] ?? null;
		if ( !$username || !$password ) {
			return null;
		}

		$dn = $this->lookupLDAPUser( $username, $errorMessage );
		if ( !$dn ) {
			return null;
		}
		if ( !$this->ldapClient->bindAs( $dn, $password ) ) {
			return null;
		}
		return $dn;
	}

	public function mapUserAttribute( string $attr ): ?string {
		switch ( $attr ) {
		case static::ATTR_USERNAME:
			return $this->getUserConfig( static::NAME_ATTR, 'uid' );
		case static::ATTR_EMAIL:
			return $this->getUserConfig( static::EMAIL_ATTR, 'mail' );
		case static::ATTR_REALNAME:
			return $this->getUserConfig( static::REALNAME_ATTR, 'cn' );
		default:
			return null;
		}
	}

	public function getProviderUserAttribute( string $providerUserID, string $attr ): ?string {
		$attrs = $this->getLDAPUser( $providerUserID, [ $attr ] );
		return $attrs ? ($attrs[$attr] ?? null) : null;
	}


	/* LDAP shenanigans */

	/**
	 * Get user base DN
	 *
	 * @return string
	 */
	protected function getUserBaseDN( ): string {
		$dn = $this->getUserConfig( static::CONFIG_BASE_DN );
		if ( $dn ) {
			return $dn;
		}

		$rdn = $this->getUserConfig( static::CONFIG_BASE_RDN );
		$bdn = $this->ldapClient->getBaseDN();
		if ( $bdn ) {
			return $rdn . ',' . $bdn;
		} else {
			return $rdn;
		}
	}

	/**
	 * Get DN for LDAP username.
	 *
	 * @param string $username        Username used for binding
	 * @param string &$errorMessage   Error message to show the user
	 * @return string|null            Corresponding LDAP DN if successful
	 */
	protected function lookupLDAPUser( string $username, ?string &$errorMessage ): ?string {
		$errorMessage = null;
		$bindAttr = $this->getUserConfig( static::CONFIG_BIND_ATTR );

		if ( $bindAttr ) {
			$baseDN = $this->getUserBaseDN();
			$escapedUsername = LDAPClient::escape($username);
			$dn = "{$bindAttr}={$escapedUsername}," . $baseDN;
		} else {
			$searchAttr = $this->getConfig( static::CONFIG_SEARCH_ATTR, 'uid' );
			$attributes = [ 'dn' ];
			try {
				$result = $this->searchLDAPUser( [ $searchAttr => $username ], $attributes );
			} catch ( Exception $ex ) {
				$this->logger->error( 'Error searching userinfo for {username}', [
					'username' => $username, 'exception' => $ex,
				] );
				$errorMessage = wfMessage(
					'ext.hybridldap.auth.userinfo-error', $this->domain
				)->text();
				$result = null;
			}
			$dn = $result ? $result["dn"] : null;
		}
		return $dn;
	}


	/*
	 * Read a single user on LDAP.
	 *
	 * @param array $dn               User DN to read
	 * @param array|null $attributes  Attributes to return
	 * @return array|null             The requested attributes if successful
	 */
	protected function getLDAPUser( string $dn, ?array $attributes ): ?array {
		$searchFilter = $this->getConfig( static::CONFIG_SEARCH_FILTER );
		$filters = $searchFilter ? [ $searchFilter ] : null;
		return $this->ldapClient->read( $dn, $attributes, $filters );
	}

	/*
	 * Search a single user on LDAP.
	 *
	 * @param array $filters          Filters to apply
	 * @param array|null $attributes  Attributes to return
	 * @return array|null             The requested attributes if successful
	 */
	protected function searchLDAPUser( array $filter, ?array $attributes ): ?array {
		$users = $this->searchLDAPUsers( $filter, $attributes );
		if ( !is_array( $users ) ) {
			return null;
		}
		if ( count( $users ) > 1 ) {
			$this->logger->notice( "User query returned more than one result (filter: {$filter})" );
		}
		if ( count( $users ) !== 1 ) {
			return null;
		}
		return $users[0];
	}

	/**
	 * Search users on LDAP.
	 *
	 * @param array $filters          Filters to apply
	 * @param array|null $attributes  Attributes to return
	 * @return array|null             The requested attributes if successful
	 */
	protected function searchLDAPUsers( array $filter, ?array $attributes ): ?array {
		$searchDN = $this->getUserBaseDN();
		$searchFilter = $this->getConfig( static::CONFIG_SEARCH_FILTER );
		if ( $searchFilter ) {
			$filter[] = $searchFilter;
		}
		return $this->ldapClient->search( $attributes, $filter, $searchDN );
	}
}
