<?php

namespace MediaWiki\Extension\SimpleLDAPAuth;

use User;
use Wikimedia\Rdbms\ILoadBalancer;
use MediaWiki\Extension\LDAPProvider\ClientConfig;

class LDAPUserMapper {
	const CONFIG_BASE_DN       = 'base_dn';
	const CONFIG_BASE_RDN      = 'base_rdn';
	const CONFIG_NAME_ATTR     = 'name_attr';
	const CONFIG_REALNAME_ATTR = 'realname_attr';
	const CONFIG_EMAIL_ATTR    = 'email_attr';
	const CONFIG_SEARCH_FILTER = 'search_filter';
	const CONFIG_SEARCH_ATTR   = 'search_attr';
	const CONFIG_BIND_ATTR     = 'bind_attr';
	const CONFIG_MAP_TYPE      = 'map_type';

	const MAPTYPE_NAME = 'username';
	const MAPTYPE_EMAIL = 'email';
	const MAPTYPE_REALNAME = 'realname';

	/**
	 * @var string
	 */
	protected $domain;

	/**
	 * @var array
	 */
	protected $config;

	/**
	 * @var LDAPClient */
	*/
	protected $ldapClient;

	/**
	 * @var UserFinder
	 */
	protected $userFinder;

	/**
	 * @var UserLinkStore
	 */
	protected $linkStore;

	/**
	 * @param string        $domain       Domain to use
	 * @param array         $config       Configuration
	 * @param LDAPClient    $ldapClient   LDAP client for mapping
	 * @param UserFactory   $userFactory  User factory for mapping
	 * @param UserLinkStore $linkStore    User link store for mapping
	 */
	public function __construct( string $domain, array $config, LDAPClient $ldapClient, UserFinder $userFinder, UserLinkStore $linkStore ) {
		$this->domain = $domain;
		$this->config = $config;
		$this->ldapClient = $ldapClient;
		$this->userFinder = $userFinder;
		$this->linkStore = $linkStore;
	}

	protected function getConfig( string $key, $default = null ) {
		return $this->config[$key] ?? $default;
	}

	/**
	 * Map username and password to MediaWiki user through LDAP.
	 *
	 * @param string $username      Username
	 * @param string $password      Password
	 * @param string &$errorMessage Error message if mapping failed
	 * @return User|null
	 */
	public function authenticate( string $username, string $password, string &$errorMessage ): User|null {
		$bindAttr = $this->getConfig( static::CONFIG_BIND_ATTR );
		$authenticated = null;
	
		if ( $bindAttr ) {
			$baseDN = $this->getUserBaseDN();
			$bindDN = "{$bindAttr}={$this->client->escape($username)}," . $baseDN;
			$authenticated = $this->ldapClient->bindUser( $bindDN, $password );
		}

		if ( $authenticated !== false ) {
			$ldapDN = $this->forwardLookup( $username, $ldapUser, $ldapName, $ldapEmail, $errorMessage );
			if ( !$ldapDN ) {
				return null;
			}
			if ( !$authenticated ) {
				$authenticated = $this->ldapClient->bindUser( $ldapDN, $password );
			}
		}
		if ( !$authenticated ) {
			$errorMessage = wfMessage(
				'simpleldapauth-error-authentication-failed', $this->domain
			)->text();
			return null;
		}

		/* We have some information: now match it to a user, existing or new */
		$user = $this->forwardMap( $ldapDN, $ldapUser, $ldapName, $ldapEmail, $errorMessage );
		if (!$user) {
			return null;
		}

		/* TODO: Sync user if requested */
		return $user;
	}

	/**
	 * Get LDAP DN for user
	 *
	 * @param User $user                 User to get DN for
	 * @param string|null $errorMessage  Error message if lookup failed for special reasons
	 * @return string|null               LDAP DN if successful
	 */
	public function getDN( UserIdentity $user, string|null &$errorMessage ): string|null {
		return $this->reverseMap( $user, $errorMessage );
	}

	/**
	 * Get LDAP attributes for user
	 *
	 * @param User $user                 User to get attributes for
	 * @param string|null $errorMessage  Error message if lookup failed for special reasons
	 * @param array|null $attributes     Attribute names to look up
	 * @return array|null                LDAP attributes if successful
	 */
	public function getAttributes( UserIdentity $user, string|null &$errorMessage, array|null $attributes = null ): array|null {
		$ldapDN = $this->reverseMap( $user, $errorMessage );
		return $this->ldapClient->read( $ldapDN, $attributes );
	}


	/**
	 * Get user information from LDAP
	 *
	 * @param string $username        username used for binding
	 * @param string &$ldapUser       LDAP username
	 * @param string &$ldapName       LDAP realname
	 * @param string &$ldapEmail      LDAP email
	 * @param string &$errorMessage   any error message for the user
	 *
	 * @return string|null            the LDAP DN if successful
	 */
	protected function forwardLookup(
		string $username,
		string &$ldapUser, string &$ldapName, string &$ldapEmail,
		string &$errorMessage
	): string|null {
		$userAttr = $this->getConfig( static::CONFIG_NAME_ATTR, 'uid' );
		$realAttr = $this->getConfig( static::CONFIG_REALNAME_ATTR, 'cn' );
		$emailAttr = $this->getConfig( static::CONFIG_EMAIL_ATTR, 'mail' );
		$searchAttr = $this->getConfig( static::CONFIG_SEARCH_ATTR, 'uid' );

		$attributes = [ 'dn', $userAttr, $realAttr, $emailAttr ];
		try {
			$result = $this->searchLDAPUser( [ $searchAttr => $username ], $attributes );
		} catch ( Exception $ex ) {
			wfDebugLog( 'SimpleLDAPAuth', "Error fetching userinfo: {$ex->getMessage()}" );
			wfDebugLog( 'SimpleLDAPAuth', $ex->getTraceAsString() );
			$result = null;
		}
		if ( !$result ) {
			$errorMessage = wfMessage(
				'simpleldapauth-error-authentication-failed-userinfo', $this->domain
			)->text();
			return null;
		}

		/* Update variables */
		$ldapUser = $result[$userAttr] ?? $username;
		$ldapName = $result[$realAttr] ?? '';
		$ldapEmail = $result[$emailAttr] ?? '';
		return $result['dn'];
	}

	/**
	 * Map LDAP attributes to a user, existing or new
	 * @param string $dn              LDAP DN
	 * @param string $username        LDAP username
	 * @param string $realname        LDAP realname
	 * @param string $email           LDAP realname
	 * @param string &$errorMessage   any error message for the user
	 *
	 * @return User|null              the user if successful
	 */
	protected function forwardMap(
		string $dn, string $username, string|null $realname, string|null $email,
		string &$errorMessage
	): User|null {
		/* First try to find the user in our mapping store. */
		$user = $this->linkStore->getUserForDN( $this->domain, $dn );
		if ( $user ) {
			return $user;
		}

		/* Not mapped yet, try to find an existing user. */
		$mapType = $this->getConfig( static::CONFIG_MAP_TYPE, static::MAPTYPE_NAME );
		switch ($mapType) {
		case static::MAPTYPE_NAME:
			$user = $this->userFinder->getUserByName( $username );
			break;
		case static::MAPTYPE_EMAIL:
			if ( !$email ) {
				$errorMessage = wfMessage(
					'simpleldapauth-error-authentication-failed-userinfo', $this->domain
				)->text();
				wfDebugLog( 'SimpleLDAPAuth', "Mapping for {$username} failed: email attribute empty" );
				return null;
			}
			$user = $this->userFinder->getUserByEmail( $email );
			break;
		case static::MAPTYPE_REALNAME:
			if ( !$realname ) {
				$errorMessage = wfMessage(
					'simpleldapauth-error-authentication-failed-userinfo', $this->domain
				)->text();
				wfDebugLog( 'SimpleLDAPAuth', "Mapping for {$username} failed: realname attribute empty" );
				return null;
			}
			$user = $this->userFinder->getUserByEmail( $realname );
			break;
		default:
			$errorMessage = wfMessage(
				'simpleldapauth-error-configuration', $this->domain
			)->text();
			wfDebugLog( 'SimpleLDAPAuth', "Invalid map type: $mapType" );
			return null;
		}
		if ($user) {
			if ( $this->linkStore->isUserMapped( $user ) ) {
				/* User is already mapped to another user */
				$errorMessage = wfMessage(
					'simpleldapauth-error-authentication-map-collision'
				)->text();
				wfDebugLog( 'SimpleLDAPAuth', "Username {$username} already mapped, not overwriting" );
				return null;
			}
			return $user;
		}

		/* Does not exist either, create a new one if and only if a same username does not exist yet. */
		if ( $this->userFinder->getUserByName( $username ) ) {
			$errorMessage = wfMessage(
				'simpleldapauth-error-authentication-attr-collision', $mapType
			)->text();
			wfDebugLog( 'SimpleLDAPAuth', "Username {$username} already taken, not overwriting" );
			return null;
		}
		$user = $this->userFinder->getUserFactory()->newFromName( $username );
		if ( $email ) {
			$user->setEmail( $email );
		}
		if ( $realname ) {
			$user->setRealName( $realname );
		}
		return $user;
	}

	/**
	 * Map a user to LDAP DN
	 *
	 * @param User        $user           to find DN for
	 * @param string|null &$errorMessage  to show user
	 * @return string|null LDAP DN if successful
	 */
	protected function reverseMap( UserIdentity $user, string|null &$errorMessage ): string|null {
		$errorMessage = null;

		/* First try to find the DN in our mapping store */
		$dn = $this->linkStore->getDNForUser( $user, $this->domain );
		if ( $dn ) {
			return $dn;
		}

		/* Not mapped yet, try to find an existing user. */
		$mapType = $this->getConfig( static::CONFIG_MAP_TYPE );
		switch ( $mapType ) {
		case static::MAPTYPE_NAME:
			$searchAttr = $this->getConfig( static::CONFIG_NAME_ATTR, 'uid' );
			$searchValue = $user->getName();
			break;
		case static::MAPTYPE_EMAIL:
			$searchAttr = $this->getConfig( static::CONFIG_EMAIL_ATTR, 'mail' );
			$realUser = $this->userFactory->newFromUserIdentity( $user );
			$searchValue = $realUser->getEmail();
			break;
		case static::MAPTYPE_REALNAME:
			$searchAttr = $this->getConfig( static::CONFIG_REALNAME_ATTR, 'cn' );
			$realUser = $this->userFactory->newFromUserIdentity( $user );
			$searchValue = $realUser->getRealName();
			break;
		default:
			$errorMessage = wfMessage(
				'simpleldapauth-error-configuration', $this->domain
			)->text();
			wfDebugLog( 'SimpleLDAPAuth', "Invalid map type: $mapType" );
			return null;
		}

		if ( !$searchValue ) {
			$errorMessage = wfMessage(
				'simpleldapauth-error-authentication-failed-userinfo', $this->domain
			)->text();
			wfDebugLog( 'SimpleLDAPAuth', "Reverse mapping for {$user->getName()} failed: {$mapType} attribute empty" );
			return null;
		}

		try {
			$result = $this->searchLDAPUser( [ $searchAttr => $searchValue ], [ 'dn '] );
		}  catch ( Exception $ex ) {
			wfDebugLog( 'SimpleLDAPAuth', "Error fetching userinfo: {$ex->getMessage()}" );
			wfDebugLog( 'SimpleLDAPAuth', $ex->getTraceAsString() );
			$result = null;
		}
		return $result ? $result['dn'] : null;
	}

	/**
	 * Get User base DN
	 *
	 * @return string
	 */
	protected function getUserBaseDN( ): string {
		$dn = $this->getConfig( static::CONFIG_BASE_DN );
		if ( $dn ) {
			return $dn;
		}

		$rdn = $this->getConfig( static::CONFIG_BASE_RDN );
		$bdn = $this->ldapClient->getBaseDN();
		if ( $bdn ) {
			return $rdn . ',' . $bdn;
		} else {
			return $rdn;
		}
	}

	/*
	 * Search a single user on LDAP.
	 *
	 * @param array $filters          Filters to apply
	 * @param array|null $attributes  Attributes to return
	 * @return array|null             The requested attributes if successful
	 */
	protected function searchLDAPUser( array $filter, array|null $attributes ): array|null {
		$users = $this->searchLDAPUsers( $filter, $attributes );
		if ( !is_array( $users ) ) {
			return null;
		}
		if ( count( $users ) > 1 ) {
			wfDebugLog( 'SimpleLDAPAuth', "User query returned more than one result (filter={$filter})" );
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
	protected function searchLDAPUsers( array $filter, array|null $attributes ): array|null {
		$searchDN = $this->getUserBaseDN();
		$searchFilter = $this->getConfig( static::CONFIG_SEARCH_FILTER );
		if ( $searchFilter ) {
			$filter[] = $searchFilter;
		}
		return $this->ldapClient->search( $attributes, $filter, $dn );
	}
}
