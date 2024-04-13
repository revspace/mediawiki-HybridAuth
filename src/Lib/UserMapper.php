<?php

namespace MediaWiki\Extension\HybridLDAPAuth;

use Config;
use User;
use MediaWiki\Extension\HybridLDAPAuth\Lib\LDAPClient;
use MediaWiki\Extension\HybridLDAPAuth\Lib\UserFinder;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\User\UserNameUtils;
use Psr\Log\LoggerInterface;
use Psr\Log\LoggerAwareInterface;
use Wikimedia\Rdbms\ILoadBalancer;

class UserMapper implements LoggerAwareInterface {
	const CONFIG_BASE_DN       = 'base_dn';
	const CONFIG_BASE_RDN      = 'base_rdn';
	const CONFIG_NAME_ATTR     = 'name_attr';
	const CONFIG_REALNAME_ATTR = 'realname_attr';
	const CONFIG_EMAIL_ATTR    = 'email_attr';
	const CONFIG_SEARCH_FILTER = 'search_filter';
	const CONFIG_SEARCH_ATTR   = 'search_attr';
	const CONFIG_BIND_ATTR     = 'bind_attr';
	const CONFIG_MAP_TYPE      = 'map_type';
	const CONFIG_AUTO_CREATE   = 'auto_create';

	const MAPTYPE_NAME = 'username';
	const MAPTYPE_EMAIL = 'email';
	const MAPTYPE_REALNAME = 'realname';

	/**
	 * @var LoggerInterface
	 */
	protected $logger;

	/**
	 * @var string
	 */
	protected $domain;

	/**
	 * @var Config
	 */
	protected $config;

	/**
	 * @var UserNameUtils
	 */
	protected $userNameUtils;

	/**
	 * @var LDAPClient
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
	public function __construct( string $domain, Config $config, UserNameUtils $userNameUtils, LDAPClient $ldapClient, UserFinder $userFinder, UserLinkStore $linkStore ) {
		$this->setLogger( LoggerFactory::getInstance( 'HybridLDAPAuth.UserMapper' ) );
		$this->domain = $domain;
		$this->config = $config;
		$this->userNameUtils = $userNameUtils;
		$this->ldapClient = $ldapClient;
		$this->userFinder = $userFinder;
		$this->linkStore = $linkStore;
	}

	public function setLogger( LoggerInterface $logger ) {
		$this->logger = $logger;
	}

	protected function getConfig( string $key, $default = null ) {
		return $this->config->has( $key ) ? $this->config->get( $key ) : $default;
	}

	public function shouldAutoCreate( bool $default = true ): bool {
		return $this->getConfig( static::CONFIG_AUTO_CREATE, $default );
	}

	/**
	 * Check whether LDAP user exists
	 *
	 * @param string $username      LDAP username
	 * @return ?bool
	 */
	public function exists( string $username ): ?bool {
		$errorMessage = null;
		$dn = $this->lookupLDAPUser( $username, $errorMessage );
		return $dn ? true : ($errorMessage ? null : false);
	}

	/**
	 * Authenticate LDAP credentials and return DN
	 *
	 * @param string $username      LDAP username
	 * @param string $password      LDAP password
	 * @return ?string
	 */
	public function authenticate( string $username, string $password ): ?string {
		$errorMessage = null;

		$dn = $this->lookupLDAPUser( $username, $errorMessage );
		if ( !$dn ) {
			return null;
		}
		if ( !$this->ldapClient->bindAs( $dn, $password ) ) {
			return null;
		}
		return $dn;
	}

	/**
	 * Try to map DN to user
	 *
	 * @param string  $username         LDAP username
	 * @param string  $password         LDAP password
	 * @param ?string &$dn              Mapped LDAP DN if successful
	 * @param ?UserIdentity &$userHint  Suggested user for linking or creation if failed
	 * @param ?string &$errorMessage    Error message to show the user if failed
	 * @return ?User
	 */
	public function mapDN( string $dn, ?UserIdentity &$userHint, ?string &$errorMessage ): ?User {
		return $this->forwardMap( $dn, $userHint, $errorMessage );
	}

	/**
	 * Get LDAP DN for user
	 *
	 * @param User $user                 User to get DN for
	 * @param string|null $errorMessage  Error message if lookup failed for special reasons
	 * @return string|null               LDAP DN if successful
	 */
	public function getDN( UserIdentity $user, ?string &$errorMessage ): ?string {
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
	public function getAttributes( UserIdentity $user, ?string &$errorMessage, ?array $attributes = null ): ?array {
		$ldapDN = $this->reverseMap( $user, $errorMessage );
		return $this->ldapClient->read( $ldapDN, $attributes );
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
		$bindAttr = $this->getConfig( static::CONFIG_BIND_ATTR );

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

	/**
	 * Map LDAP attributes to a user, existing or new
	 *
	 * @param string  $dn               LDAP DN
	 * @param ?UserIdentity &$userHint  Suggested username for linking or creation if failed
	 * @param ?string &$errorMessage    Error message to show the user if failed
	 * @return User|null                Mapped user if successful
	 */
	protected function forwardMap( string $dn, ?UserIdentity &$userHint, ?string &$errorMessage ): ?User {
		$userHint = null;
		$errorMessage = null;

		/* First try to find the user in our mapping store. */
		$user = $this->linkStore->getUserForDN( $this->domain, $dn );
		if ( $user ) {
			return $user;
		}

		/* Not mapped yet, get some info about our user */
		$userAttr = $this->getConfig( static::CONFIG_NAME_ATTR, 'uid' );
		$realAttr = $this->getConfig( static::CONFIG_REALNAME_ATTR, 'cn' );
		$emailAttr = $this->getConfig( static::CONFIG_EMAIL_ATTR, 'mail' );
		try {
			$result = $this->getLDAPUser( $dn, [ $userAttr, $realAttr, $emailAttr ] );
		} catch ( Exception $ex ) {
			$this->logger->error( 'Error fetching userinfo for DN {dn}', [
				'dn' => $dn, 'exception' => $ex,
			] );
			$result = null;
		}
		if ( $result === null ) {
			$errorMessage = wfMessage(
				'ext.hybridldap.auth.userinfo-error', $this->domain
			)->text();
			return null;
		}
		$username = $result[$userAttr][0];
		$email = $result[$emailAttr][0];
		$realname = $result[$realAttr][0];

		/* Try to map it to an existing user */
		$mapType = $this->getConfig( static::CONFIG_MAP_TYPE, static::MAPTYPE_NAME );
		switch ($mapType) {
		case static::MAPTYPE_NAME:
			$newUsername = $this->userNameUtils->getCanonical( $username, UserNameUtils::RIGOR_USABLE );
			$user = $newUsername ? $this->userFinder->getUserByName( $newUsername ) : null;
			break;
		case static::MAPTYPE_EMAIL:
			if ( !$email ) {
				$errorMessage = wfMessage(
					'ext.hybridldap.auth.userinfo-error', $this->domain
				)->text();
				$this->logger->notice( "Mapping for {$username} failed: email attribute empty" );
				return null;
			}
			$user = $this->userFinder->getUserByEmail( $email );
			break;
		case static::MAPTYPE_REALNAME:
			if ( !$realname ) {
				$errorMessage = wfMessage(
					'ext.hybridldap.auth.userinfo-error', $this->domain
				)->text();
				$this->logger->notice( "Mapping for {$username} failed: realname attribute empty" );
				return null;
			}
			$user = $this->userFinder->getUserByEmail( $realname );
			break;
		default:
			$errorMessage = wfMessage(
				'ext.hybridldap.configuration-error', $this->domain
			)->text();
			$this->logger->critical( 'HybridLDAPAuth', "Invalid map type: $mapType" );
			return null;
		}
		/* Only return if target user is not already linked */
		if ( $user && !$this->linkStore->isUserLinked( $user, $this->domain ) ) {
			/* Store fresh new link and return */
			$this->linkStore->linkUser( $user, $this->domain, $dn );
			return $user;
		}

		/* No match found! Try to find a hint. */
		$usernameHint = $this->userNameUtils->getCanonical( $username, UserNameUtils::RIGOR_CREATABLE );
		if ( $usernameHint ) {
			$userHint = $this->userFinder->getUserByName( $usernameHint );
			if ( !$userHint ) {
				$userHint = $this->userFactory->newFromName( $usernameHint, UserNameUtils::RIGOR_CREATABLE );
			} else if ( $this->linkStore->isUserLinked( $userHint, $this->domain ) ) {
				/* Don't hint if hinted-at user exists and is already linked. */
				$userHint = null;
			}
		}
		return null;
	}

	/**
	 * Map a user to LDAP DN
	 *
	 * @param User        $user           to find DN for
	 * @param string|null &$errorMessage  to show user
	 * @return string|null LDAP DN if successful
	 */
	protected function reverseMap( UserIdentity $user, ?string &$errorMessage ): ?string {
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
				'ext.hybridldap.configuration-error', $this->domain
			)->text();
			$this->logger->critical( "Invalid map type: $mapType" );
			return null;
		}

		if ( !$searchValue ) {
			$errorMessage = wfMessage(
				'ext.hybridldap.auth.userinfo-error', $this->domain
			)->text();
			$username = $user->getName();
			$this->logger->notice( "Reverse mapping for {$username} failed: {$mapType} attribute empty" );
			return null;
		}

		try {
			$result = $this->searchLDAPUser( [ $searchAttr => $searchValue ], [ 'dn '] );
		}  catch ( Exception $ex ) {
			$errorMessage = wfMessage(
				'ext.hybridldap.auth.userinfo-error', $this->domain
			)->text();
			$this->logger->error( "Error searching userinfo for [{$searchAttr}: {$searchValue}]",
				[ 'exception' => $ex ]);
			$result = null;
		}
		return $result ? $result['dn'] : null;
	}

	/**
	 * Get user base DN
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
