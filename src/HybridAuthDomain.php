<?php

namespace MediaWiki\Extension\HybridAuth;

use Config;
use HashConfig;
use Message;
use User;
use MediaWiki\Extension\HybridAuth\Lib\GroupMapper;
use MediaWiki\Extension\HybridAuth\Lib\LDAPClient;
use MediaWiki\Extension\HybridAuth\Lib\UserFinder;
use MediaWiki\Extension\HybridAuth\Lib\UserMapper;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserNameUtils;
use Wikimedia\Rdbms\ILoadBalancer;


class HybridAuthDomain {
	const CONFIG_AUTO_CREATE = 'auto_create';
	const CONFIG_USER        = 'user';
	const CONFIG_GROUP       = 'group';

	const USERCONFIG_AUTO_CREATE = 'auto_create';
	const USERCONFIG_MAP_TYPE    = 'map_type';
	const USERCONFIG_HINT_TYPE   = 'hint_type';

	const MAPTYPE_NAME = 'username';
	const MAPTYPE_EMAIL = 'email';
	const MAPTYPE_REALNAME = 'realname';

	/**
	 * @var string
	 */
	protected $domain;

	/**
	 * @var Config
	 */
	protected $config;
	/**
	 * @var Config
	 */
	protected $userConfig;
	/**
	 * @var Config
	 */
	protected $groupConfig;

	/**
	 * @var HybridAuthProvider
	 */
	protected $provider;

	/**
	 * @var UserFactory
	 */
	protected $userFactory;

	/**
	 * @var UserLinkStore
	 */
	protected $linkStore;

	public function __construct( string $domain, Config $config, HybridAuthProvider $provider, UserFactory $userFactory, UserNameUtils $userNameUtils, UserFinder $userFinder, UserLinkStore $linkStore ) {
		$this->domain = $domain;
		$this->config = $config;
		$this->provider = $provider;
		$this->userFactory = $userFactory;
		$this->userNameUtils = $userNameUtils;
		$this->userFinder = $userFinder;
		$this->linkStore = $linkStore;

		$this->userConfig = new HashConfig( $this->getConfig( static::CONFIG_USER, [] ) );
		$this->groupConfig = new HashConfig( $this->getConfig( static::CONFIG_GROUP, [] ) );
	}

	protected function getConfig( string $key, $default = null ) {
		return $this->config->has( $key ) ? $this->config->get( $key ) : $default;
	}

	protected function getUserConfig( string $key, $default = null ) {
		return $this->userConfig->has( $key ) ? $this->userConfig->get( $key ) : $default;
	}

	protected function getGroupConfig( string $key, $default = null ) {
		return $this->groupConfig->has( $key ) ? $this->groupConfig->get( $key ) : $default;
	}


	public function shouldAutoCreateUser(): bool {
		return $this->getUserConfig(
			static::USERCONFIG_AUTO_CREATE,
			$this->getConfig( static::CONFIG_AUTO_CREATE, true )
		);
	}

	public function getDescription(): string {
		return $this->provider->getDescription();
	}

	public function getAuthenticationFields( ?string $providerUserID = null ): array {
		return $this->provider->getAuthenticationFields( $providerUserID );
	}

	public function getAttributeFields( string $providerUserID ): array {
		return $this->provider->getAttributeFields( $providerUserID );
	}

	public function authenticate( array $values, ?Message &$errorMessage ): ?HybridAuthSession {
		$errorMessage = null;
		return $this->provider->authenticate( $values, $errorMessage );
	}

	public function canSudo( $providerUserID ): bool {
		return $this->provider->canSudo( $providerUserID );
	}

	public function sudo( $providerUserID, ?Message &$errorMessage ): ?HybridAuthSession {
		$errorMessage = null;
		return $this->provider->sudo( $providerUserID, $errorMessage );
	}

	public function getUser( string $providerUserID ): ?User {
		return $this->linkStore->getUserForProvider( $this->domain, $providerUserID );
	}

	public function mapProviderUser( HybridAuthSession $hybridAuthSession, ?UserIdentity &$userHint, ?Message &$errorMessage ): ?User {
		$userHint = null;
		$errorMessage = null;

		/* Try to map it to an existing user */
		$mapType = $this->getUserConfig( static::USERCONFIG_MAP_TYPE, static::MAPTYPE_NAME );
		$mapAttrs = $this->getUserMapAttributes( $hybridAuthSession, $mapType, $errorMessage );
		if ( $mapAttrs === null && !$errorMessage ) {
			$errorMessage = wfMessage( 'ext.hybridauth.authentication.userinfo-error', $this->domain );
			$this->logger->notice( "User mapping for {$providerUserID} failed: {$mapType} unmappable" );
			return null;
		}
		if ( $mapAttrs ) {
			foreach ( $mapAttrs as $attrValue ) {
				switch ( $mapType ) {
				case static::MAPTYPE_NAME:
					$newUsername = $this->userNameUtils->getCanonical( $attrValue, UserNameUtils::RIGOR_USABLE );
					$user = $newUsername ? $this->userFinder->getUserByName( $newUsername ) : null;
					break;
				case static::MAPTYPE_EMAIL:
					$user = $this->userFinder->getUserByEmail( $attrValue );
					break;
				case static::MAPTYPE_REALNAME:
					$user = $this->userFinder->getUserByRealName( $attrValue );
					break;
				}
				/* Only provide candidate if target user is not already linked */
				if ( $user && !$this->isUserLinked( $user, $this->domain ) ) {
					$user = null;
				}
				if ( $user ) {
					return $user;
				}
			}
		}

		/* No map match found! Try to find a hint. */
		$hintType = $this->getUserConfig( static::USERCONFIG_HINT_TYPE, static::MAPTYPE_NAME );
		if ( $hintType === $mapType ) {
			$hintType = null;
		}
		$hintErrorMessage = null;
		$hintAttrs = $hintType ? $this->getUserMapAttributes( $hybridAuthSession, $hintType, $hintErrorMessage ) : null;
		if ( $hintAttrs ) {
			foreach ( $hintAttrs as $attrValue) {
				switch ( $hintType ) {
				case static::MAPTYPE_NAME:
					$userHint = $this->userFactory->newFromName( $attrValue, UserNameUtils::RIGOR_CREATABLE );
					break;
				default:
					$userHint = null;
					break;
				}
				if ( $userHint->isRegistered() && $this->linkStore->isUserLinked( $userHint, $this->domain ) ) {
					/* Don't hint if hinted-at user exists and is already linked. */
					$userHint = null;
				}
				if ( $userHint ) {
					break;
				}
			}
		}

		return null;
	}

	protected function getUserMapAttributes( HybridAuthSession $hybridAuthSession, string $mapType, ?Message &$errorMessage ): ?array {
		switch ( $mapType ) {
		case static::MAPTYPE_NAME:
			$attrType = HybridAuthProvider::USERATTR_NAME;
			break;
		case static::MAPTYPE_EMAIL:
			$attrType = HybridAuthProvider::USERATTR_EMAIL;
			break;
		case static::MAPTYPE_REALNAME:
			$attrType = HybridAuthProvider::USERATTR_REALNAME;
			break;
		default:
			$errorMessage = wfMessage( 'ext.hybridauth.configuration-error', $this->domain );
			$this->logger->critical( "Invalid map type: {$mapType}" );
			return null;
		}
		$providerAttrName = $this->provider->mapUserAttribute( $attrType );
		if ( !$providerAttrName ) {
			$errorMessage = wfMessage( 'ext.hybridauth.configuration-error', $this->domain );
			$this->logger->critical( "User attribute {$attrType} attribute empty does not map in domain {$this->domain}" );
			return null;
		}
		return $hybridAuthSession->getUserAttributes( $providerAttrName );
	}


	/* Utility functions */

	public function hasUser( UserIdentity $user ): bool {
		return $this->getProviderUserID( $user ) !== null;
	}

	public function hasUserByName( string $username ): bool {
		return $this->getProviderUserIDByName( $username ) !== null;
	}

	public function getProviderUserID( UserIdentity $user ): ?string {
		return $this->linkStore->getProviderIDForUser( $user, $this->domain );
	}

	public function getProviderUserIDByName( string $username ): ?string {
		$user = $this->userFactory->newFromName( $username );
		return $user && $user->isRegistered() ? $this->getProviderUserID( $user ) : null;
	}

	public function linkUser( UserIdentity $user, string $providerID ): void {
		$this->linkStore->linkUser( $user, $this->domain, $providerID );
	}

	public function linkUserByID( int $userID, string $providerID ): void {
		$this->linkUser( $this->userFactory->newFromId( $userID ), $providerID );
	}

	public function linkUserByName( string $username, string $providerID ): void {
		$user = $this->userFactory->newFromName( $username );
		if ( $user && $user->isRegistered() ) {
			$this->linkUser( $user, $providerID );
		}
	}

	public function unlinkUser( UserIdentity $user ): void {
		$this->linkStore->unlinkUser( $user, $this->domain );
	}

	public function unlinkUserByID( int $userID ): void {
		$this->unlinkUser( $this->userFactory->newFromId( $userID ) );
	}

	public function unlinkUserByName( string $username ): void {
		$user = $this->userFactory->newFromName( $username );
		if ( $user && $user->isRegistered() ) {
			$this->unlinkUser( $user );
		}
	}

	public function unlinkProviderUser( string $providerID ): void {
		$this->linkStore->unlinkProvider( $this->domain, $providerID);
	}
}
