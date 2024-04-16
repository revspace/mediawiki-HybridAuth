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
use MediaWiki\User\UserOptionsManager;
use MediaWiki\User\UserNameUtils;
use Wikimedia\Rdbms\ILoadBalancer;


class HybridAuthDomain {
	const CONFIG_AUTO_CREATE = 'auto_create';
	const CONFIG_USER        = 'user';
	const CONFIG_GROUP       = 'group';

	const USERCONFIG_AUTO_CREATE = 'auto_create';
	const USERCONFIG_MAP_TYPE    = 'map_type';
	const USERCONFIG_HINT_TYPE   = 'hint_type';
	const USERCONFIG_PULL_ATTRS  = 'pull_attributes';
	const USERCONFIG_PUSH_ATTRS  = 'push_attributes';

	const SYNCATTR_ATTRIBUTE          = 'attribute';
	const SYNCATTR_PROVIDER_ATTRIBUTE = 'provider_attribute';
	const SYNCATTR_PREFERENCE         = 'preference';
	const SYNCATTR_VALUE              = 'value';
	const SYNCATTR_CALLBACK           = 'callback';
	const SYNCATTR_OVERWRITE          = 'overwrite';
	const SYNCATTR_DELETE             = 'delete';

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
	 * @var UserNameUtils
	 */
	protected $userNameUtils;

	/**
	 * @var UserOptionsManager
	 */
	protected $userOptionsManager;

	/**
	 * @var UserLinkStore
	 */
	protected $linkStore;

	public function __construct( string $domain, Config $config, HybridAuthProvider $provider, UserFactory $userFactory, UserNameUtils $userNameUtils, UserOptionsManager $userOptionsManager, UserFinder $userFinder, UserLinkStore $linkStore ) {
		$this->domain = $domain;
		$this->config = $config;
		$this->provider = $provider;
		$this->userFactory = $userFactory;
		$this->userNameUtils = $userNameUtils;
		$this->userOptionsManager = $userOptionsManager;
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


	public function shouldAutoCreateUser( UserIdentity $user): bool {
		return $this->getUserConfig(
			static::USERCONFIG_AUTO_CREATE,
			$this->getConfig( static::CONFIG_AUTO_CREATE, true )
		) && !$user->isRegistered();
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
		$mapAttrName = $this->mapUserAttribute( $mapType, $errorMessage );
		if ( $mapAttrName === null ) {
			return null;
		}
		$mapAttrs = $hybridAuthSession->getUserAttributes( $mapAttrName );
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
				default:
					$errorMessage = wfMessage( 'ext.hybridauth.configuration-error', $this->domain );
					$this->logger->critical( "Invalid map type: {$mapType}" );
					return null;
				}
				/* Only provide candidate if target user is not already linked */
				if ( $user && $this->linkStore->isUserLinked( $user, $this->domain ) ) {
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
		if ( $hintType ) {
			$hintAttrName = $this->mapUserAttribute( $hintType, $errorMessage );
			if ( $hintAttrName === null ) {
				return null;
			}
		} else {
			$hintAttrName = null;
		}
		$hintAttrs = $hintAttrName ? $hybridAuthSession->getUserAttributes( $hintAttrName ) : null;
		if ( $hintAttrs ) {
			foreach ( $hintAttrs as $attrValue) {
				switch ( $hintType ) {
				case static::MAPTYPE_NAME:
					$userHint = $this->userFactory->newFromName( $attrValue, UserNameUtils::RIGOR_CREATABLE );
					break;
				default:
					$errorMessage = wfMessage( 'ext.hybridauth.configuration-error', $this->domain );
					$this->logger->critical( "Invalid map type: {$mapType}" );
					return null;
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

	public function synchronizeUser( UserIdentity $userIdentity, HybridAuthSession $hybridAuthSession, ?Message &$errorMessage ): bool {
		$user = $this->userFactory->newFromUserIdentity( $userIdentity );
		$this->userOptionsManager->clearUserOptionsCache( $user );

		/* Pull attributes into local user */
		foreach ( $this->getUserConfig( static::USERCONFIG_PULL_ATTRS, [] ) as $pullAttr ) {
			if ( is_string( $pullAttr ) ) {
				$pullAttr = [ static::SYNCATTR_ATTRIBUTE => $pullAttr, static::SYNCATTR_OVERWRITE => true ];
			}
			if ( !is_array( $pullAttr ) ) {
				$errorMessage = wfMessage( 'ext.hybridauth.configuration-error', $this->domain );
				$this->logger->critical( "Invalid pull attribute type: {$pullAttr}" );
				return false;
			}
			/* Read attribute */
			if ( isset( $pullAttr[static::SYNCATTR_VALUE] ) ) {
				$attrValues = [ $pullAttr[static::SYNCATTR_VALUE] ];
			} else if ( isset( $pullAttr[static::SYNCATTR_PROVIDER_ATTRIBUTE] ) ) {
				$attrValues = $hybridAuthSession->getUserAttributes( $pullAttr[static::SYNCATTR_PROVIDER_ATTRIBUTE] );
			} else if ( isset( $pullAttr[static::SYNCATTR_ATTRIBUTE] ) ) {
				$errorMessage = null;
				$providerAttrSource = $this->mapUserAttribute( $pullAttr[static::SYNCATTR_ATTRIBUTE], $errorMessage );
				if ( $providerAttrSource === null ) {
					return false;
				}
				$attrValues = $hybridAuthSession->getUserAttributes( $providerAttrSource );
			} else {
				$errorMessage = wfMessage( 'ext.hybridauth.configuration-error', $this->domain );
				$this->logger->critical( "Invalid pull attribute, can not determine value source: {$pullAttr}" );
				return false;
			}
			/* Process attribute? */
			if ( isset( $pullAttr[static::SYNCATTR_CALLBACK] ) ) {
				$callback = $pullAttr[static::SYNCATTR_CALLBACK];
				if ( $callback( $attrValues ) === false ) {
					continue;
				}
			}
			/* Check if it should be deleted */
			if ( $attrValues === null || !$attrValues || $attrValues[0] === null ) {
				if ( !($pullAttr[static::SYNCATTR_DELETE] ?? false) ) {
					continue;
				}
				$attrValue = null;
			} else {
				$attrValue = is_array( $attrValues ) ? $attrValues[0] : $attrValues;
			}
			$overwrite = $pullAttr[static::SYNCATTR_OVERWRITE] ?? true;
			/* Write attribute */
			if ( isset( $pullAttr[static::SYNCATTR_PREFERENCE] ) ) {
				$prefDest = $pullAttr[static::SYNCATTR_PREFERENCE];
				if ( $attrValue === null ) {
					$attrValue = $this->userOptionsManager->getDefaultOption( $prefDest );
				} else if ( !$overwrite && $this->userOptionsManager->getOption( $user, $prefDest, null ) !== null ) {
					continue;
				}
				$this->userOptionsManager->setOption( $user, $prefDest, $attrValue );
			} else if ( isset( $pullAttr[static::SYNCATTR_ATTRIBUTE] ) ) {
				$mapType = $pullAttr[static::SYNCATTR_ATTRIBUTE];
				switch (  $mapType ) {
				case static::MAPTYPE_EMAIL:
					if ( $attrValue !== null && !$overwrite && $user->getEmail() ) {
						continue 2;
					}
					$user->setEmail( $attrValue );
					$user->confirmEmail();
					break;
				case static::MAPTYPE_REALNAME:
					if ( $attrValue !== null && !$overwrite && $user->getRealName() ) {
						continue 2;
					}
					$user->setRealName( $attrValue );
					break;
				default:
					$errorMessage = wfMessage( 'ext.hybridauth.configuration-error', $this->domain );
					$this->logger->critical( "Invalid pull attribute, invalid map type {$mapType}: {$pullAttr}" );
					return false;
				}
			} else {
				$errorMessage = wfMessage( 'ext.hybridauth.configuration-error', $this->domain );
				$this->logger->critical( "Invalid pull attribute, can not determine value destination: {$pullAttr}" );
				return false;
			}
		}

		/* Push attributes to remote user */
		foreach ( $this->getUserConfig( static::USERCONFIG_PUSH_ATTRS, [] ) as $pushAttr ) {
			if ( is_string( $pushAttr ) ) {
				$pushAttr = [ static::SYNCATTR_ATTRIBUTE => $pushAttr, static::SYNCATTR_OVERWRITE => true ];
			}
			if ( !is_array( $pushAttr ) ) {
				$errorMessage = wfMessage( 'ext.hybridauth.configuration-error', $this->domain );
				$this->logger->critical( "Invalid push attribute type: {$pushAttr}" );
				return false;
			}
			/* Read attribute */
			if ( isset( $pushAttr[static::SYNCATTR_VALUE] ) ) {
				$attrValue = $pushAttr[static::SYNCATTR_VALUE];
			} else if ( isset( $pushAttr[static::SYNCATTR_PREFERENCE] ) ) {
				$attrValue = $this->userOptionsLookup->getOption( $user, $pushAttr[static::SYNCATTR_PREFERENCE] );
			} else if ( isset( $pushAttr[static::SYNCATTR_ATTRIBUTE] ) ) {
				$mapType = $pushAttr[static::SYNCATTR_ATTRIBUTE];
				switch ( $mapType ) {
				case static::MAPTYPE_NAME:
					$attrValue = $user->getName();
					break;
				case static::MAPTYPE_EMAIL:
					$attrValue = $user->getEmail();
					break;
				case static::MAPTYPE_REALNAME:
					$attrValue = $user->getRealName();
					break;
				default:
					$errorMessage = wfMessage( 'ext.hybridauth.configuration-error', $this->domain );
					$this->logger->critical( "Invalid push attribute, invalid map type {$mapType}: {$pushAttr}" );
					return false;
				}
			} else {
				$errorMessage = wfMessage( 'ext.hybridauth.configuration-error', $this->domain );
				$this->logger->critical( "Invalid push attribute, can not determine value source: {$pushAttr}" );
				return false;
			}
			/* Process attribute? */
			if ( isset( $pushAttr[static::SYNCATTR_CALLBACK] ) ) {
				$callback = $pushAttr[static::SYNCATTR_CALLBACK];
				if ( $callback( $attrValue ) === false ) {
					continue;
				}
			}
			/* Check if it should be deleted */
			if ( $attrValue === null ) {
				if ( !($pushAttr[static::SYNCATTR_DELETE] ?? false) ) {
					continue;
				}
				$attrValues = [];
			} else if ( is_array( $attrValue ) ) {
				$attrValues = $attrValue;
			} else {
				$attrValues = [ $attrValue ];
			}
			$overwrite = $pushAttr[static::SYNCATTR_OVERWRITE] ?? true;
			/* Write attribute */
			if ( isset( $pushAttr[static::SYNCATTR_PROVIDER_ATTRIBUTE] ) ) {
				$providerAttrDest = $pushAttr[static::SYNCATTR_PROVIDER_ATTRIBUTE];
				if ( $attrValues && !$overwrite && $hybridAuthSession->getUserAttributes( $providerAttrDest ) ) {
					continue;
				}
				$hybridAuthSession->setUserAttributes( $providerAttrDest, $attrValues );
			} else if ( isset( $pushAttr[static::SYNCATTR_ATTRIBUTE] ) ) {
				$errorMessage = null;
				$providerAttrDest = $this->mapUserAttribute( $pushAttr[static::SYNCATTR_ATTRIBUTE], $errorMessage );
				if ( $providerAttrDest === null ) {
					return false;
				}
				if ( $attrValues && !$overwrite && $hybridAuthSession->getUserAttributes( $providerAttrDest ) ) {
					continue;
				}
				$hybridAuthSession->setUserAttributes( $providerAttrDest, $attrValues );
			} else {
				$errorMessage = wfMessage( 'ext.hybridauth.configuration-error', $this->domain );
				$this->logger->critical( "Invalid push attribute, can not determine value destination: {$pushAttr}" );
				return false;
			}
		}

		$user->saveSettings();
		return true;
	}

	public function synchronizeUserByID( int $userID, HybridAuthSession $hybridAuthSession, ?Message &$errorMessage ): bool {
		$user = $this->userFactory->newFromId( $userID );
		return $user && $user->isRegistered() ? $this->synchronizeUser( $user, $hybridAuthSession, $errorMessage ) : false;
	}

	public function synchronizeUserByName( string $username, HybridAuthSession $hybridAuthSession, ?Message &$errorMessage ): bool {
		$user = $this->userFactory->newFromName( $username );
		return $user && $user->isRegistered() ? $this->synchronizeUser( $user, $hybridAuthSession, $errorMessage ) : false;
	}

	protected function mapUserAttribute( string $mapType, ?Message &$errorMessage ): ?string {
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
		return $providerAttrName;
	}


	/* Utility functions */
	public function canCreateUser( string $username ): bool {
		$user = $this->userFactory->newFromName( $username, UserNameUtils::RIGOR_CREATABLE );
		return $user && !$user->isSystemUser() && !$user->isRegistered();
	}

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
