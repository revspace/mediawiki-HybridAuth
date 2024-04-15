<?php

namespace MediaWiki\Extension\HybridAuth\Auth;

use Exception;
use MWException;
use User;

use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\HybridAuth\HybridAuthDomain;
use MediaWiki\Extension\HybridAuth\HybridAuthManager;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\User\UserIdentity;

use MediaWiki\Extension\PluggableAuth\PluggableAuth;
use MediaWiki\Extension\PluggableAuth\PluggableAuthLogin;


class PluggableAuthProvider extends PluggableAuth {
	const SESSIONKEY_PROVIDER_USER_ID = 'ext.hybridauth.pluggable.selected-provider-user-id';
	const CONFIG_DOMAIN = 'domain';

	/**
	 * @var AuthManager
	 */
	private $authManager;

	/**
	 * @var HybridAuthManager
	 */
	private $hybridAuthManager;

	/**
	 * @var ?HybridAuthDomain
	 */
	private $hybridAuthDomain;

	public function __construct( AuthManager $authManager, HybridAuthManager $hybridAuthManager ) {
		$this->setLogger( LoggerFactory::getInstance( 'HybridAuth.Pluggable' ) );
		$this->authManager = $authManager;
		$this->hybridAuthManager = $hybridAuthManager;
		$this->hybridAuthDomain = null;
	}

	protected function getDomain(): string {
		$data = $this->getData();
		return $data->has( static::CONFIG_DOMAIN ) ? $config->get( static::CONFIG_DOMAIN ) : $this->getConfigId();
	}

	protected function getHybridAuthDomain( ): HybridAuthDomain {
		if ( !$this->hybridAuthDomain ) {
			$domain = $this->getDomain();
			$this->hybridAuthDomain = $this->hybridAuthManager->getAuthDomain( $domain );
		}
		return $this->hybridAuthDomain;
	}

	/**
	 * Authenticates against HybridAuth
	 * @param int &$id set to user ID
	 * @param string &$username set to username
	 * @param string &$realname set to real name
	 * @param string &$email set to email
	 * @param string &$errorMessage any errors
	 * @return bool false on failure
	 * @SuppressWarnings( UnusedFormalParameter )
	 * @SuppressWarnings( ShortVariable )
	 */
	public function authenticate( ?int &$id, ?string &$username, ?string &$realname, ?string &$email, ?string &$errorMessage ): bool {
		$fields = $this->authManager->getAuthenticationSessionData(
			PluggableAuthLogin::EXTRALOGINFIELDS_SESSION_KEY
		);
		$hybridAuthDomain = $this->getHybridAuthDomain();
		if ( !$hybridAuthDomain ) {
			return false;
		}

		/* Verify user is who they say they are first */
		$errorMessage = null;
		$hybridAuthSession = $hybridAuthDomain->authenticate( $fields, $errorMessage );
		if ( !$hybridAuthSession ) {
			if ( !$errorMessage ) {
				$errorMessage = wfMessage(
					'ext.hybridauth.authentication.credential-error', $this->getDomain()
				)->text();
			}
			return false;
		}

		/* Now, let's try finding the associated user */
		$providerUserID = $hybridAuthSession->getUserID();
		$user = $hybridAuthDomain->getUser( $providerUserID );
		$userHint = null;
		if ( !$user ) {
			/* None found, let's try mapping it */
			$user = $hybridAuthDomain->mapProviderUser( $hybridAuthSession, $userHint, $errorMessage );
		}

		if ( !$user ) {
			/* No user found, but maybe the user hint can help us */
			if ( $userHint->isRegistered() ) {
				/* Hinted-at user already exists and we can't do manual confirmation, so reject the attempt. :( */
				$errorMessage = wfMessage(
					'ext.hybridauth.map.not-linking', $userHint->getName()
				)->text();
				$this->getLogger()->warning(
					"Username {username} mapped to collided user {collidedUsername}, not overwriting",
					[ 'username' => $username, 'collidedUsername' => $userHint->getName() ]
				);
				return false;
			}
			/* Hinted user does not exist yet! Only proceed to create it if that is within our policy. */
			if ( !$hybridAuthDomain->shouldAutoCreateUser() ) {
				if ( !$errorMessage ) {
					$errorMessage = wfMessage( 'ext.hybridauth.map.not-creating' );
				}
				return false;
			}
			/* Proceed with hinted-at user */
			$user = $userHint;
		}

		/* This is a workaround: As "PluggableAuthUserAuthorization" hook is
		 * being called before PluggableAuth::saveExtraAttributes (see below)
		 * we can not persist the domain here, as the user id may be null (first login)
		 */
		$this->authManager->setAuthenticationSessionData(
			static::SESSIONKEY_PROVIDER_USER_ID, $providerUserID
		);
		if ( $user->isRegistered() ) {
			/* Make sure that the user link and attributes are updated for existing users.
			 * PluggableAuth will only call this when a user gets newly created.
			 */
			$this->saveExtraAttributes( $user->getUserId() );
		}

		/* Finally set the attributes */
		$id = $user->getId();
		$username = $user->getName();
		$realname = $user->getRealName();
		$email = $user->getEmail();

		return true;
	}

	/**
	 * @param User &$user to log out
	 */
	public function deauthenticate( UserIdentity &$user ): void {
		/* Nothing to do, really */
		$user = null;
	}

	/**
	 * @param UserIdentity $user to get attributes for
	 */
	public function getAttributes( UserIdentity $user ): array {
		$errorMessage = null;
		$attributes = []; // TODO: $this->getUserMapper()->getAttributes( $user, $errorMessage );
		return $attributes;
	}

	/**
	 * @param int $userId for user
	 */
	public function saveExtraAttributes( int $userID ): void {
		$hybridAuthDomain = $this->getHybridAuthDomain();
		$providerUserID = $this->authManager->getAuthenticationSessionData(
			static::SESSIONKEY_PROVIDER_USER_ID
		);
		$fields = $this->authManager->getAuthenticationSessionData(
			PluggableAuthLogin::EXTRALOGINFIELDS_SESSION_KEY
		);

		/**
		 * This can be unset when user account creation was initiated by a foreign source
		 * (e.g Auth_remoteuser). There is no way of knowing the provider ID at this point.
		 * This can also not be a local login attempt as it would be caught in `authenticate`.
		 */
		if ( $providerUserID === null ) {
			return;
		}

		/* Link user */
		$hybridAuthDomain->linkUserByID( $userID, $providerUserID );

		/* Synchronize user */
		$errorMessage = null;
		$hybridAuthSession = $hybridAuthDomain->authenticate( $fields, $errorMessage );
		if ( !$hybridAuthSession && $hybridAuthDomain->canSudo( $providerUserID ) ) {
			$hybridAuthSession = $hybridAuthDomain->sudo( $providerUserID, $errorMessage );
		}
		if ( $hybridAuthSession ) {
			$hybridAuthDomain->synchronizeUserByID( $userID, $hybridAuthSession, $errorMessage );
		}
	}

	public static function getExtraLoginFields( ): array {
		return $this->getHybridAuthDomain()->getAuthenticationFields();
	}
}
