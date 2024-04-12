<?php

namespace MediaWiki\Extension\SimpleLDAPAuth\Auth;

use Exception;
use MWException;
use User;

use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\SimpleLDAPAuth\LDAPAuthDomain;
use MediaWiki\Extension\SimpleLDAPAuth\LDAPAuthManager;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\User\UserIdentity;

use MediaWiki\Extension\PluggableAuth\PluggableAuth;
use MediaWiki\Extension\PluggableAuth\PluggableAuthLogin;


class LDAPPluggableAuth extends PluggableAuth {
	const SESSIONKEY_DN = 'ldap-simpleauth-selected-dn';

	const FORMFIELD_USERNAME = 'ldap_username';
	const FORMFIELD_PASSWORD = 'ldap_password';

	/**
	 * @var AuthManager
	 */
	private $authManager;

	/**
	 * @var LDAPAuthManager
	 */
	private $ldapAuthManager;

	/**
	 * @var ?LDAPAuthDomain
	 */
	private $ldapAuthDomain;

	public function __construct( AuthManager $authManager, LDAPAuthManager $ldapAuthManager ) {
		$this->setLogger( LoggerFactory::getInstance( 'SimpleLDAPAuth' ) );
		$this->authManager = $authManager;
		$this->ldapAuthManager = $ldapAuthManager;
		$this->ldapAuthDomain = null;
	}

	protected function getLDAPAuthDomain( ): LDAPAuthDomain {
		if ( !$this->ldapAuthDomain ) {
			$name = $this->getConfigId();
			$config = $this->getData();
			$this->ldapAuthDomain = $this->ldapAuthManager->getAuthDomain( $name, $config );
		}
		return $this->ldapAuthDomain;
	}

	/**
	 * Authenticates against LDAP
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
		$extraLoginFields = $this->authManager->getAuthenticationSessionData(
			PluggableAuthLogin::EXTRALOGINFIELDS_SESSION_KEY
		);
		$username = $extraLoginFields[static::FORMFIELD_USERNAME] ?? '';
		$password = $extraLoginFields[static::FORMFIELD_PASSWORD] ?? '';
		if ( !$username || !$password ) {
			return false;
		}

		$ldapAuthDomain = $this->getLDAPAuthDomain();
		if ( !$ldapAuthDomain ) {
			return false;
		}

		/* Verify user is who they say they are first */
		$errorMessage = null;
		$dn = $ldapAuthDomain->authenticateLDAPUser( $username, $password, $errorMessage );
		if ( !$dn ) {
			if ( !$errorMessage ) {
				$errorMessage = wfMessage(
					'ext.simpleldapauth.error.authentication.credentials', $this->domain
				)->text();
			}
			return false;
		}

		/* Now, let's try mapping */
		$userHint = null;
		$user = $ldapAuthDomain->mapUserFromDN( $dn, $userHint, $errorMessage );
		if ( !$user ) {
			/* No user found, but maybe the user hint can help us */
			if ( $userHint->isRegistered() ) {
				/* Hinted-at user already exists and we can't do manual confirmation, so reject the attempt. :( */
				$errorMessage = wfMessage(
					'ext.simpleldapauth.error.map.not-linking', $userHint->getName()
				)->text();
				$this->getLogger()->warning(
					"Username {username} mapped to collided user {collidedUsername}, not overwriting",
					[ 'username' => $username, 'collidedUsername' => $userHint->getName() ]
				);
				return false;
			}
			/* Hinted user does not exist yet! Only proceed to create it if that is within our policy. */
			if ( !$ldapAuthDomain->shouldAutoCreateUser() ) {
				if ( !$errorMessage ) {
					$errorMessage = wfMessage( 'ext.simpleldapauth.error.map.not-creating' );
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
			static::SESSIONKEY_DN,
			$dn
		);

		/* If we matched to an existing user, overwrite attributes,
		 * else leave them intact from the LDAP query.
		 */
		if ( $user->isRegistered() ) {
			$id = $user->getId();
			$username = $user->getName();
			$realname = $user->getRealName();
			$email = $user->getEmail();

			/* Make sure that the user-domain-relation and user-DN-relation
			 * is updated for existing users. PluggableAuth will only call this
			 * when a user gets newly created.
			 */
			$this->saveExtraAttributes( $id );
		}
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
		$ldapAuthDomain = $this->getLDAPAuthDomain();
		$dn = $this->authManager->getAuthenticationSessionData(
			static::SESSIONKEY_DN
		);
		/**
		 * This can be unset when user account creation was initiated by a foreign source
		 * (e.g Auth_remoteuser). There is no way of knowing the DN at this point.
		 * This can also not be a local login attempt as it would be caught in `authenticate`.
		 */
		if ( $dn !== null ) {
			$ldapAuthDomain->linkUserByID( $userID, $dn );
		}
	}

	public static function getExtraLoginFields( ): array {
		return [
			static::FORMFIELD_USERNAME => [
				'type' => 'string',
				'label' => wfMessage( 'userlogin-yourname' ),
				'help' => wfMessage( 'authmanager-username-help' ),
			],
			static::FORMFIELD_PASSWORD => [
				'type' => 'password',
				'label' => wfMessage( 'userlogin-yourpassword' ),
				'help' => wfMessage( 'authmanager-password-help' ),
				'sensitive' => true,
			]
		];
	}
}
