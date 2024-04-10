<?php

namespace MediaWiki\Extension\SimpleLDAPAuth;

use Exception;
use MWException;
use User;

use MediaWiki\Auth\AuthManager;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserIdentity;
use Wikimedia\Rdbms\ILoadBalancer;

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

	public function __construct( AuthManager $authManager, UserFactory $userFactory, ILoadBalancer $loadBalancer ) {
		$this->setLogger( LoggerFactory::getInstance( 'SimpleLDAPAuth' ) );
		$this->authManager = $authManager;
		$this->ldapAuthManager = new LDAPAuthManager( $loadBalancer, $userFactory );
	}

	protected function getDomain( ): string {
		$name = $this->getConfigId();
		$config = $this->getData();
		return $this->ldapAuthManager->getDomain( $name, $config );
	}

	protected function getUserMapper( ): LDAPUserMapper {
		$name = $this->getConfigId();
		$config = $this->getData();
		return $this->ldapAuthManager->getUserMapper( $name, $config );
	}

	protected function getGroupMapper( ): LDAPGroupMapper {
		$name = $this->getConfigId();
		$config = $this->getData();
		return $this->ldapAuthManager->getGroupMapper( $name, $config );
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
		$user = $this->getUserMapper()->authenticate( $username, $password, $dn, $errorMessage );
		if ( !$user ) {
			return false;
		}

		/* This is a workaround: As "PluggableAuthUserAuthorization" hook is
		 * being called before PluggableAuth::saveExtraAttributes (see below)
		 * we can not rely on UserLinkStore here. Further complicating things,
		 * we can not persist the domain here, as the user id may be null (first login)
		 */
		$this->authManager->setAuthenticationSessionData(
			static::SESSIONKEY_DN,
			$dn
		);

		/* If we matched to an existing user, overwrite attributes,
		 * else leave them intact from the LDAP query.
		 */
		if ( $user->getId() !== 0 ) {
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
		$attributes = $this->getUserMapper()->getAttributes( $user, $errorMessage );
		return $attributes;
	}

	/**
	 * @param int $userId for user
	 */
	public function saveExtraAttributes( int $userId ): void {
		$domain = $this->getDomain();
		$dn = $this->authManager->getAuthenticationSessionData(
			static::SESSIONKEY_DN
		);
		/**
		 * This can be unset when user account creation was initiated by a foreign source
		 * (e.g Auth_remoteuser). There is no way of knowing the DN at this point.
		 * This can also not be a local login attempt as it would be caught in `authenticate`.
		 */
		if ( $dn !== null ) {
			$this->ldapAuthManager->linkUserID( $userId, $domain, $dn );
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
