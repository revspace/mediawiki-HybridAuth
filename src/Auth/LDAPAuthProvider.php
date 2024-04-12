<?php

namespace MediaWiki\Extension\SimpleLDAPAuth\Auth;

use Exception;
use MWException;
use StatusValue;
use User;

use MediaWiki\Auth\AbstractPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\SimpleLDAPAuth\LDAPAuthDomain;
use MediaWiki\Extension\SimpleLDAPAuth\LDAPAuthManager;
use MediaWiki\Logger\LoggerFactory;

class LDAPAuthProvider extends AbstractPrimaryAuthenticationProvider {
	const SESSIONKEY_DOMAIN = 'ldap-simpleauth-selected-domain';
	const SESSIONKEY_DN = 'ldap-simpleauth-selected-dn';

	/**
	 * @var LDAPAuthManager
	 */
	private $ldapAuthManager;
	/**
	 * @var bool
	 */
	private $authorative;

	public function __construct( LDAPAuthManager $ldapAuthManager, bool $authorative = false ) {
		$this->setLogger( LoggerFactory::getInstance( 'SimpleLDAPAuth' ) );
		$this->ldapAuthManager = $ldapAuthManager;
		$this->authorative = $authorative;
	}

	protected function getLDAPAuthDomain( string $name ): LDAPAuthDomain {
		return $this->ldapAuthManager->getDomain( $name );
	}


	/**
	 * AuthenticationProvider interface
	 */

	public function getAuthenticationRequests( $action, array $options ): array {
		$username = $options["username"] ?? null;
		$domains = $this->ldapAuthManager->getAllDomains();
		$linkedDomains = $username ? $this->ldapAuthManager->getUserDomainsByName( $username ) : [];
		$unlinkedDomains = array_diff( $domains, $linkedDomains );

		$reqs = [];
		switch ( $action ) {
		case AuthManager::ACTION_LINK:
		case AuthManager::ACTION_LOGIN:
			$reqs[] = new LDAPAuthRequest( $unlinkedDomains );
			break;
		case AuthManager::ACTION_CHANGE:
			foreach ( $linkedDomains as $domain ) {
				$ldapAuthDomain = $this->ldapAuthManager->getAuthDomain( $domain );
				$reqs[] = new LDAPAttrRequest( $domain, $ldapAuthDomain->getDNByUserName( $username ) );
			}
			break;
		case AuthManager::ACTION_UNLINK:
		case AuthManager::ACTION_REMOVE:
			foreach ( $linkedDomains as $domain ) {
				$ldapAuthDomain = $this->ldapAuthManager->getAuthDomain( $domain );
				$reqs[] = new LDAPLinkRequest( $domain, $ldapAuthDomain->getDNByUserName( $username ) );
			}
			break;
		default:
			return [];
		}

		foreach ($reqs as $req) {
			$req->action = $action;
			$req->username = $username;
		}
		return $reqs;
	}

	/**
	 * PrimaryAuthenticationProvider interface: authentication flows
	 */

	public function beginPrimaryAuthentication( array $reqs ): AuthenticationResponse {
		$req = AuthenticationRequest::getRequestByClass( $reqs, LDAPAuthRequest::class );
		if ( !$req ) {
			return AuthenticationResponse::newAbstain();
		}

		$domain = $req->getLDAPDomain();
		if ( !$req || !$req->username || !$req->password || !$domain ) {
			return AuthenticationResponse::newAbstain();
		}
		$ldapAuthDomain = $this->ldapAuthManager->getAuthDomain( $domain );
		if ( !$ldapAuthDomain ) {
			return AuthenticationResponse::newAbstain();
		}

		/* Verify user is who they say they are first */
		$errorMessage = null;
		$dn = $ldapAuthDomain->authenticateLDAPUser( $req->username, $req->password, $errorMessage );
		if ( !$dn ) {
			if ( $this->authorative && !$errorMessage ) {
				$errorMessage = wfMessage(
					'ext.simpleldapauth.error.authentication.credentials', $domain
				)->text();
			}
			if ( $errorMessage ) {
				return AuthenticationResponse::newFail( $errorMessage );
			} else {
				return AuthenticationResponse::newAbstain();
			}
		}

		/* Now, let's try mapping */
		$userHint = null;
		$user = $ldapAuthDomain->mapUserFromDN( $dn, $userHint, $errorMessage );
		if ( $user ) {
			/* The easy case: a user was found! */
			return AuthenticationResponse::newPass( $user->getName() );
		}

		/* No user found and no hint: was there anything fatal? */
		if ( !$userHint && $errorMessage ) {
			return AuthenticationResponse::newFail( $errorMessage );
		}

		/* Figure out if we want to:
		 * 1. Link with hinted existing user
		 * 2. Auto-create hinted-at non-existing user
		 * 3. Manually create a new user
		 */
		if ( $userHint && !$userHint->isRegistered() && $ldapDomain->shouldAutoCreateUser() ) {
			/* Initiate user creation: will be handled by AuthManager,
			 * and confirmed with a call to autoCreatedAccount() below.
			 * Set domain and DN in session here as autoCreatedAccount() does not get any context.
			 */
			$this->manager->setAuthenticationSessionData(
				static::SESSIONKEY_DOMAIN, $domain
			);
			$this->manager->setAuthenticationSessionData(
				static::SESSIONKEY_DN, $dn
			);
			return AuthenticationResponse::newPass( $userHint->getName() );
		} else {
			/* Either we have a hint to an existing user, or want to give
			 * the opportunity to manually create a new user.
			 * Both are handled by initiating a link request: this will be handled by AuthManager,
			 * and confirmed with a call to providerChangeAuthenticationData( $req ) below.
			 */
			$response = AuthenticationResponse::newPass( null );
			$response->linkRequest = new LDAPLinkRequest( $domain, $dn );
			$response->linkRequest->action = AuthManager::ACTION_LINK;
			$response->linkRequest->username = $userHint ? $userHint->getName() : null;
			return $response;
		}
	}

	public function postAuthentication( $user, AuthenticationResponse $response) {
		$this->manager->removeAuthenticationSessionData(
			static::SESSIONKEY_DOMAIN
		);
		$this->manager->removeAuthenticationSessionData(
			static::SESSIONKEY_DN
		);
	}

	public function beginPrimaryAccountCreation( $user, $creator, array $reqs ): AuthenticationResponse {
		return AuthenticationResponse::newAbstain();
	}

	public function beginPrimaryAccountLink( $user, array $reqs ): AuthenticationResponse {
		$req = AuthenticationRequest::getRequestByClass( $reqs, LDAPAuthRequest::class );
		if ( !$req ) {
			return AuthenticationResponse::newAbstain();
		}
		$domain = $req->getLDAPDomain();
		if ( !$req || !$req->username || !$req->password || !$domain ) {
			return AuthenticationResponse::newAbstain();
		}
		$ldapAuthDomain = $this->ldapAuthManager->getAuthDomain( $domain );
		if ( !$ldapAuthDomain ) {
			return AuthenticationResponse::newAbstain();
		}

		/* Verify user is who they say they are first */
		$errorMessage = null;
		$dn = $ldapAuthDomain->authenticateLDAPUser( $req->username, $req->password, $errorMessage );
		if ( !$dn ) {
			if ( $this->authorative && !$errorMessage ) {
				$errorMessage = wfMessage(
					'ext.simpleldapauth.error.authentication.credentials', $domain
				)->text();
			}
			if ( $errorMessage ) {
				return AuthenticationResponse::newFail( $errorMessage );
			} else {
				return AuthenticationResponse::newAbstain();
			}
		}

		/* Verify user link status */
		$linkedUser = $ldapAuthDomain->getUserByDN( $dn );
		if ( $linkedUser && $linkedUser->isRegistered() ) {
			if ( $linkedUser->getUserId() != $user->getUserId() ) {
				/* Already linked to another user, bail */
				$errorMessage = wfMessage(
					'ext.simpleldapauth.error.map.not-linking', $domain
				)->text();
				return AuthenticationResponse::newFail( $errorMessage );
			} else {
				/* Already linked to this user, no-op */
				return AuthenticationResponse::newPass( $user->getName() );
			}
		}

		/* Now kiss, uh... link */
		$ldapAuthDomain->linkUser( $user, $dn );
		return AuthenticationResponse::newPass( $user->getName() );
	}

	/**
	 * PrimaryAuthenticationProvider: state management
	 */

	public function accountCreationType(): string {
		return static::TYPE_LINK;
	}

	public function testUserExists( $username, $flags = User::READ_NORMAL ) {
		$domains = $this->ldapAuthManager->getAllDomains();
		foreach ( $domains as $domain ) {
			$ldapAuthDomain = $this->ldapAuthManager->getAuthDomain( $domain );
			if ( $ldapAuthDomain && $ldapAuthDomain->hasLDAPUser( $username ) ) {
				return true;
			}
		}
		return false;
	}

	public function autoCreatedAccount( $user, $source ) {
		if ( $source !== $this->getUniqueId() ) {
			return;
		}

		/* Do we need to link this auto-created account? */
		$domain = $this->manager->getAuthenticationSessionData( static::SESSIONKEY_DOMAIN );
		$dn = $this->manager->getAuthenticationSessionData( static::SESSIONKEY_DN );
		if ( !$domain || !$dn ) {
			return;
		}

		/* Wipe the state, as it's for one-time use only */
		$this->resetLDAPAuthState();

		/* Go ahead and link it now */
		$ldapAuthDomain = $this->ldapAuthManager->getAuthDomain( $domain );
		if ( !$ldapAuthDomain ) {
			return;
		}
		$ldapAuthDomain->linkUser( $user, $dn );
	}

	public function providerAllowsAuthenticationDataChange( AuthenticationRequest $req, $checkData = true ): StatusValue {
		if ( $req instanceof LDAPLinkRequest ) {
			switch ( $req->action ) {
			case AuthManager::ACTION_LINK:
			case AuthManager::ACTION_UNLINK:
			case AuthManager::ACTION_REMOVE:
				break;
			default:
				return StatusValue::newFatal(
					wfMessage( 'ext.simpleldapauth.error.change.bad-action', [ $req->action ] )
				);
			}

			if ( $checkData ) {
				if ( !$req->username ) {
					return StatusValue::newGood( 'ignore' );
				}
				$domains = $this->ldapAuthManager->getAllDomains();
				if ( !$req->domain ) {
					return StatusValue::newFatal(
						wfMessage( 'ext.simpleldapauth.error.change.missing-domain' )
					);
				}
				if ( ! in_array( $req->domain, $domains ) ) {
					return StatusValue::newFatal(
						wfMessage( 'ext.simpleldapauth.error.change.bad-domain', [ $req->domain ] )
					);
				}
				if ( $req->action == AuthManager::ACTION_LINK && !$req->dn ) {
					return StatusValue::newFatal(
						wfMessage( 'ext.simpleldapauth.error.change.missing-dn' )
					);
				}
			}
			return StatusValue::newGood();
		}
		return StatusValue::newGood( 'ignore' );
	}

	public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
		$username = $req->username;
		if ( !$username ) {
			return;
		}

		if ( $req instanceof LDAPLinkRequest ) {
			if ( !$req->domain ) {
				return;
			}
			$ldapAuthDomain = $this->ldapAuthManager->getAuthDomain( $req->domain );
			if ( !$ldapAuthDomain ) {
				return;
			}
			switch ( $req->action ) {
			case AuthManager::ACTION_LINK:
				if ( !$req->dn ) {
					return;
				}
				$ldapAuthDomain->linkUserByName( $username, $req->dn );
				break;
			case AuthManager::ACTION_UNLINK:
			case AuthManager::ACTION_REMOVE:
				$ldapAuthDomain->unlinkUserByName( $username );
				break;
			}
		}
	}
}
