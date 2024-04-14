<?php

namespace MediaWiki\Extension\HybridAuth\Auth;

use Exception;
use MWException;
use StatusValue;
use User;

use MediaWiki\Auth\AbstractPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\HybridAuth\HybridAuthDomain;
use MediaWiki\Extension\HybridAuth\HybridAuthManager;
use MediaWiki\Logger\LoggerFactory;

class PrimaryAuthProvider extends AbstractPrimaryAuthenticationProvider {
	const SESSIONKEY_DOMAIN           = 'ext.hybridauth.primary.selected-domain';
	const SESSIONKEY_PROVIDER_USER_ID = 'ext.hybridauth.primary.selected-provider-user-id';

	/**
	 * @var HybridAuthManager
	 */
	private $hybridAuthManager;

	public function __construct( HybridAuthManager $hybridAuthManager ) {
		$this->setLogger( LoggerFactory::getInstance( 'HybridAuth.Provider' ) );
		$this->hybridAuthManager = $hybridAuthManager;
	}

	protected function getHybridAuthDomain( string $name ): HybridAuthDomain {
		return $this->hybridAuthManager->getAuthDomain( $name );
	}


	/**
	 * AuthenticationProvider interface
	 */

	public function getAuthenticationRequests( $action, array $options ): array {
		$username = $options["username"] ?? null;
		$domains = $this->hybridAuthManager->getAllDomains();
		$linkedDomains = $username ? $this->hybridAuthManager->getUserDomainsByName( $username ) : [];

		switch ( $action ) {
		case AuthManager::ACTION_LOGIN:
			$relevantDomains = $domains;
			break;
		case AuthManager::ACTION_LINK:
			$unlinkedDomains = array_diff( $domains, $linkedDomains );
			$relevantDomains = $unlinkedDomains;
			break;
		case AuthManager::ACTION_CHANGE:
		case AuthManager::ACTION_UNLINK:
		case AuthManager::ACTION_REMOVE:
			$relevantDomains = $linkedDomains;
			break;
		}

		$reqs = [];
		if ( $this->hybridAuthManager->isLocalEnabled() ) {
			switch ( $action ) {
			case AuthManager::ACTION_LOGIN:
				$reqs[] = new AuthRequest( null, null, [] );
				break;
			}
		}
		foreach ( $relevantDomains as $domain ) {
			$hybridAuthDomain = $this->getHybridAuthDomain( $domain );
			switch ( $action ) {
			case AuthManager::ACTION_LINK:
			case AuthManager::ACTION_LOGIN:
				$authFields = $hybridAuthDomain->getAuthenticationFields();
				$desc = $hybridAuthDomain->getDescription();
				$req = new AuthRequest( $domain, $desc, $authFields );
				break;
			case AuthManager::ACTION_CHANGE:
				$desc = $hybridAuthDomain->getDescription();
				$providerUserID = $hybridAuthDomain->getProviderUserIDByName( $username );
				if ( !$providerUserID ) {
					continue 2;
				}
				$attrFields = $hybridAuthDomain->getAttributeFields( $providerUserID );
				if ( !$hybridAuthDomain->canSudo( $providerUserID ) ) {
					$authFields = $hybridAuthDomain->getAuthenticationFields( $providerUserID );
				} else {
					$authFields = null;
				}
				$req = new AttrRequest( $domain, $desc, $providerUserID, $attrFields, $authFields );
				break;
			case AuthManager::ACTION_UNLINK:
			case AuthManager::ACTION_REMOVE:
				$desc = $hybridAuthDomain->getDescription();
				$providerUserID = $hybridAuthDomain->getProviderUserIDByName( $username );
				if ( !$providerUserID ) {
					continue 2;
				}
				$req = new LinkRequest( $domain, $desc, $providerUserID );
				break;
			}
			$reqs[] = $req;
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
		foreach ( $reqs as $req ) {
			if ( !($req instanceof AuthRequest) ) {
				continue;
			}
			if ( $req->isLocalDomain() || !$req->isDomainSelected() ) {
				continue;
			}
			$domain = $req->getDomain();
			if ( !$domain ) {
				continue;
			}
			$fieldValues = $req->getFieldValues();
			return $this->beginHybridAuthentication( $domain, $fieldValues );
		}
		return AuthenticationResponse::newAbstain();
	}

	public function beginPrimaryAccountLink( $user, array $reqs ): AuthenticationResponse {
		foreach ( $reqs as $req ) {
			if ( !($req instanceof AuthRequest) ) {
				continue;
			}
			if ( $req->isLocalDomain() || !$req->isDomainSelected() ) {
				continue;
			}
			$domain = $req->getDomain();
			if ( !$domain ) {
				continue;
			}
			$fieldValues = $req->getFieldValues();
			return $this->beginHybridAuthentication( $domain, $fieldValues, $user );
		}
		return AuthenticationResponse::newAbstain();
	}

	public function beginHybridAuthentication( string $domain, array $fieldValues, ?User $targetUser = null ): AuthenticationResponse {
		$hybridAuthDomain = $this->getHybridAuthDomain( $domain );
		if ( !$hybridAuthDomain ) {
			$this->getLogger()->critical( "Could not instantiate domain: $domain" );
			return AuthenticationResponse::newFail(
				wfMessage( 'ext.hybridauth.configuration-error', [ $domain ] )
			);
		}

		/* Verify user is who they say they are first */
		$errorMessage = null;
		$hybridAuthSession = $hybridAuthDomain->authenticate( $fieldValues, $errorMessage );
		if ( !$hybridAuthSession ) {
			if ( !$errorMessage ) {
				$errorMessage = wfMessage(
					'ext.hybridauth.authentication.credential-error', [ $domain ]
				);
			}
			$this->getLogger()->debug( "Authentication in domain $domain failed: $errorMessage ");
			return AuthenticationResponse::newFail( $errorMessage );
		}

		/* Do we already have a linked user? */
		$providerUserID = $hybridAuthSession->getUserID();
		$user = $hybridAuthDomain->getUser( $providerUserID );
		if ( $user ) {
			/* The easy case: yes! */
			if ( $targetUser && $targetUser->getUserId() != $user->getUserId() ) {
				/* If a user was given and they are not the same, we bail */
				$errorMessage = wfMessage( 'ext.hybridauth.map.not-linking', $domain );
				return AuthenticationResponse::newFail( $errorMessage );
			}
			return AuthenticationResponse::newPass( $user->getName() );
		}

		/* Not yet: find a user to link to: either given or by mapping */
		$userHint = null;
		if ( $targetUser ) {
			$user = $targetUser;
		} else {
			$user = $hybridAuthDomain->mapProviderUser( $hybridAuthSession, $userHint, $errorMessage );
		}
		if ( $user ) {
			/* New user was found: we can link and we're done! */
			$hybridAuthDomain->linkUser( $user, $providerUserID );
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
		if ( $userHint && !$userHint->isRegistered() && $hybridAuthDomain->shouldAutoCreateUser() ) {
			/* Initiate user creation: will be handled by AuthManager,
			 * and confirmed with a call to autoCreatedAccount() below.
			 * Set domain and DN in session here as autoCreatedAccount() does not get any context.
			 */
			$this->manager->setAuthenticationSessionData(
				static::SESSIONKEY_DOMAIN, $domain
			);
			$this->manager->setAuthenticationSessionData(
				static::SESSIONKEY_PROVIDER_USER_ID, $providerUserID
			);
			return AuthenticationResponse::newPass( $userHint->getName() );
		} else {
			/* Either we have a hint to an existing user, or want to give
			 * the opportunity to manually create a new user.
			 * Both are handled by initiating a link request: this will be handled by AuthManager,
			 * and confirmed with a call to providerChangeAuthenticationData( $req ) below.
			 */
			$providerDesc = $hybridAuthDomain->getDescription();
			$response = AuthenticationResponse::newPass( null );
			$response->linkRequest = new LinkRequest( $domain, $providerDesc, $providerUserID );
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
			static::SESSIONKEY_PROVIDER_USER_ID
		);
	}

	public function beginPrimaryAccountCreation( $user, $creator, array $reqs ): AuthenticationResponse {
		return AuthenticationResponse::newAbstain();
	}

	/**
	 * PrimaryAuthenticationProvider: state management
	 */

	public function accountCreationType(): string {
		return static::TYPE_LINK;
	}

	public function testUserExists( $username, $flags = User::READ_NORMAL ) {
		$domains = $this->hybridAuthManager->getAllDomains();
		foreach ( $domains as $domain ) {
			$hybridAuthDomain = $this->getHybridAuthDomain( $domain );
			if ( !$hybridAuthDomain ) {
				continue;
			}
			if ( $hybridAuthDomain->hasUserByName( $username ) ) {
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
		$providerUserID = $this->manager->getAuthenticationSessionData( static::SESSIONKEY_PROVIDER_USER_ID );
		if ( !$domain || !$providerUserID ) {
			return;
		}

		/* Go ahead and link it now */
		$hybridAuthDomain = $this->getHybridAuthDomain( $domain );
		if ( !$hybridAuthDomain ) {
			return;
		}
		$hybridAuthDomain->linkUser( $user, $providerUserID );
	}

	public function providerAllowsAuthenticationDataChange( AuthenticationRequest $req, $checkData = true ): StatusValue {
		if ( $req instanceof LinkRequest ) {
			switch ( $req->action ) {
			case AuthManager::ACTION_LINK:
			case AuthManager::ACTION_UNLINK:
			case AuthManager::ACTION_REMOVE:
				break;
			default:
				return StatusValue::newFatal(
					wfMessage( 'ext.hybridauth.update.action-error', [ $req->action ] )
				);
			}

			if ( $checkData ) {
				if ( !$req->username ) {
					return StatusValue::newGood( 'ignore' );
				}
				$domain = $req->getDomain();
				$domains = $this->hybridAuthManager->getAllDomains();
				if ( !in_array( $domain, $domains ) ) {
					return StatusValue::newFatal(
						wfMessage( 'ext.hybridauth.update.domain-error', [ $domain ] )
					);
				}
				if ( $req->action == AuthManager::ACTION_LINK && $req->getProviderUserID() === null ) {
					return StatusValue::newFatal(
						wfMessage( 'ext.hybridauth.update.id-missing' )
					);
				}
			}
			return StatusValue::newGood();
		} else if ( $req instanceof AttrRequest ) {
			switch ( $req->action ) {
			case AuthManager::ACTION_CHANGE:
				break;
			default:
				return StatusValue::newFatal(
					wfMessage( 'ext.hybridauth.update.action-error', [ $req->action ] )
				);
			}

			if ( $checkData ) {
				$providerUserID = $req->getProviderUserID();
				if ( $providerUserID === null ) {
					return StatusValue::newFatal(
						wfMessage( 'ext.hybridauth.update.id-missing' )
					);
				}
				$domain = $req->getDomain();
				// TODO: identity checks?

				$hybridAuthDomain = $this->getHybridAuthDomain( $domain );
				if ( !$hybridAuthDomain ) {
					return StatusValue::newFatal(
						wfMessage( 'ext.hybridauth.update.domain-error', [ $domain ] )
					);
				}

				/* Enter session now */
				$errorMessage = null;
				if ( $hybridAuthDomain->canSudo( $providerUserID ) ) {
					$errorMessage = null;
					$session = $hybridAuthDomain->sudo( $providerUserID, $errorMessage );
				} else {
					$authFields = $req->getHybridAuthenticationValues();
					$session = $hybridAuthDomain->authenticate( $authFields, $errorMessage );
				}
				if ( !$session ) {
					if ( !$errorMessage ) {
						$errorMessage = wfMessage(
							'ext.hybridauth.authentication.credential-error', [ $domain ]
						);
					}
					return Status::newFatal( $errorMessage );
				}
				$req->hybridAuthSession = $session;
				return StatusValue::newGood();
			}
		}
		return StatusValue::newGood( 'ignore' );
	}

	public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
		$username = $req->username;
		if ( !$username ) {
			return;
		}

		if ( $req instanceof LinkRequest ) {
			$hybridAuthDomain = $this->getHybridAuthDomain( $req->getDomain() );
			if ( !$hybridAuthDomain ) {
				return;
			}
			switch ( $req->action ) {
			case AuthManager::ACTION_LINK:
				$providerUserID = $req->getProviderUserID();
				if ( $providerUserID === null ) {
					return;
				}
				$hybridAuthDomain->linkUserByName( $username, $providerUserID );
				break;
			case AuthManager::ACTION_UNLINK:
			case AuthManager::ACTION_REMOVE:
				$hybridAuthDomain->unlinkUserByName( $username );
				break;
			}
		} else if ( $req instanceof AttrRequest ) {
			$hybridAuthSession = $req->hybridAuthSession ?? null;
			if ( !$hybridAuthSession ) {
				return;
			}
			foreach ( $req->getHybridAttributeValues() as $attr => $value ) {
				$hybridAuthSession->setUserAttributes( $attr, [ $value ] );
			}
		}
	}
}
