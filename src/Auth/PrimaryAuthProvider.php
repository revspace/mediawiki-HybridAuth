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
use MediaWiki\Permissions\PermissionManager;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\User\UserIdentity;

use MediaWiki\Extension\HybridAuth\HybridAuthDomain;
use MediaWiki\Extension\HybridAuth\HybridAuthManager;
use MediaWiki\Extension\HybridAuth\HybridAuthSession;

class PrimaryAuthProvider extends AbstractPrimaryAuthenticationProvider {
	const SESSIONKEY_CREATED_USER = 'ext.hybridauth.primary.created-user';

	const SESSUSER_DOMAIN           = 'domain';
	const SESSUSER_PROVIDER_USER_ID = 'provider_user_id';
	const SESSUSER_AUTH_FIELDS      = 'auth_fields';

	/**
	 * @var HybridAuthManager
	 */
	private $hybridAuthManager;
	/**
	 * @var PermissionManager
	 */
	private $permissionManager;

	public function __construct( HybridAuthManager $hybridAuthManager, PermissionManager $permissionManager ) {
		if ( !method_exists( $this, 'postInitSetup' ) ) {
			$this->setLogger( LoggerFactory::getInstance( 'HybridAuth.Provider' ) );
		}
		$this->hybridAuthManager = $hybridAuthManager;
		$this->permissionManager = $permissionManager;
	}

	protected function getHybridAuthDomain( string $name ): HybridAuthDomain {
		return $this->hybridAuthManager->getAuthDomain( $name );
	}

	protected function setHybridCreatedSessionUser( string $domain, string $providerUserID, array $authFields ) {
		$this->manager->setAuthenticationSessionData( static::SESSIONKEY_CREATED_USER, [
			static::SESSUSER_DOMAIN => $domain,
			static::SESSUSER_PROVIDER_USER_ID => $providerUserID,
			static::SESSUSER_AUTH_FIELDS => $authFields,
		] );
	}
	
	protected function popHybridCreatedSessionUser( ?string &$domain, ?string &$providerUserID, ?array &$authFields ): bool {
		$userInfo = $this->manager->getAuthenticationSessionData( static::SESSIONKEY_CREATED_USER, null );
		if ( !$userInfo ) {
			return false;
		}
		$this->manager->removeAuthenticationSessionData( static::SESSIONKEY_CREATED_USER, null );
		$domain = $userInfo[static::SESSUSER_DOMAIN];
		$providerUserID = $userInfo[static::SESSUSER_PROVIDER_USER_ID];
		$authFields = $userInfo[static::SESSUSER_AUTH_FIELDS];
		return true;
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
		default:
			$this->logger->error( "Unknown action $action" );
			return [];
		}

		$reqs = [];
		$domainCount = count( $relevantDomains );
		if ( $this->hybridAuthManager->isLocalEnabled() ) {
			$domainCount += 1;
			switch ( $action ) {
			case AuthManager::ACTION_LOGIN:
				$reqs[] = new AuthRequest( null, null, [], $username !== null, $domainCount == 1 );
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
				$req = new AuthRequest( $domain, $desc, $authFields, $username !== null, $domainCount == 1 );
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
			$req->hybridAuthUsername = $username;
		}
		return $reqs;
	}

	/**
	 * PrimaryAuthenticationProvider interface: authentication flows
	 */

	public function beginPrimaryAuthentication( array $reqs ): AuthenticationResponse {
		foreach ( $reqs as $req ) {
			if ( !( $req instanceof AuthRequest ) ) {
				continue;
			}
			if ( $req->isLocalHybridDomain() || !$req->isHybridDomainSelected() ) {
				continue;
			}
			$domain = $req->getHybridDomain();
			if ( !$domain ) {
				continue;
			}
			$fieldValues = $req->getHybridAuthenticationValues();
			return $this->beginHybridAuthentication( $domain, $fieldValues );
		}
		return AuthenticationResponse::newAbstain();
	}

	public function beginPrimaryAccountLink( $user, array $reqs ): AuthenticationResponse {
		foreach ( $reqs as $req ) {
			if ( !( $req instanceof AuthRequest ) ) {
				continue;
			}
			if ( $req->isLocalHybridDomain() || !$req->isHybridDomainSelected() ) {
				continue;
			}
			$domain = $req->getHybridDomain();
			if ( !$domain ) {
				continue;
			}
			$fieldValues = $req->getHybridAuthenticationValues();
			return $this->beginHybridAuthentication( $domain, $fieldValues, $user );
		}
		return AuthenticationResponse::newAbstain();
	}

	protected function beginHybridAuthentication( string $domain, array $fieldValues, ?User $targetUser = null ): AuthenticationResponse {
		$hybridAuthDomain = $this->getHybridAuthDomain( $domain );
		if ( !$hybridAuthDomain ) {
			$this->logger->critical( "Could not instantiate domain: $domain" );
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
			$this->logger->debug( "Authentication in domain $domain failed: $errorMessage ");
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
			return $this->finishHybridAuthentication( $user, $hybridAuthDomain, $hybridAuthSession );
		}

		/* Not yet: find a user to link to: either given or by mapping */
		$userHint = null;
		if ( $targetUser ) {
			$user = $targetUser;
		} else {
			$user = $hybridAuthDomain->mapProviderUser( $hybridAuthSession, $userHint, $errorMessage );
		}
		if ( $user ) {
			/* Mapped user was found: we can link and we're done! */
			$hybridAuthDomain->linkUser( $user, $providerUserID );
			return $this->finishHybridAuthentication( $user, $hybridAuthDomain, $hybridAuthSession );
		}

		/* No user found and no hint: was there anything fatal? */
		if ( !$userHint && $errorMessage ) {
			return AuthenticationResponse::newFail( $errorMessage );
		}

		/* Do we want to automatically create this user? */
		$canCreate = $this->permissionManager->userHasAnyRight( new User(), 'autocreateaccount', 'createaccount' );
		if ( $canCreate && $userHint && $hybridAuthDomain->shouldAutoCreateUser( $userHint ) ) {
			/* Create account! */
			return $this->createHybridUser( $domain, $providerUserID, $fieldValues, $userHint->getName() );
		}

		/* At this point we need to ask the user for input and then link.
		 * This is done by initiating a link request: this will be handled by AuthManager,
		 * and confirmed with a call to providerChangeAuthenticationData( $req ) below.
		 * If we can create users, we first give the user the option to in a new UI prompt,
		 * since the existing AuthManager UI around this does not.
		 * The link request is initiated in continuePrimaryAuthentication() in that case.
		 */
		$usernameHint = $userHint && !$userHint->isRegistered() ? $userHint->getName() : null;
		$linkRequest = $this->prepareHybridUserCreateLink( $domain, $providerUserID, $fieldValues, $usernameHint );
		if ( $canCreate ) {
			return $this->startHybridUserCreateLink( $linkRequest );
		} else {
			return $this->finishHybridUserLink( $linkRequest );
		}
	}

	public function continuePrimaryAuthentication( array $reqs ): AuthenticationResponse {
		foreach ( $reqs as $req ) {
			if ( !( $req instanceof LinkRequest ) ) {
				continue;
			}
			$domain = $req->getHybridDomain();
			/* Here, the user either clicks 'create account' or 'continue login' */
			if ( $req->createaccount ) {
				$username = $req->new_username ?? null;
				/* On first show, we hide the username field until the user has clicked 'create'. */
				if ( !$username ) {
					$req->new_username = '';
					$messageType = $username === null ? 'warning' : 'error';
					return AuthenticationResponse::newUI( $reqs, wfMessage( 'nouserspecified' ), $messageType );
				}
				
				/* Check and create: this will be confirmed with a call to
				 * autoCreatedAccount() below.
				 */
				$hybridAuthDomain = $this->getHybridAuthDomain( $domain );
				if ( !$hybridAuthDomain ) {
					return AuthenticationResponse::newAbstain();
				}
				if ( !$hybridAuthDomain->canCreateUser( $username ) ) {
					return AuthenticationResponse::newUI( $reqs, wfMessage( 'userexists' ), 'error' );
				}
				return $this->finishHybridUserCreate( $req, $username );
			} else if ( $req->loginattempt ) {
				return $this->finishHybridUserLink( $req );
			}
		}
		return AuthenticationResponse::newAbstain();
	}

	public function beginPrimaryAccountCreation( $user, $creator, array $reqs ): AuthenticationResponse {
		return AuthenticationResponse::newAbstain();
	}


	/* Session helpers */

	public function finishHybridAuthentication( UserIdentity $user, HybridAuthDomain $hybridAuthDomain, HybridAuthSession $hybridAuthSession ): AuthenticationResponse {
		if ( !$hybridAuthDomain->synchronizeUser( $user, $hybridAuthSession, $errorMessage ) ) {
			return AuthenticationResponse::newFail( $errorMessage );
		}
		return AuthenticationResponse::newPass( $user->getName() );
	}

	protected function createHybridUser( string $domain, string $providerUserID, array $authFields, string $username ): AuthenticationResponse {
		/* Initiate user creation: this will be handled by AuthManager,
		 * and confirmed with a call to autoCreatedAccount( $req ) below.
		 */
		$this->setHybridCreatedSessionUser( $domain, $providerUserID, $authFields );
		return AuthenticationResponse::newPass( $username );
	}

	protected function prepareHybridUserCreateLink( string $domain, string $providerUserID, array $authFields, ?string $usernameHint ): LinkRequest {
		/* Create create/login request */
		$hybridAuthDomain = $this->getHybridAuthDomain( $domain );
		$providerDesc = $hybridAuthDomain->getDescription();
		return new LinkRequest( $domain, $providerDesc, $providerUserID, $usernameHint, $authFields );
	}

	protected function startHybridUserCreateLink( LinkRequest $linkRequest ): AuthenticationResponse {
		/* Show create/login UI before continuing */
		return AuthenticationResponse::newUI( [ $linkRequest ], wfMessage( 'authmanager-authn-no-local-user-link' ), 'warning' );
	}

	protected function finishHybridUserCreate( LinkRequest $linkRequest, string $username ): AuthenticationResponse {
		/* Finish by creating user */
		$domain = $linkRequest->getHybridDomain();
		$providerUserID = $linkRequest->getHybridProviderUserID();
		$authFields = $linkRequest->getHybridAuthenticationFields();
		return $this->createHybridUser( $domain, $providerUserID, $authFields, $username );
	}

	protected function finishHybridUserLink( LinkRequest $linkRequest ): AuthenticationResponse {
		/* Initiate link: this will be handled by AuthManager,
		 * and confirmed with a call to providerChangeAuthenticationData( $req ) below.
		 */
		$linkRequest->action = AuthManager::ACTION_LINK;
		$response = AuthenticationResponse::newPass( null );
		$response->linkRequest = $linkRequest;
		return $response;
	}


	/**
	 * PrimaryAuthenticationProvider: state management
	 */

	protected function getHybridAuthSession( string $domain, string $providerUserID, array $authFields, ?Message &$errorMessage ): ?HybridAuthSession {
		$errorMessage = null;
		$hybridAuthDomain = $this->getHybridAuthDomain( $domain );
		if ( !$hybridAuthDomain ) {
			$errorMessage = wfMessage( 'ext.hybridauth.update.domain-error', [ $domain ] );
			return null;
		}
		$hybridAuthSession = $hybridAuthDomain->authenticate( $authFields, $errorMessage );
		if ( !$hybridAuthSession && $hybridAuthDomain->canSudo( $providerUserID ) ) {
			$hybridAuthSession = $hybridAuthDomain->sudo( $providerUserID, $errorMessage );
		}
		if ( !$hybridAuthSession ) {
			if ( !$errorMessage ) {
				$errorMessage = wfMessage(
					'ext.hybridauth.authentication.credential-error', [ $domain ]
				);
			}
			return null;
		}
		return $hybridAuthSession;
	}

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
		if ( !$this->popHybridCreatedSessionUser( $domain, $providerUserID, $authFields ) ) {
			return;
		}

		/* Time to finalize the new user: first, we link.... */
		$hybridAuthDomain = $this->getHybridAuthDomain( $domain );
		if ( !$hybridAuthDomain ) {
			return;
		}
		$hybridAuthDomain->linkUser( $user, $providerUserID );

		/* And finally, we synchronize */
		$hybridAuthSession = $this->getHybridAuthSession( $domain, $providerUserID, $authFields, $errorMessage );
		if ( !$hybridAuthSession ) {
			return;
		}
		if ( !$hybridAuthDomain->synchronizeUser( $user, $hybridAuthSession, $errorMessage ) ) {
			return;
		}
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
				if ( !$req->getHybridUsername() ) {
					return StatusValue::newGood( 'ignore' );
				}
				$domain = $req->getHybridDomain();
				$hybridAuthDomain = $this->getHybridAuthDomain( $domain );
				if ( !$hybridAuthDomain) {
					return StatusValue::newFatal(
						wfMessage( 'ext.hybridauth.update.domain-error', [ $domain ] )
					);
				}
				if ( $req->action == AuthManager::ACTION_LINK ) {
					$providerUserID = $req->getHybridProviderUserID();
					if ( $providerUserID === null ) {
						return StatusValue::newFatal(
							wfMessage( 'ext.hybridauth.update.id-missing' )
						);
					}
					$authFields = $req->getHybridAuthenticationFields();
					if ( $authFields === null ) {
						return StatusValue::newFatal(
							wfMessage( 'ext.hybridauth.update.auth-missing' )
						);
					}
					$req->hybridAuthSession = $this->getHybridAuthSession( $domain, $providerUserID, $authFields, $errorMessage );
					if ( !$req->hybridAuthSession ) {
						return StatusValue::newFatal( $errorMessage );
					}
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
				$providerUserID = $req->getHybridProviderUserID();
				if ( $providerUserID === null ) {
					return StatusValue::newFatal(
						wfMessage( 'ext.hybridauth.update.id-missing' )
					);
				}
				$domain = $req->getHybridDomain();
				// TODO: identity checks?

				$hybridAuthDomain = $this->getHybridAuthDomain( $domain );
				if ( !$hybridAuthDomain ) {
					return StatusValue::newFatal(
						wfMessage( 'ext.hybridauth.update.domain-error', [ $domain ] )
					);
				}
				$authFields = $req->getHybridAuthenticationValues();
				if ( $authFields === null ) {
					return StatusValue::newFatal(
						wfMessage( 'ext.hybridauth.update.auth-missing' )
					);
				}
				$req->hybridAuthSession = $this->getHybridAuthSession( $domain, $providerUserID, $authFields, $errorMessage );
				if ( !$req->hybridAuthSession ) {
					return Status::newFatal( $errorMessage );
				}
			}

			return StatusValue::newGood();
		}
		return StatusValue::newGood( 'ignore' );
	}

	public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
		if ( $req instanceof LinkRequest ) {
			$username = $req->getHybridUsername();
			if ( !$username ) {
				return;
			}

			$hybridAuthDomain = $this->getHybridAuthDomain( $req->getHybridDomain() );
			if ( !$hybridAuthDomain ) {
				return;
			}
			switch ( $req->action ) {
			case AuthManager::ACTION_LINK:
				$providerUserID = $req->getHybridProviderUserID();
				if ( $providerUserID === null ) {
					return;
				}
				$hybridAuthDomain->linkUserByName( $username, $providerUserID );
				$hybridAuthSession = $req->hybridAuthSession ?? null;
				if ( !$hybridAuthSession ) {
					return;
				}
				$hybridAuthDomain->synchronizeUserByName( $username, $hybridAuthSession, $errorMessage );
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
