<?php

namespace MediaWiki\Extension\HybridAuth\Auth;

use RawMessage;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\AuthenticationRequest;

class LinkRequest extends AuthenticationRequest {
	/**
	 * @var string
	 */
	protected $hybridAuthDomain;
	/**
	 * @var string
	 */
	protected $hybridAuthProviderDesc;
	/**
	 * @var ?string
	 */
	protected $hybridAuthProviderUserID;
	/**
	 * @var ?string
	 */
	protected $hybridAuthUsernameHint;
	/**
	 * @var ?array
	 */
	protected $hybridAuthFields;

	public function __construct ( string $domain, string $providerDesc, ?string $providerUserID = null, ?string $usernameHint = null, ?array $authFields = null ) {
		$this->hybridAuthDomain = $domain;
		$this->hybridAuthProviderDesc = $providerDesc;
		$this->hybridAuthProviderUserID = $providerUserID;
		$this->hybridAuthUsernameHint = $usernameHint;
		$this->hybridAuthUsername = null;
		$this->hybridAuthFields = $authFields;
	}

	public function getUniqueId(): string {
		return "HybridAuth:LinkRequest:" . $this->getHybridDomain();
	}

	public function getFieldInfo(): array {
		switch ( $this->action ) {
		case AuthManager::ACTION_LOGIN:
		case AuthManager::ACTION_LOGIN_CONTINUE:
			$fields = [];
			if ( $this->new_username !== null ) {
				$fields['new_username'] = [
					'type' => 'string',
					'label' => wfMessage( 'userlogin-yourname' ),
					'help' => wfMessage( 'authmanager-username-help' ),
					'value' => ($this->new_username ?? $this->hybridAuthUsernameHint) ?? '',
					'optional' => true,
				];
			}
			$fields = array_merge( $fields, [
				'createaccount' => [
					'type' => 'button',
					'label' => wfMessage( 'pt-createaccount' ),
					'value' => 'create',
					'optional' => true,
				],
				'loginattempt' => [
					'type' => 'button',
					'label' => wfMessage( 'pt-login-continue-button' ),
					'value' => 'login',
					'optional' => true,
				],
			] );
			return $fields;
		case AuthManager::ACTION_UNLINK:
		case AuthManager::ACTION_REMOVE:
			return [
				'domain' => [
					'type' => 'button',
					'label' => wfMessage( 'ext.hybridauth.provider-domain-label',
						[ $this->hybridAuthDomain, $this->hybridAuthProviderDesc ]
					),
					'help' => new RawMessage( '' ),
				]
			];
		default:
			return [];
		}
	}

	public function describeCredentials(): array {
		return [
			'provider' => wfMessage( 'ext.hybridauth.provider-label', [ $this->hybridAuthProviderDesc ] ),
			'account' => $this->hybridAuthProviderUserID
				? wfMessage( 'ext.hybridauth.account-label', [
					$this->hybridAuthDomain, $this->hybridAuthProviderUserID,
				] )
				: wfMessage( 'ext.hybridauth.domain-label', [ $this->hybridAuthDomain ] ),
		];
	}

	public function getHybridUsername(): ?string {
		return ($this->hybridAuthUsername ?? $this->new_username) ?? $this->username;
	}

	public function getHybridDomain(): string {
		return $this->hybridAuthDomain;
	}

	public function getHybridProviderUserID(): ?string {
		return $this->hybridAuthProviderUserID;
	}

	public function getHybridAuthenticationFields(): ?array {
		return $this->hybridAuthFields;
	}
}
