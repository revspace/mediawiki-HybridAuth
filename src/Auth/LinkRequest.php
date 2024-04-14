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

	public function __construct ( string $domain, string $providerDesc, ?string $providerUserID = null ) {
		$this->hybridAuthDomain = $domain;
		$this->hybridAuthProviderDesc = $providerDesc;
		$this->hybridAuthProviderUserID = $providerUserID;
	}

	public function getUniqueId(): string {
		return "HybridAuth:LinkRequest:" . $this->getDomain();
	}

	public function getFieldInfo(): array {
		switch ( $this->action ) {
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

	public function getDomain(): string {
		return $this->hybridAuthDomain;
	}

	public function getProviderUserID(): ?string {
		return $this->hybridAuthProviderUserID;
	}
}
