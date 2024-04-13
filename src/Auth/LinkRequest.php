<?php

namespace MediaWiki\Extension\HybridLDAPAuth\Auth;

use RawMessage;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\AuthenticationRequest;

class LDAPLinkRequest extends AuthenticationRequest {
	public function __construct ( string $domain, ?string $dn = null ) {
		$this->domain = $domain;
		$this->dn = $dn;
	}

	public function getUniqueId(): string {
		return parent::getUniqueId() . ":" . $this->domain;
	}

	public function getFieldInfo(): array {
		switch ( $this->action ) {
		case AuthManager::ACTION_UNLINK:
		case AuthManager::ACTION_REMOVE:
			return [
				'domain' => [
					'type' => 'button',
					'label' => wfMessage( 'ext.hybridldap.provider-domain-label', [ $this->domain ] ),
					'help' => new RawMessage( '' )
				]
			];
		default:
			return [];
		}
	}

	public function describeCredentials(): array {
		return [
			'provider' => wfMessage( 'ext.hybridldap.provider-label' ),
			'account' => $this->dn
				? wfMessage( 'ext.hybridldap.account-label', [ $this->domain, $this->dn ] )
				: wfMessage( 'ext.hybridldap.domain-label', [ $this->domain ] ),
		];
	}
}
