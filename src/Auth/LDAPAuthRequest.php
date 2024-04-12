<?php

namespace MediaWiki\Extension\HybridLDAPAuth\Auth;

use RawMessage;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\PasswordAuthenticationRequest;

class LDAPAuthRequest extends PasswordAuthenticationRequest {
	public function __construct ( array $domains ) {
		$this->domains = $domains;
		$this->domain = null;
	}

	public function getFieldInfo(): array {
		if ( !$this->domains ) {
			return [];
		}

		$fields = [
			'username' => [
				'type' => 'string',
				'label' => wfMessage( 'userlogin-yourname' ),
				'help' => wfMessage( 'authmanager-username-help' ),
			],
			'password' => [
				'type' => 'password',
				'label' => wfMessage( 'userlogin-yourpassword' ),
				'help' => wfMessage( 'authmanager-password-help' ),
				'sensitive' => true,
			],
		];

		$domainValues = [];
		if ( $this->action === AuthManager::ACTION_LOGIN ) {
			$domainValues[''] = wfMessage( 'ext.hybridldap.local-domain-label' );
		}
		foreach ( $this->domains as $domain ) {
			$domainValues['ldap.' . $domain] = wfMessage( 'ext.hybridldap.provider-domain-label', [ $domain ] );
		}
		$fields['domain'] = [
			'type' => 'select',
			'options' => $domainValues,
			'value' => $this->domain,
			'label' => wfMessage( 'yourdomainname' ),
			'help' => wfMessage( 'authmanager-domain-help' ),
		];

		return $fields;
	}

	public function describeCredentials(): array {
		return [
			'provider' => wfMessage( 'ext.hybridldap.provider-label' ),
			'account' => wfMessage( 'ext.hybridldap.domain-label', [ $this->domain ] ),
		];
	}

	public function getLDAPDomain(): ?string {
		if ( $this->domain && strpos( $this->domain, 'ldap.' ) === 0 ) {
			return substr( $this->domain, strlen( 'ldap.' ) );
		}
		return null;
	}
}
