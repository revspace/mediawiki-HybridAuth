<?php

namespace MediaWiki\Extension\SimpleLDAPAuth\Auth;

use RawMessage;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\PasswordAuthenticationRequest;
use MediaWiki\Extension\SimpleLDAPAuth\LDAPAuthManager;

class LDAPAuthRequest extends PasswordAuthenticationRequest {
	public function __construct ( array $domains ) {
		$this->domains = $domains;
		$this->domain = null;
	}

	public function getFieldInfo(): array {
		if ( !$this->domains ) {
			return [];
		}

		$fields = parent::getFieldInfo();

		$domainValues = [];
		if ( $this->action === AuthManager::ACTION_LOGIN || $this->action === AuthManager::ACTION_LOGIN_CONTINUE ) {
			$domainValues[''] = new RawMessage( 'Local' );
		}
		foreach ( $this->domains as $domain ) {
			$domainValues['ldap.' . $domain] = wfMessage( 'ext.simpleldapauth.form.domain-label', [ $domain ] );
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
			'provider' => new RawMessage( '$1', [ 'LDAP' ] ),
			'account' => new RawMessage( '$1', [ $this->domain ] ),
		];
	}

	public function getLDAPDomain(): ?string {
		if ( $this->domain && strpos( $this->domain, 'ldap.' ) === 0 ) {
			return substr( $this->domain, strlen( 'ldap.' ) );
		}
		return null;
	}
}
