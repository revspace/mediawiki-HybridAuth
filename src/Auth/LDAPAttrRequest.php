<?php

namespace MediaWiki\Extension\SimpleLDAPAuth\Auth;

use RawMessage;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\AuthenticationRequest;

class LDAPAttrRequest extends AuthenticationRequest {
	public function __construct ( string $domain, string $dn ) {
		$this->domain = $domain;
		$this->dn = $dn;
	}

	public function getUniqueId(): string {
		return parent::getUniqueId() . ":" . $this->domain;
	}

	public function getFieldInfo(): array {
		return [
			'password' => [
				'type' => 'password',
				'label' => wfMessage( 'newpassword' ),
				'help' => wfMessage( 'authmanager-password-help' ),
				'sensitive' => true,
			],
			'retype' => [
				'type' => 'password',
				'label' => wfMessage( 'retypenew' ),
				'help' => wfMessage( 'authmanager-retype-help' ),
				'sensitive' => true,
			],
		];
	}

	public function describeCredentials(): array {
		return [
			'provider' => new RawMessage( '$1', [ 'LDAP' ] ),
			'account' => new RawMessage( '$1: $2', [ $this->domain, $this->dn ] )
		];
	}
}
