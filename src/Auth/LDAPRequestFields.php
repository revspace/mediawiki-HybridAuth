<?php

namespace MediaWiki\Extension\SimpleLDAPAuth\Auth;

use RawMessage;
use MediaWiki\Auth\AuthManager;

trait LDAPRequestFields {
	/**
	 * @var array
	 */
	protected $domains;

	/**
	 * @var ?string
	 */
	public $domain = null;

	/**
	 * @var ?string
	 */
	public $dn = null;

	public function getLDAPFieldInfo(): array {
		if ( !$this->domains ) {
			return [];
		}

		if ( $this->action === AuthManager::ACTION_LOGIN || $this->action === AuthManager::ACTION_LOGIN_CONTINUE ) {
			$values = [
				'' => new RawMessage( 'Local' )
			];
		} else {
			$values = [];
		}
		foreach ( $this->domains as $domain ) {
			$values['ldap.' . $domain] = new RawMessage( '$1: $2', [ 'LDAP', $domain ] );
		}
		return [
			'domain' => [
				'type' => 'select',
				'options' => $values,
				'value' => $this->domain,
				'label' => wfMessage( 'yourdomainname' ),
				'help' => wfMessage( 'authmanager-domain-help' ),
			]
		];
	}

	public function getLDAPDomain(): ?string {
		if ( $this->domain && strpos( $this->domain, 'ldap.' ) === 0 ) {
			return substr( $this->domain, strlen( 'ldap.' ) );
		}
		return null;
	}
}
