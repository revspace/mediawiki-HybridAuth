<?php

namespace MediaWiki\Extension\HybridLDAPAuth\Auth;

use RawMessage;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\AuthenticationRequest;

class AttrRequest extends AuthenticationRequest {
	public function __construct ( string $domain, string $dn, array $attributes = [] ) {
		$this->domain = $domain;
		$this->dn = $dn;
		$this->attributes = [];
	}

	public function getUniqueId(): string {
		return parent::getUniqueId() . ":" . $this->domain;
	}

	public function getFieldInfo(): array {
		$fields = [];
		
		$fields = array_merge( $fields, [
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
		]);
		foreach ( $this->getLDAPAttributes() as $attr => $value ) {
			$label = wfMessage( "ext.hybridldap.attr.$attr-label" );
			if ( !$label->exists() ) {
				$label = wfMessage( 'ext.hybridldap.attr-label', [ $attr ] );
			}
			$help = wfMessage( "ext.hybridldap.attr.$attr-help" );
			if ( !$help->exists() ) {
				$label = wfMessage( 'ext.hybridldap.attr-help', [ $attr ] );
			}
			$attrField = 'ldap_'. $attr;
			$fields[$attrField] = [
				'type' => 'string',
				'label' => $label,
				'help' => $help,
				'value' => $value,
			];
		}

		return $fields;
	}

	public function getLDAPAttributes(): array {
		$values = [];
		foreach ( $this->attributes as $attr => $value ) {
			$attrField = 'ldap_' . $attr;
			$values[$attr] = isset( $this->$attrField ) ? $this->$attrField : $value;
		}
		return $values;
	}

	public function describeCredentials(): array {
		return [
			'provider' => wfMessage( 'ext.hybridldap.provider-label' ),
			'account' => wfMessage( 'ext.hybridldap.account-label', [ $this->domain, $this->dn ] )
		];
	}
}
