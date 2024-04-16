<?php

namespace MediaWiki\Extension\HybridAuth\Auth;

use RawMessage;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\AuthenticationRequest;

class AttrRequest extends AuthenticationRequest {
	public function __construct ( string $domain, string $providerDesc, string $providerUserID, array $attrFields, ?array $authFields = [] ) {
		$this->hybridAuthDomain = $domain;
		$this->hybridAuthProviderDesc = $providerDesc;
		$this->hybridAuthProviderUserID = $providerUserID;
		$this->hybridAuthAttrFields = $attrFields;
		$this->hybridAuthAuthFields = $authFields ?? [];
	}

	public function getUniqueId(): string {
		return "HybridAuth:AttrRequest:" . $this->getHybridDomain();
	}

	public function getFieldInfo(): array {
		return array_merge( $this->hybridAuthAuthFields, $this->hybridAuthAttrFields );
	}

	public function describeCredentials(): array {
		return [
			'provider' => wfMessage( 'ext.hybridauth.provider-label', [ $this->hybridAuthProviderDesc ] ),
			'account' => wfMessage( 'ext.hybridauth.account-label', [
				$this->hybridAuthDomain, $this->hybridAuthProviderUserID,
			] ),
		];
	}

	public function getHybridDomain(): string {
		return $this->hybridAuthDomain;
	}

	public function getHybridProviderUserID(): string {
		return $this->hybridAuthProviderUserID;
	}

	public function getHybridAuthenticationValues(): array {
		$values = [];
		foreach ( $this->hybridAuthAuthFields as $name => $desc ) {
			if ( isset( $this->$name ) ) {
				$values[$name] = $this->$name;
			}
		}
		return $values;
	}

	public function getHybridAttributeValues(): array {
		$values = [];
		foreach ( $this->hybridAuthAttrFields as $name => $desc ) {
			if ( isset( $this->$name ) ) {
				$values[$name] = $this->$name;
			}
		}
		return $values;
	}
}
