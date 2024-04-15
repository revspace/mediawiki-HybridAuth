<?php

namespace MediaWiki\Extension\HybridAuth\Auth;

use RawMessage;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\AuthenticationRequest;

class AuthRequest extends AuthenticationRequest {
	public function __construct ( ?string $domain, ?string $desc, array $fields, bool $continue = false, bool $alone = false ) {
		$this->hybridAuthDomain = $domain;
		$this->hybridAuthProviderDesc = $desc;
		$this->hybridAuthFields = $fields;
		$this->hybridAuthContinue = $continue;
		$this->hybridAuthAlone = $alone;
		$this->domain = null;
	}

	public function getUniqueId(): string {
		return "HybridAuth:AuthRequest:" . $this->getDomain();
	}

	public function getFieldInfo(): array {
		if ( $this->isLocalDomain() ) {
			$domainLabel = wfMessage( 'ext.hybridauth.local-domain-label' );
		} else {
			$domainLabel = wfMessage( 'ext.hybridauth.provider-domain-label',
				[ $this->hybridAuthDomain, $this->hybridAuthProviderDesc ]
			);
		}

		$fields = [
			'domain' => [
				'label'   => wfMessage( 'yourdomainname' ),
				'help'    => wfMessage( 'authmanager-domain-help' ),
			]
		];
		if ( $this->hybridAuthAlone ) {
			$fields['domain']['type'] = 'hidden';
			$this->selectDomain();
			if ( !$this->isLocalDomain() ) {
				/* Change submit button to clarify login provider */
				$buttonLabelName = $this->hybridAuthContinue ? 'pt-login-continue-button' : 'pt-login-button';
				$fields['hybridauth_submit'] = [
					'type' => 'button',
					'label' => wfMessage(
						'ext.hybridauth.login-button-label',
						[ wfMessage( $buttonLabelName )->text(), $this->hybridAuthProviderDesc ]
					),
				];
			}
		} else {
			$fields['domain']['type'] = 'select';
			$fields['domain']['options'] = [ $this->getDomainFieldValue() => $domainLabel ];
		}
		if ( $this->isDomainSelected() ) {
			$fields['domain']['value'] = $this->getDomainFieldValue();
		}
		foreach ( $this->hybridAuthFields as $key => $value ) {
			$fields[$key] = $value;
		}
		return $fields;
	}

	public function describeCredentials(): array {
		return [
			'provider' => wfMessage( 'ext.hybridauth.provider-label', $this->hybridAuthProviderDesc ),
			'account' => wfMessage( 'ext.hybridauth.domain-label', [ $this->hybridAuthDomain ] ),
		];
	}

	public function isLocalDomain(): bool {
		return !$this->hybridAuthDomain;
	}

	public function isDomainSelected(): bool {
		return $this->domain === $this->getDomainFieldValue();
	}

	public function selectDomain(): void {
		$this->domain = $this->getDomainFieldValue();
	}

	public function getDomain(): ?string {
		return $this->hybridAuthDomain;
	}

	public function getFieldValues(): array {
		$values = [];
		foreach ( $this->hybridAuthFields as $key => $value ) {
			$values[$key] = $this->$key ?? null;
		}
		return $values;
	}

	protected function getDomainFieldValue(): string {
		return $this->isLocalDomain() ? '' : 'hybridauth.' . $this->hybridAuthDomain;
	}
}
