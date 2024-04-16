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
		$this->hybridAuthUsername = null;
		$this->domain = null;
	}

	public function getUniqueId(): string {
		return "HybridAuth:AuthRequest:" . $this->getHybridDomain();
	}

	public function getFieldInfo(): array {
		if ( $this->isLocalHybridDomain() ) {
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
			$this->selectHybridDomain();
			if ( !$this->isLocalHybridDomain() ) {
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
			$fields['domain']['options'] = [ $this->getHybridDomainFieldValue() => $domainLabel ];
		}
		if ( $this->isHybridDomainSelected() ) {
			$fields['domain']['value'] = $this->getHybridDomainFieldValue();
		}
		foreach ( $this->hybridAuthFields as $key => $value ) {
			/* Work around MediaWiki bug that equates a `username` field to other unwanted stuff */
			if ( $this->action === AuthManager::ACTION_LINK && $key === 'username' ) {
				$key = 'hybridauth_username';
			}
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

	public function getHybridUsername(): ?string {
		return $this->hybridAuthUsername;
	}

	public function isLocalHybridDomain(): bool {
		return !$this->hybridAuthDomain;
	}

	public function isHybridDomainSelected(): bool {
		return $this->domain === $this->getHybridDomainFieldValue();
	}

	public function selectHybridDomain(): void {
		$this->domain = $this->getHybridDomainFieldValue();
	}

	public function getHybridDomain(): ?string {
		return $this->hybridAuthDomain;
	}

	public function getHybridAuthenticationValues(): array {
		$values = [];
		foreach ( $this->hybridAuthFields as $key => $value ) {
			/* Undo above workaround */
			if ( $this->action === AuthManager::ACTION_LINK && $key === 'username' ) {
				$attr = 'hybridauth_username';
			} else {
				$attr = $key;
			}
			$values[$key] = $this->$attr ?? null;
		}
		return $values;
	}

	protected function getHybridDomainFieldValue(): string {
		return $this->isLocalHybridDomain() ? '' : 'hybridauth.' . $this->hybridAuthDomain;
	}
}
