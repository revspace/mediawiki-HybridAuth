<?php

namespace MediaWiki\Extension\HybridLDAPAuth\Api;

use ApiBase;
use ApiMain;
use MediaWiki\Extension\HybridLDAPAuth\LDAPAuthManager;

abstract class Base extends ApiBase {
	public function __construct( ApiMain $mainModule, $moduleName ) {
		parent::__construct( $mainModule, $moduleName );

		$services = \MediaWiki\MediaWikiServices::getInstance();
		$this->ldapAuthManager = $services->getService( LDAPAuthManager::SERVICE_NAME );
	}

	public function getAllowedParams(): array {
		return [
			'domain' => [
				ApiBase::PARAM_TYPE => 'string',
				ApiBase::PARAM_REQUIRED => true
			]
		];
	}

	public function getLDAPAuthDomain(): LDAPAuthDomain {
		$params = $this->extractRequestParams();
		$name = $params["domain"];
		$domain = $this->ldapAuthManager->getAuthDomain( $name );
		if ( !$domain ) {
			$this->dieWithError( 'apierror-pagecannotexist' );
		}
		return $domain;
	}
}
