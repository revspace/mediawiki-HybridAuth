<?php

namespace MediaWiki\Extension\SimpleLDAPAuth\Api;

use ApiBase;
use ApiMain;
use MediaWiki\Extension\SimpleLDAPAuth\LDAPAuthManager;
use MediaWiki\Extension\SimpleLDAPAuth\LDAPGroupMapper;
use MediaWiki\Extension\SimpleLDAPAuth\LDAPUserMapper;
use MediaWiki\Extension\SimpleLDAPAuth\UserLinkStore;

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
