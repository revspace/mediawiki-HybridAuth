<?php

namespace MediaWiki\Extension\HybridAuth\Api;

use ApiBase;
use ApiMain;
use MediaWiki\Extension\HybridAuth\HybridAuthManager;

abstract class Base extends ApiBase {
	public function __construct( ApiMain $mainModule, $moduleName ) {
		parent::__construct( $mainModule, $moduleName );

		$services = \MediaWiki\MediaWikiServices::getInstance();
		$this->hybridAuthManager = $services->getService( HybridAuthManager::SERVICE_NAME );
	}

	public function getAllowedParams(): array {
		return [
			'domain' => [
				ApiBase::PARAM_TYPE => 'string',
				ApiBase::PARAM_REQUIRED => true
			]
		];
	}

	public function getHybridAuthDomain(): HybridAuthDomain {
		$params = $this->extractRequestParams();
		$name = $params["domain"];
		$domain = $this->hybridAuthManager->getAuthDomain( $name );
		if ( !$domain ) {
			$this->dieWithError( 'apierror-pagecannotexist' );
		}
		return $domain;
	}
}
