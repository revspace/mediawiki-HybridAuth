<?php

namespace MediaWiki\Extension\HybridAuth\Api;

use ApiBase;

class Unlink extends Base {
	public function getAllowedParams(): array {
		$params = parent::getAllowedParams();
		$params["id"] = [
			ApiBase::PARAM_TYPE => 'string',
			ApiBase::PARAM_REQUIRED => true
		];
		return $params;
	}

	public function needsToken( ): string {
		return 'csrf';
	}

	public function isWriteMode( ): bool {
		return true;
	}

	public function execute( ): void {
		$this->checkUserRightsAny( 'ext.hybridauth.link' );

		$params = $this->extractRequestParams();
		$id = $params["id"];

		$hybridAuthDomain = $this->getHybridAuthDomain();
		$hybridAuthDomain->unlinkProviderUser( $id );

		$res = [ 'ok' => true ];
		$this->getResult()->addValue( null, $this->getModuleName(), $res  );
	}
}
