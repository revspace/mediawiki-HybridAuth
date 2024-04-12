<?php

namespace MediaWiki\Extension\SimpleLDAPAuth\Api;

use ApiBase;

class Unlink extends Base {
	public function getAllowedParams(): array {
		$params = parent::getAllowedParams();
		$params["dn"] = [
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
		$this->checkUserRightsAny( 'ext.simpleldapauth.link' );

		$params = $this->extractRequestParams();
		$dn = $params["dn"];

		$ldapAuthDomain = $this->getLDAPAuthDomain();
		$ldapAuthDomain->unlinkUserByDN( $dn );

		$res = [ 'ok' => true ];
		$this->getResult()->addValue( null, $this->getModuleName(), $res  );
	}
}
