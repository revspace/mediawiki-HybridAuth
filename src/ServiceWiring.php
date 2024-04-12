<?php

namespace MediaWiki\Extension\SimpleLDAPAuth;

use MediaWiki\MediaWikiServices;

return [
	LDAPAuthManager::SERVICE_NAME => function ( MediaWikiServices $services ) : LDAPAuthManager {
		return new LDAPAuthManager(
			$services->getDBLoadBalancer(),
			$services->getUserFactory(),
			$services->getUserNameUtils()
		);
	},
];