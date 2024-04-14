<?php

namespace MediaWiki\Extension\HybridAuth;

use ExtensionRegistry;
use MediaWiki\Config\ServiceOptions;
use MediaWiki\MediaWikiServices;

return [
	HybridAuthManager::SERVICE_NAME => function ( MediaWikiServices $services ) : HybridAuthManager {
		return new HybridAuthManager(
			new ServiceOptions( HybridAuthManager::SERVICE_OPTIONS, $services->getMainConfig() ),
			ExtensionRegistry::getInstance(),
			$services->getObjectFactory(),
			$services->getDBLoadBalancer(),
			$services->getUserFactory(),
			$services->getUserNameUtils()
		);
	},
];
