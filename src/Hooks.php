<?php

namespace MediaWiki\Extension\HybridAuth;

use MediaWiki\Installer\Hook\LoadExtensionSchemaUpdatesHook;

class Hooks implements LoadExtensionSchemaUpdatesHook {
	const TABLES = [UserLinkStore::BASETABLE];

	public static function onRegistration() {
		global $wgHybridAuthEnableLocal, $wgAuthManagerAutoConfig;

		if ( !$wgHybridAuthEnableLocal ) {
			/* Disable password providers if local login is disabled */
			$primaryProviders = $wgAuthManagerAutoConfig['primaryauth'] ?? [];
			foreach ( $primaryProviders as $key => $provider) {
				$providerClass = $provider['class'] ?? null;
				if ( !$providerClass ) {
					continue;
				}
				if ( strstr( $providerClass, 'MediaWiki\\Auth\\' ) !== $providerClass ) {
					continue;
				}
				if ( !stristr( $providerClass, 'password' ) ) {
					continue;
				}
				unset( $wgAuthManagerAutoConfig['primaryauth'][$key] );
			}
		}
	}

	/**
	 * @param DatabaseUpdater $updater object
	 * @return bool
	 */
	public function onLoadExtensionSchemaUpdates( $updater ) {
		$schemaDir = dirname( __DIR__ ) . "/schema";
		foreach ( static::TABLES as $table ) {
			switch ( $updater->getDB()->getType() ) {
				case 'mysql':
				case 'sqlite':
					$schemaFile = "${schemaDir}/{$table}.mysql.sql";
					break;

				case 'postgres':
					$schemaFile = "${schemaDir}/{$table}.postgres.sql";
					break;
				default:
					return false;
			}
			$updater->addExtensionTable(
				"ext_hybridauth_{$table}", $schemaFile
			);
			break;
		}
		return true;
	}
}

