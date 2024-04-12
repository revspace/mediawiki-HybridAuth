<?php

namespace MediaWiki\Extension\HybridLDAPAuth;

use DatabaseUpdater;

class Hooks {
	const TABLES = [UserLinkStore::BASETABLE];

	/**
	 * @param DatabaseUpdater $updater object
	 * @return bool
	 */
	public static function onLoadExtensionSchemaUpdates( DatabaseUpdater $updater ) {
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
				"ext_hybridldap_{$table}", $schemaFile
			);
			break;
		}
		return true;
	}
}

