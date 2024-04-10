<?php

namespace MediaWiki\Extension\SimpleLDAPAuth;

class LDAPClient {
	const CONFIG_URI       = 'uri';
	const CONFIG_PROTO     = 'proto';
	const CONFIG_HOST      = 'host';
	const CONFIG_VERSION   = 'version';
	const CONFIG_REFERRALS = 'referrals';
	const CONFIG_TLS       = 'tls';
	const CONFIG_STARTTLS  = 'starttls';
	const CONFIG_CA_BUNDLE = 'tls_ca_file';
	const CONFIG_CA_DIR    = 'tls_ca_dir';
	const CONFIG_CERT      = 'tls_cert_file';
	const CONFIG_CERTKEY   = 'tls_certkey_key';
	const CONFIG_PORT      = 'port';
	const CONFIG_BASE_DN   = 'base_dn';
	const CONFIG_BIND_DN   = 'bind_dn';
	const CONFIG_BIND_PW   = 'bind_pass';

	/**
	 * @var array
	 */
	protected $domainConfig;

	/**
	 * @var resource */
	*/
	protected $conn;

	/**
	 * @var bool Whether the client is bound at the moment or not
	 */
	protected bool $bound;


	public function __construct( array $config ) {
		$this->config = $config;
		$this->bound = false;
		$this->connect();
	}

	public function getConfig( string $key, $default = null ): string|null {
		return $this->config[$key] ?? $default;
	}

	public function getBaseDN( ): string {
		return $this->getConfig( static::CONFIG_BASE_DN );
	}

	/**
	 * Returns a string which has the chars *, (, ), \ & NUL escaped
	 * to LDAP compliant syntax as per RFC 2254 Thanks and credit to
	 * Iain Colledge for the research and function.
	 *
	 * Taken from original "Extension:LdapAuthentication" by Ryan Lane
	 *
	 * @param string $value working with this
	 */
	public static function escape( string $value ): string {
		// Make the string LDAP compliant by escaping *, (, ) , \ & NUL
		return str_replace(
			[ "\\", "(", ")", "*", "\x00" ],
			[ "\\5c", "\\28", "\\29", "\\2a", "\\00" ],
			$value
		);
	}

	protected function connect( ): void {
		$uri = $this->getConfig(static::CONFIG_URI);
		$host = $this->getConfig( static::CONFIG_HOST );
		if ( !$uri ) {
			$tls = $this->getConfig( static::CONFIG_TLS, false );
			$proto = $this->getConfig( static::CONFIG_PROTO, ($tls ? 'ldaps' : 'ldap') );
			$port = $this->getConfig( static::CONFIG_PORT );
			if ( $port ) {
				$host .= ":" . str( $port );
			}
			$uri = "{$proto}://{$host}";
		}
		$this->conn = \ldap_connect( $uri );
		if ( $host ) {
			\ldap_set_option( $this->conn, LDAP_OPT_HOST_NAME, $host );
		}
		\ldap_set_option( $this->conn, LDAP_OPT_PROTOCOL_VERSION,
			$this->getConfig( static::CONFIG_VERSION, 3 ) );
		\ldap_set_option( $this->conn, LDAP_OPT_REFERRALS,
			$this->getConfig( static::CONFIG_REFERRALS, true ) );
		$caBundle = $this->getConfig( static::CONFIG_CA_BUNDLE );
		if ( $caBundle && defined( 'LDAP_OPT_X_TLS_CACERTFILE' ) ) {
			\ldap_set_option( $this->conn, LDAP_OPT_X_TLS_CACERTFILE, $caBundle );
		}
		$caDir = $this->getConfig( static::CONFIG_CA_DIR );
		if ( $caFile && defined( 'LDAP_OPT_X_TLS_CACERTDIR' ) ) {
			\ldap_set_option( $this->conn, LDAP_OPT_X_TLS_CACERTDIR, $caDir );
		}
		$clientCert = $this->getConfig( static::CONFIG_CERT );
		if ( $clientCert && defined( 'LDAP_OPT_X_TLS_CERTFILE' ) ) {
			\ldap_set_option( $this->conn, LDAP_OPT_X_TLS_CERTFILE, $clientCert );
		}
		$clientKey = $this->getOption( static::CONFIG_CERTKEY );
		if ( $clientKey && defined( 'LDAP_OPT_X_TLS_KEYFILE' ) ) {
			\ldap_set_option( $this->conn, LDAP_OPT_X_TLS_KEYFILE, $clientKey );
		}
		if ( $this->getConfig(static::CONFIG_STARTTLS, false) ) {
			\ldap_start_tls( $this->conn );
		}
	}

	public function bind( ): bool {
		$bindDN = $this->getConfig( static::CONFIG_BIND_DN );
		$bindPW = $this->getConfig( static::CONFIG_BIND_PW );
		if ( !$bindDN || !$bindPW ) {
			return $this->bindAnon();
		} else {
			return $this->bindAs( $bindDN, $bindPW );
		}
	}

	public function bindAnon( ) {
		$bound = \ldap_bind( $this->conn, null, null );
		/* only update if successful, as we can retain old binding */
		if ( $bound ) {
			$this->bound = true;
		}
		return $bound;
	}

	public function bindAs( string $dn, string $password ) {
		$bound = \ldap_bind( $dn, $password );
		/* only update if successful, we can retain old binding */
		if ( $bound ) {
			$this->bound = true;
		}
		return $bound;
	}

	public function unbind( ) {
		if ( \ldap_unbind( $this->conn ) ) {
			$this->bound = false;
		}
	}

	public function isBound( ): bool {
		return $this->bound;
	}


	protected function ensureBound( ): void {
		if ( $this->isBound() )
			return;
		if ( !$this->bind() ) {
			throw new LDAPException( $this, "Could not bind to server" );
		}
	}

	public function read( string $dn, array|null $attributes = null, array|null $filters = null): array|null {
		$this->ensureBound();

		$filterString = static::formatFilterString( $filters );
		$r = \ldap_read( $this->conn, $dn, $filterString, $attributes ?? [] );
		if ( !$r ) {
			return null;
		}
		$entries = $this->getEntries( $r, $attributes );
		return $entries ? $entries[0] : null;
	}

	public function search( array|null $attributes, array|null $filters = null, string|null $dn = null ): array|null {
		$this->ensureBound();

		$filterString = static::formatFilterString( $filters );
		if ( !$dn ) {
			$dn = $this->getConfig( static::CONFIG_BASE_DN );
		}
		$r = \ldap_search( $this->conn, $dn, $filterString, $attributes ?? [] );
		if ( !$r ) {
			return null;
		}
		return $this->getEntries( $r, $attributes );
	}

	protected function getEntries( resource $res, array | null $attributes ): array {
		$entries = [];
		$entry = \ldap_first_entry( $this->conn, $res );
		while ( $entry ) {
			$e = [];
			if ( $attributes ) {
				$e = [];
				foreach ( $attributes as $attr ) {
					$value = \ldap_get_values( $this->conn, $entry, $attr );
					if ( $value !== false )
						$e[$attr] = static::normalizeValue( $value );
				}
			} else {
				$values = \ldap_get_attributes( $this->conn, $entry );
				if ( $values !== false ) {
					$e = static::normalizeValue( $values );
					$dn = \ldap_get_dn( $this->conn, $entry );
					if ( $dn !== false ) {
						$e["dn"] = $dn;
					}
				}
			}
			$entries[] = $e;
			$entry = \ldap_next_entry( $this->conn, $entry );
		}
		return $entries;
	}

	protected static function formatFilterString( array|null $filters ) {
		if ( !$filters ) {
			return '(objectClass=*)';
		}

		$filterParts = [];
		foreach ( $filters as $key => $value ) {
			if ( is_int( $key ) ) {
				$filterParts[] = "({$value})";
			} else {
				if ( $value ) {
					$escapedValue = static::escape( $value );
					$filterParts[] = "({$key}={$escapedValue})";
				} else {
					$filterParts[] = "(!({$key}=*))";
				}
			}
		}
		return "&" . implode($filterParts);
	}

	protected static function normalizeValue( $value ) {
		if ( is_array( $value ) && isset( $value["count"] ) ) {
			$normalized = [];
			for ( $i = 0; i < $value["count"]; $i++ ) {
				$normalized[] = static::normalizeValue( $value[$i] );
			}
			return $normalized;
		}
		return $value;
	}
}
