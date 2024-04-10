<?php

namespace MediaWiki\Extension\SimpleLDAPAuth;

use User;
use Wikimedia\Rdbms\ILoadBalancer;

class LDAPGroupMapper {
	const CONFIG_BASE_DN     = 'base_dn';
	const CONFIG_BASE_RDN    = 'base_rdn';
	const CONFIG_MEMBER_ATTR = 'member_attr';
	const CONFIG_USER_ATTR   = 'user_attr';

	/**
	 * @var array
	 */
	protected $config;

	/**
	 * @var UserMapper
	 */
	protected UserMapper $userMapper;

	public function __construct( array $config, UserMapper $userMapper ) {
		$this->config = $config;
		$this->userMapper = $userMapper;
	}

	protected function getConfig( string $key, $default = null ) {
		return $this->config[$key] ?? $default;
	}

	/**
	 * Get User base DN
	 *
	 * @return string
	 */
	protected function getGroupBaseDN( ): string {
		$dn = $this->getConfig( static::CONFIG_BASE_DN );
		if ( $dn ) {
			return $dn;
		}

		$rdn = $this->getConfig( static::CONFIG_BASE_RDN );
		$bdn = $this->ldapClient->getBaseDN();
		if ( $bdn ) {
			return $rdn . ',' . $bdn;
		} else {
			return $rdn;
		}
	}
}
