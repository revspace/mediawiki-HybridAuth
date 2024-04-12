<?php

namespace MediaWiki\Extension\SimpleLDAPAuth;

use Config;
use User;
use Wikimedia\Rdbms\ILoadBalancer;

class LDAPGroupMapper {
	const CONFIG_BASE_DN     = 'base_dn';
	const CONFIG_BASE_RDN    = 'base_rdn';
	const CONFIG_MEMBER_ATTR = 'member_attr';
	const CONFIG_USER_ATTR   = 'user_attr';

	/**
	 * @var string
	 */
	protected $domain;

	/**
	 * @var Config
	 */
	protected $config;

	/**
	 * @var LDAPUserMapper
	 */
	protected $userMapper;

	public function __construct( string $domain, Config $config, LDAPUserMapper $userMapper ) {
		$this->domain = $domain;
		$this->config = $config;
		$this->userMapper = $userMapper;
	}

	protected function getConfig( string $key, $default = null ) {
		return $this->config->has( $key ) ? $this->config->get( $key ) : $default;
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
