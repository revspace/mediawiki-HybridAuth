<?php

namespace MediaWiki\Extension\HybridLDAPAuth;

use Config;
use User;
use MediaWiki\Logger\LoggerFactory;
use Psr\Log\LoggerInterface;
use Psr\Log\LoggerAwareInterface;
use Wikimedia\Rdbms\ILoadBalancer;

class LDAPGroupMapper implements LoggerAwareInterface {
	const CONFIG_BASE_DN     = 'base_dn';
	const CONFIG_BASE_RDN    = 'base_rdn';
	const CONFIG_MEMBER_ATTR = 'member_attr';
	const CONFIG_USER_ATTR   = 'user_attr';

	/**
	 * @var LoggerInterface
	 */
	protected $logger;

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
		$this->setLogger( LoggerFactory::getInstance( 'HybridLDAPAuth.GroupMapper' ) );
		$this->domain = $domain;
		$this->config = $config;
		$this->userMapper = $userMapper;
	}

	public function setLogger( LoggerInterface $logger ) {
		$this->logger = $logger;
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
