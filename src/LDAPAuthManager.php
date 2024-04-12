<?php

namespace MediaWiki\Extension\HybridLDAPAuth;

use Config;
use HashConfig;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserNameUtils;
use Wikimedia\Rdbms\ILoadBalancer;

class LDAPAuthManager {
	const SERVICE_NAME = 'HybridLDAPAuth.LDAPAuthManager';

	/**
	 * @var ILoadBalancer
	 */
	protected $loadBalancer;

	/**
	 * @var UserFactory
	 */
	protected $userFactory;

	/**
	 * @var UserNameUtils
	 */
	protected $userNameUtils;

	/**
	 * @var UserLinkStore
	 */
	protected $linkStore;

	/**
	 * @var LDAPAuthDomain[]
	 */
	protected $domains;

	public function __construct( ILoadBalancer $loadBalancer, UserFactory $userFactory, UserNameUtils $userNameUtils ) {
		$this->loadBalancer = $loadBalancer;
		$this->userFactory = $userFactory;
		$this->userNameUtils = $userNameUtils;
		$this->linkStore = new UserLinkStore( $this->loadBalancer );
		$this->domains = [];
	}

	private function getDomainConfig(): array {
		global $LDAPAuthProviderDomains;
		return $LDAPAuthProviderDomains;
	}

	public function getAuthDomain( string $domain, ?Config $config = null ): ?LDAPAuthDomain {
		$arrConfig = $this->getDomainConfig()[$domain] ?? null;
		if ( !$arrConfig ) {
			return null;
		}
		$config = new HashConfig( $arrConfig );
		if ( !isset( $this->domains[$domain] ) ) {
			$this->domains[$domain] = new LDAPAuthDomain( $domain, $config, $this->loadBalancer, $this->userFactory, $this->userNameUtils, $this->linkStore );
		}
		return $this->domains[$domain];
	}

	public function getAllDomains( ?Config $config = null ): array {
		return array_keys( $this->getDomainConfig() );
	}

	public function getUserDomains( UserIdentity $user ): array {
		return $this->linkStore->getDomainsForUser( $user );
	}

	public function getUserDomainsByName( string $username ): array {
		$user = $this->userFactory->newFromName( $username );
		return $user ? $this->getUserDomains( $user ) : [];
	}
}
