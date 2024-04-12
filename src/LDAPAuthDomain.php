<?php

namespace MediaWiki\Extension\HybridLDAPAuth;

use Config;
use HashConfig;
use User;
use MediaWiki\Extension\HybridLDAPAuth\Lib\LDAPClient;
use MediaWiki\Extension\HybridLDAPAuth\Lib\UserFinder;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserNameUtils;
use Wikimedia\Rdbms\ILoadBalancer;


class LDAPAuthDomain {
	const CONFIG_CONNECTION  = 'connection';
	const CONFIG_AUTO_CREATE = 'auto_create';
	const CONFIG_USER        = 'user';
	const CONFIG_GROUP       = 'group';

	/**
	 * @var string
	 */
	protected $domain;

	/**
	 * @var Config
	 */
	protected $config;

	/**
	 * @var UserFactory
	 */
	protected $userFactory;

	/**
	 * @var UserLinkStore
	 */
	protected $linkStore;

	/**
	 * @var LDAPUserMapper
	 */
	protected $userMapper;

	/**
	 * @var LDAPGroupMapper
	 */
	protected $groupMapper;

	public function __construct( string $domain, Config $config, ILoadBalancer $loadBalancer, UserFactory $userFactory, UserNameUtils $userNameUtils, UserLinkStore $linkStore ) {
		$this->domain = $domain;
		$this->config = $config;
		$this->userFactory = $userFactory;
		$this->linkStore = $linkStore;

		$connConfig = new HashConfig( $this->getConfig( static::CONFIG_CONNECTION, [] ) );
		$client = new LDAPClient( $connConfig );

		$finder = new UserFinder( $loadBalancer, $this->userFactory );
		$userConfig = new HashConfig( $this->getConfig( static::CONFIG_USER, [] ) );
		$this->userMapper = new LDAPUserMapper( $this->domain, $userConfig, $userNameUtils, $client, $finder, $this->linkStore );

		$groupConfig = new HashConfig( $this->getConfig( static::CONFIG_GROUP, [] ) );
		$this->groupMapper = new LDAPGroupMapper ( $this->domain, $groupConfig, $this->userMapper );
	}

	protected function getConfig( string $key, $default = null ) {
		return $this->config->has( $key ) ? $this->config->get( $key ) : $default;
	}

	public function shouldAutoCreateUser(): bool {
		return $this->userMapper->shouldAutoCreate(
			$this->getConfig( static::CONFIG_AUTO_CREATE, true )
		);
	}

	public function authenticateLDAPUser( string $username, string $password, ?string &$errorMessage ): ?string {
		return $this->userMapper->authenticate( $username, $password, $errorMessage );
	}

	public function hasLDAPUser( string $username ): ?bool {
		return $this->userMapper->exists( $username );
	}

	public function mapUserFromDN( string $dn, ?UserIdentity &$userHint, ?string &$errorMessage ): ?User {
		return $this->userMapper->mapDN( $dn, $userHint, $errorMessage );
	}

	public function getUserByDN( string $dn ): ?User {
		return $this->linkStore->getUserForDN($this->domain, $dn );
	}

	public function getDNByUser( UserIdentity $user ): ?string {
		return $this->linkStore->getDNForUser( $user, $this->domain );
	}

	public function getDNByUserName( string $username ): ?string {
		$user = $this->userFactory->newFromName( $username );
		return $user->isRegistered() ? $this->getDNByUser( $user ) : null;
	}

	public function linkUser( UserIdentity $user, string $dn ): void {
		$this->linkStore->linkUser( $user, $this->domain, $dn );
	}

	public function linkUserByID( int $userID, string $dn ): void {
		$this->linkUser( $this->userFactory->newFromId( $userID ), $dn );
	}

	public function linkUserByName( string $username, string $dn ): void {
		$user = $this->userFactory->newFromName( $username );
		if ( $user->isRegistered() ) {
			$this->linkUser( $user, $dn );
		}
	}

	public function unlinkUser( UserIdentity $user ): void {
		$this->linkStore->unlinkUser( $user, $this->domain );
	}

	public function unlinkUserByID( int $userID ): void {
		$this->unlinkUser( $this->userFactory->newFromId( $userID ) );
	}

	public function unlinkUserByName( string $username ): void {
		$user = $this->userFactory->newFromName( $username );
		if ( $user->isRegistered() ) {
			$this->unlinkUser( $user );
		}
	}

	public function unlinkDN( string $dn ): void {
		$this->linkStore->unlinkDN( $this->domain, $dn );
	}
}
