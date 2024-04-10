<?php

namespace MediaWiki\Extension\SimpleLDAPAuth;

use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserFactory;
use Wikimedia\Rdbms\ILoadBalancer;

class LDAPAuthManager {
	const CONFIG_DOMAIN = 'domain';
	const CONFIG_USER   = 'user';
	const CONFIG_GROUP  = 'group';

	public function __construct( ILoadBalancer $loadBalancer, UserFactory $userFactory ) {
		$this->loadBalancer = $loadBalancer;
		$this->userFactory = $userFactory;
		$this->linkStore = new UserLinkStore( $loadBalancer );
		$this->userMappers = [];
		$this->groupMappers = [];
	}

	public function getUserFactory( ): UserFactory {
		return $this->userFactory;
	}

	public function getLinkStore( ): UserLinkStore {
		return $this->linkStore;
	}

	public function getDomain( $name, $config ): string {
		return $config->get( static::CONFIG_DOMAIN ) ?? $name;
	}

	public function getUserMapper( $name, $config ): LDAPUserMapper {
		$domain = $this->getDomain( $name, $config );
		if ( !isset( $this->userMappers[$domain] ) ) {
			$finder = new UserFinder( $this->loadBalancer, $this->userFactory );
			$client = new LDAPClient( $config );
			$this->userMappers[$domain] = new LDAPUserMapper( $domain, $config->get( static::CONFIG_USER ), $client, $finder, $this->linkStore );
		}
		return $this->userMappers[$domain];
	}

	public function getGroupMapper( $name, $config ): LDAPGroupMapper {
		$domain = $this->getDomain( $name, $config );
		if ( !isset( $this->groupMappers[$domain] ) ) {
			$userMapper = $this->getUserMapper( $name, $config );
			$this->groupMappers[$domain] = new LDAPGroupMapper( $config->get( static::CONFIG_GROUP ), $userMapper );
		}
		return $this->groupMappers[$domain];
	}

	public function linkUser( UserIdentity $user, string $domain, string $dn ): void {
		$this->linkStore->setDNForUser( $user, $domain, $dn );
	}

	public function linkUserID( int $userID, string $domain, string $dn ): void {
		$this->linkUser( $this->userFactory->newFromId( $userID ), $domain, $dn );
	}

	public function unlinkUser( UserIdentity $user ): void {
		$this->linkStore->clearDNForUser( $user );
	}

	public function unlinkUserID( int $userID ): void {
		$this->unlinkUser( $this->userFactory->newFromid( $userID ) );
	}

	public function unlinkUserDN( string $domain, string $dn ): void {
		$this->linkStore->clearUserForDN( $domain, $dn );
	}
}
