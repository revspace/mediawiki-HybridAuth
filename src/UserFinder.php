<?php

namespace MediaWiki\Extension\SimpleLDAPAuth;

use User;
use MediaWiki\User\UserFactory;
use Wikimedia\Rdbms\ILoadBalancer;

class UserFinder {
	/**
	 * @var ILoadBalancer
	 */
	protected $loadbalancer;

	/**
	 * @var UserFactory
	 */
	protected $userFactory;

	/**
	 * @param ILoadBalancer $loadBalancer to use
	 * @param UserFactory   $userFactory  to use
	 */
	public function __construct( ILoadBalancer $loadbalancer, UserFactory $userFactory ): void {
		$this->loadbalancer = $loadbalancer;
		$this->userFactory = $userFactory;
	}

	/**
	 * @return UserFactory
	 */
	public function getUserFactory(): UserFactory {
		return $this->userFactory;
	}

	/**
	 * @param string $user  to get user from
	 * @return User|null
	 */
	public function getUserByName( string $name ): User|null {
		$user = $this->userFactory->newFromName( $username );
		return $user->isRegistered() ? $user : null;
	}

	/**
	 * @param string $email to get user from
	 * @return User|null
	 */
	public function getUserByEmail( string $email ): User|null {
		return $this->getUserBy( 'user_email', $email );
	}

	/**
	 * @param string $email to get user from
	 * @return User|null
	 */
	public function getUserByRealName( string $realname ): User|null {
		return $this->getUserBy( 'user_real_name', $realname );
	}

	protected function getUserBy( string $field, string $value ): User|null {
		$dbr = $this->loadBalancer->getConnection( DB_REPLICA );
		$userRow = $dbr->selectRow(
		    'user',
		    [ 'user_id' ],
		    [ $field => $value ],
		    __METHOD__ );
		return $userRow ? $this->userFactory->newFromId( $userRow->user_id ) : null;
	}
}

