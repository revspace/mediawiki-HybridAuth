<?php

namespace MediaWiki\Extension\SimpleLDAPAuth;

use User;
use MediaWiki\User\UserFactory;
use Wikimedia\Rdbms\ILoadBalancer;

class UserFinder {
	/**
	 * @var ILoadBalancer
	 */
	protected $loadBalancer;

	/**
	 * @var UserFactory
	 */
	protected $userFactory;

	/**
	 * @param ILoadBalancer $loadBalancer to use
	 * @param UserFactory   $userFactory  to use
	 */
	public function __construct( ILoadBalancer $loadBalancer, UserFactory $userFactory ) {
		$this->loadBalancer = $loadBalancer;
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
	public function getUserByName( string $name ): ?User {
		return $this->getUserBy( 'user_name', $name );
	}

	/**
	 * @param string $email to get user from
	 * @return User|null
	 */
	public function getUserByEmail( string $email ): ?User {
		return $this->getUserBy( 'user_email', $email );
	}

	/**
	 * @param string $email to get user from
	 * @return User|null
	 */
	public function getUserByRealName( string $realname ): ?User {
		return $this->getUserBy( 'user_real_name', $realname );
	}

	protected function getUserBy( string $field, string $value ): ?User {
		$dbr = $this->loadBalancer->getConnection( DB_REPLICA );
		$userRow = $dbr->newSelectQueryBuilder()
			->from( 'user' )
			->where( "LOWER({$field}) = " . $dbr->addQuotes( strtolower( $value ) ) )
			->field( 'user_id' )
			->fetchRow();
		return $userRow ? $this->userFactory->newFromId( $userRow->user_id ) : null;
	}
}

