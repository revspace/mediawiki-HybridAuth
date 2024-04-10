<?php

namespace MediaWiki\Extension\SimpleLDAPAuth;

use User;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserIdentity;
use Wikimedia\Rdbms\ILoadBalancer;

class UserLinkStore {
	const BASETABLE = 'link';
	const TABLE = 'ldap_simpleauth_' . self::BASETABLE;

	/**
	 * @var ILoadBalancer
	 */
	protected $loadBalancer = null;

	/**
	 * @param ILoadBalancer $loadBalancer to use
	 */
	public function __construct( ILoadBalancer $loadBalancer ) {
		$this->loadBalancer = $loadBalancer;
	}

	/**
	 * @param  string $domain to get user for
	 * @param  string $dn     to get user for
	 * @return User|null
	 */
	public function getUserForDN( string $domain, string $dn ): ?User {
		$dbr = $this->loadBalancer->getConnection( DB_REPLICA );
		$row = $dbr->newSelectQueryBuilder()
			->from( static::TABLE )
			->field( 'user_id' )
			->where( [ 'domain' => $domain, 'dn' => $dn ] )
			->fetchRow();
		return $row ? UserFactory::newFromId( $row->user_id ) : null;
	}

	/**
	 * @param  User $user    to check link status for
	 * @return bool
	 */
	public function isUserLinked( User $user ): bool {
		if ( !$user->isRegistered() ) {
			return false;
		}
		$dbr = $this->loadBalancer->getConnection( DB_REPLICA );
		$count = $dbr->newSelectQueryBuilder()
			->from( static::TABLE )
			->where( [ 'user_id' => $user->getId() ] )
			->fetchRowCount();
		return $count > 0;
	}

	/**
	 * @param  User $user     to get DN for
	 * @param  string $domain to get DN for
	 * @return string|null
	 */
	public function getDNForUser( User $user, string $domain ): ?string {
		if (!$user->isRegistered()) {
			return null;
		}
		$dbr = $this->loadBalancer->getConnection( DB_REPLICA );
		$row = $dbr->newSelectQueryBuilder()
			->from( static::TABLE )
			->field( 'dn ')
			->where( [ 'user_id' => $user->getId(), 'domain' => $domain ] )
			->fetchRow();
		return $row ? $row->dn : null;
	}

	/**
	 * @param UserIdentity $user to set
	 * @param string $dn to set user to
	 * @return bool
	 */
	public function setDNForUser( UserIdentity $user, string $domain, string $dn ): bool {
		$this->clearDNForUser( $user );
		$userId = $user->getId();
		if ( $userId != 0 ) {
			$dbw = $this->loadBalancer->getConnection( DB_PRIMARY );
			return $dbw->insert(
				static::TABLE,
				[
					'user_id' => $userId,
					'domain' => $domain,
					'dn' => $dn,
				],
				__METHOD__
			);
		}
		return false;
	}

	/**
	 * @param UserIdentity $user to clear
	 * @return bool
	 */
	public function clearDNForUser( $user ) {
		$userId = $user->getId();
		if ( $userId != 0 ) {
                        $dbw = $this->loadBalancer->getConnection( DB_PRIMARY );
			$dbw->delete(
				static::TABLE,
				[ 'user_id' => $userId ],
				__METHOD__
			);
			return $dbw->affectedRows() > 0;
		}
		return false;
	}
}
