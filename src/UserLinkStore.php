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
	 * @param  UserIdentity $user     User get DN for
	 * @param  string       $domain   Domain in which to find DN
	 * @return string|null
	 */
	public function getDNForUser( UserIdentity $user, string $domain ): ?string {
		if ( !$user->isRegistered() ) {
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
	 * @param  UserIdentity $user   User to get linked domains for
	 * @return array
	 */
	public function getDomainsForUser( UserIdentity $user ): array {
		if ( !$user->isRegistered() ) {
			return [];
		}

		$dbr = $this->loadBalancer->getConnection( DB_REPLICA );
		return $dbr->newSelectQueryBuilder()
			->from( static::TABLE )
			->field( 'domain ')
			->where( [ 'user_id' => $user->getId() ] )
			->fetchFieldValues();
	}

	/**
	 * @param  UserIdentity $user    User to check link for
	 * @param  string $domain        Domain in which to check link
	 * @return bool Whether user is linked in domain
	 */
	public function isUserLinked( User $user, string $domain ): bool {
		if ( !$user->isRegistered() ) {
			return false;
		}
		$dbr = $this->loadBalancer->getConnection( DB_REPLICA );
		$count = $dbr->newSelectQueryBuilder()
			->from( static::TABLE )
			->where( [ 'user_id' => $user->getId(), 'domain' => $domain  ] )
			->fetchRowCount();
		return $count > 0;
	}

	/**
	 * @param UserIdentity $user  User to link
	 * @param string $domain      Domain to link in
	 * @param string $dn          DN to link
	 * @return bool Whether a link was overwritten
	 */
	public function linkUser( UserIdentity $user, string $domain, string $dn ): bool {
		$hadLink = $this->unlinkUser( $user, $domain );
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
		return $hadLink;
	}

	/**
	 * @param UserIdentity $user    User to unlink 
	 * @param string $domain        Domain to unlink in
	 * @return bool Whether or not a link was present
	 */
	public function unlinkUser( UserIdentity $user, string $domain ): bool {
		$userId = $user->getId();
		if ( $userId != 0 ) {
			$dbw = $this->loadBalancer->getConnection( DB_PRIMARY );
			$dbw->delete(
				static::TABLE,
				[ 'user_id' => $userId, 'domain' => $domain ],
				__METHOD__
			);
			return $dbw->affectedRows() > 0;
		}
		return false;
	}

	/**
	 * @param string $domain        Domain to unlink in
	 * @param string $dn            DN to unlink
	 * @return bool Whether or not a link was present
	 */
	public function unlinkDN( string $domain, string $dn ): bool {
		$dbw = $this->loadBalancer->getConnection( DB_PRIMARY );
		$dbw->delete(
			static::TABLE,
			[ 'domain' => $domain, 'dn' => $dn ],
			__METHOD__
		);
		return $dbw->affectedRows() > 0;
	}
}
