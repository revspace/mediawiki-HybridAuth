<?php

namespace MediaWiki\Extension\HybridAuth;

use User;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserIdentity;
use Wikimedia\Rdbms\ILoadBalancer;

class UserLinkStore {
	const BASETABLE = 'user_link';
	const TABLE = 'ext_hybridauth_' . self::BASETABLE;

	/**
	 * @var ILoadBalancer
	 */
	protected $loadBalancer = null;
	/**
	 * @var bool
	 */
	protected $tableExists;
	/**
	 * @var UserFactory
	 */
	protected $userFactory;

	/**
	 * @param ILoadBalancer $loadBalancer to use
	 */
	public function __construct( ILoadBalancer $loadBalancer, UserFactory $userFactory ) {
		$this->loadBalancer = $loadBalancer;
		$this->userFactory = $userFactory;
		$this->tableExists = $this->loadBalancer
			->getConnection( DB_REPLICA )
			->tableExists( static::TABLE );
	}

	/**
	 * @param  string $domain to get user for
	 * @param  string $dn     to get user for
	 * @return User|null
	 */
	public function getUserForProvider( string $domain, string $id ): ?User {
		if ( !$this->tableExists ) {
			return null;
		}
		$dbr = $this->loadBalancer->getConnection( DB_REPLICA );
		$row = $dbr->newSelectQueryBuilder()
			->from( static::TABLE )
			->field( 'user_id' )
			->where( [ 'domain' => $domain, 'provider_id' => $id ] )
			->fetchRow();
		return $row ? $this->userFactory->newFromId( $row->user_id ) : null;
	}

	/**
	 * @param  UserIdentity $user     User get ID for
	 * @param  string       $domain   Domain in which to find ID
	 * @return string|null
	 */
	public function getProviderIDForUser( UserIdentity $user, string $domain ): ?string {
		if ( !$this->tableExists || !$user->isRegistered() ) {
			return null;
		}
		$dbr = $this->loadBalancer->getConnection( DB_REPLICA );
		$row = $dbr->newSelectQueryBuilder()
			->from( static::TABLE )
			->field( 'provider_id ')
			->where( [ 'user_id' => $user->getId(), 'domain' => $domain ] )
			->fetchRow();
		return $row ? $row->provider_id : null;
	}

	/**
	 * @param  UserIdentity $user   User to get linked domains for
	 * @return array
	 */
	public function getDomainsForUser( UserIdentity $user ): array {
		if ( !$this->tableExists || !$user->isRegistered() ) {
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
		if ( !$this->tableExists || !$user->isRegistered() ) {
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
	 * @param string $id          Provider ID to link
	 * @return bool Whether a link was overwritten
	 */
	public function linkUser( UserIdentity $user, string $domain, string $id ): bool {
		$hadLink = $this->unlinkUser( $user, $domain );
		$userId = $user->getId();
		if ( $userId != 0 ) {
			$dbw = $this->loadBalancer->getConnection( DB_PRIMARY );
			return $dbw->insert(
				static::TABLE,
				[
					'user_id' => $userId,
					'domain' => $domain,
					'provider_id' => $id,
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
	 * @param string $dn            Provider ID to unlink
	 * @return bool Whether or not a link was present
	 */
	public function unlinkProvider( string $domain, string $id ): bool {
		$dbw = $this->loadBalancer->getConnection( DB_PRIMARY );
		$dbw->delete(
			static::TABLE,
			[ 'domain' => $domain, 'provider_id' => $id ],
			__METHOD__
		);
		return $dbw->affectedRows() > 0;
	}
}
