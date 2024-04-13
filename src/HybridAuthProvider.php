<?php

namespace MediaWiki\Extension\HybridLDAPAuth;

use Config;
use User;
use MediaWiki\User\UserIdentity;

abstract class HybridAuthProvider {
	public const USERATTR_USERNAME = 'name';
	public const USERATTR_EMAIL = 'email';
	public const USERATTR_REALNAME = 'realname';

	public abstract function getDomainDescription(): string;

	public abstract function getAuthenticationFields(): array;
	public abstract function authenticate( array $values, string &$errorMessage ): ?string;

	public abstract function mapUserAttribute( string $attr ): ?string;
	public abstract function getProviderUserAttribute( string $providerUserID, string $attr ): ?string;
}
