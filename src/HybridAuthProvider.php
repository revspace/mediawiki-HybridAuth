<?php

namespace MediaWiki\Extension\HybridAuth;

use Config;
use Message;
use User;
use MediaWiki\User\UserIdentity;

abstract class HybridAuthProvider {
	public const USERATTR_NAME = 'name';
	public const USERATTR_EMAIL = 'email';
	public const USERATTR_REALNAME = 'realname';

	public abstract function getDescription(): string;
	public abstract function getAuthenticationFields( ?string $providerUserID = null ): array;
	public abstract function getAttributeFields( string $providerUserID ): array;
	public abstract function mapUserAttribute( string $attr ): ?string;

	public abstract function authenticate( array $values, ?Message &$errorMessage ): ?HybridAuthSession;
	public abstract function canSudo( string $providerUserID ): bool;
	public abstract function sudo( string $providerUserID, ?Message &$errorMessage ): ?HybridAuthSession;
}
