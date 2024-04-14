<?php

namespace MediaWiki\Extension\HybridAuth;

use Config;
use User;
use MediaWiki\User\UserIdentity;

abstract class HybridAuthSession{
	public abstract function getUserID(): ?string;
	public abstract function getUserAttributes( string $attr ): ?array;
	public abstract function setUserAttributes( string $attr, ?array $values ): bool;
}
