<?php

namespace MediaWiki\Extension\HybridAuth;

use Config;
use ExtensionRegistry;
use HashConfig;
use MediaWiki\Config\ServiceOptions;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserNameUtils;
use Wikimedia\Rdbms\ILoadBalancer;

use MediaWiki\Extension\HybridAuth\Lib\UserFinder;

class HybridAuthManager {
	const OPTION_DOMAINS = 'HybridAuthDomains';
	const OPTION_LOCAL   = 'HybridAuthEnableLocal';

	const SERVICE_NAME = 'HybridAuthManager';
	const SERVICE_OPTIONS = [
		self::OPTION_DOMAINS, self::OPTION_LOCAL,
	];
	const EXTENSION_PROVIDERS = 'HybridAuth';

	const DOMAINOPTION_ENABLED  = 'enabled';
	const DOMAINOPTION_PROVIDER = 'provider';
	const DOMAINOPTION_SPEC     = 'spec';
	const DOMAINOPTION_CONFIG   = 'config';

	/**
	 * @var bool
	 */
	protected $enableLocal;

	/**
	 * @var Config
	 */
	protected $domainOptions;

	/**
	 * @var ObjectFactory
	 */
	protected $objectFactory;

	/**
	 * @var UserFactory
	 */
	protected $userFactory;

	/**
	 * @var UserNameUtils
	 */
	protected $userNameUtils;

	/**
	 * @var UserFinder
	 */
	protected $userFinder;

	/**
	 * @var UserLinkStore
	 */
	protected $userLinkStore;

	/**
	 * @var HybridAuthDomain[]
	 */
	protected $domains;

	public function __construct( ServiceOptions $options, ExtensionRegistry $extensions, $objectFactory, ILoadBalancer $loadBalancer, UserFactory $userFactory, UserNameUtils $userNameUtils ) {
		$options->assertRequiredOptions( static::SERVICE_OPTIONS );
		$this->enableLocal = $options->get( static::OPTION_LOCAL );
		$this->domainOptions = static::resolveDomainOptions( $options->get( static::OPTION_DOMAINS ), $extensions );
		$this->objectFactory = $objectFactory;
		$this->userFactory = $userFactory;
		$this->userNameUtils = $userNameUtils;
		$this->userFinder = new UserFinder( $loadBalancer, $this->userFactory );
		$this->userLinkStore = new UserLinkStore( $loadBalancer );
		$this->domains = [];
	}

	public static function resolveDomainOptions( array $config, ExtensionRegistry $extensions ): array {
		$resolvedConfig = [];
		foreach ( $config as $domain => $options ) {
			if ( isset( $options[static::DOMAINOPTION_ENABLED] ) && $options[static::DOMAINOPTION_ENABLED] === false ) {
				continue;
			}
			if ( !isset( $options[static::DOMAINOPTION_SPEC] ) ) {
				$providerName = $options[static::DOMAINOPTION_PROVIDER] ?? null;
				if ( !$providerName ) {
					continue;
				}
				$providerSpec = $extensions->getAttribute( static::EXTENSION_PROVIDERS . $providerName );
				if ( !$providerSpec ) {
					continue;
				}
				$options[static::DOMAINOPTION_SPEC] = $providerSpec;
			}
			$resolvedConfig[$domain] = $options;
		}
		return $resolvedConfig;
	}

	public function isLocalEnabled(): bool {
		return $this->enableLocal;
	}

	public function getAuthDomain( string $domain ): ?HybridAuthDomain {
		if ( !isset( $this->domains[$domain] ) ) {
			$domainOptions = $this->domainOptions[$domain] ?? null;
			if ( !$domainOptions ) {
				return null;
			}
			$domainConfig = new HashConfig( $domainOptions[static::DOMAINOPTION_CONFIG] ?? [] );
			$provider = $this->objectFactory->createObject( $domainOptions[static::DOMAINOPTION_SPEC], [
				'assertClass' => HybridAuthProvider::class,
				'extraArgs' => [$domain, $domainConfig],
			]);
			$this->domains[$domain] = new HybridAuthDomain( $domain, new HashConfig( $domainOptions ), $provider, $this->userFactory, $this->userNameUtils, $this->userFinder, $this->userLinkStore );
		}
		return $this->domains[$domain];
	}

	public function getAllDomains( ?Config $config = null ): array {
		return array_keys( $this->domainOptions );
	}

	public function getUserDomains( UserIdentity $user ): array {
		return $this->userLinkStore->getDomainsForUser( $user );
	}

	public function getUserDomainsByName( string $username ): array {
		$user = $this->userFactory->newFromName( $username );
		return $user ? $this->getUserDomains( $user ) : [];
	}
}
