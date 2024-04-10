<?php

namespace MediaWiki\Extension\SimpleLDAPAuth\Api;

use ApiBase;
use ApiMain;
use MediaWiki\Extension\PluggableAuth\PluggableAuthFactory;
use MediaWiki\Extension\SimpleLDAPAuth\LDAPAuthManager;
use MediaWiki\Extension\SimpleLDAPAuth\LDAPGroupMapper;
use MediaWiki\Extension\SimpleLDAPAuth\LDAPUserMapper;
use MediaWiki\Extension\SimpleLDAPAuth\UserLinkStore;

abstract class Base extends ApiBase {
	public function __construct( ApiMain $mainModule, $moduleName ) {
		parent::__construct( $mainModule, $moduleName );
		$services = \MediaWiki\MediaWikiServices::getInstance();
		$loadBalancer = $services->getDBLoadBalancer();
		$userFactory = $services->getUserFactory();
		$this->authFactory = $services->getService( 'PluggableAuthFactory' );
		$this->linkStore = new UserLinkStore( $loadBalancer );
		$this->ldapAuthManager = new LDAPAuthManager( $loadBalancer, $userFactory );
	}

	public function getAllowedParams(): array {
		return [
			'domain' => [
				ApiBase::PARAM_TYPE => 'string',
				ApiBase::PARAM_REQUIRED => true
			]
		];
	}

	public function getLDAPParams(): array {
		$params = $this->extractRequestParams();
		$name = $params["domain"];
		$config = $this->authFactory->getConfig()[$name] ?? null;
		if ( !$config ) {
			$this->dieWithError( 'apierror-pagecannotexist' );
		}
		return [ $name, $config ];
	}

	public function getDomain(): string {
		[$name, $config] = $this->getLDAPParams();
		return $this->ldapAuthManager->getDomain( $name, $config );
	}

	public function getUserMapper(): LDAPUserMapper {
		[$name, $config] = $this->getLDAPParams();
		return $this->ldapAuthManager->getUserMapper( $name, $config );
	}

	public function getGroupMapper(): LDAPGroupMapper {
		[$name, $config] = $this->getLDAPParams();
		return $this->ldapAuthManager->getGroupMapper( $name, $config );
	}
}
