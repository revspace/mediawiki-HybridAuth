<?php

namespace MediaWiki\Extension\SimpleLDAPAuth\Lib;

use MWException;

class LDAPException extends MWException {
	/**
	 * @var LDAPClient
	 */
	protected $ldapClient;

	public function __construct( LDAPClient $client, string $message ) {
		parent::__construct( $message );
		$this->ldapClient = $client;
	}
}
