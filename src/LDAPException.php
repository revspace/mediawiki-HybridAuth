<?php

namespace MediaWiki\Extension\SimpleLDAPAuth;

use MWException;

class LDAPException extends MWException {
	/**
	 * @var LDAPClient
	 */
	protected LDAPClient $ldapClient;

	public function __construct( LDAPClient $client, string $message ) {
		parent::__construct( $message );
		$this->ldapClient = $client;
	}
}
