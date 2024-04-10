CREATE TABLE /*_*/ldap_simpleauth_link (
	-- LDAP domain
	domain varchar(255) not null,

	-- LDAP DN
	dn varchar(255) not null,

	-- User to which this DN belongs
	user_id int not null

) /*$wgDBTableOptions*/;

CREATE UNIQUE INDEX /*i*/user_id on /*_*/ldap_simpleauth_link (user_id);
CREATE INDEX /*i*/link on /*_*/ldap_simpleauth_link (domain, dn);
