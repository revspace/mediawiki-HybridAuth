CREATE TABLE ext_hybridldap_user_link (
	-- LDAP domain
	domain varchar(255) not null,

	-- LDAP DN
	dn varchar(255) not null,

	-- User to which this DN belongs
	user_id integer not null

) /*$wgDBTableOptions*/;

CREATE INDEX user_id on ext_hybridldap_user_link (user_id);
CREATE INDEX link on ext_hybridldap_user_link (domain, dn);
