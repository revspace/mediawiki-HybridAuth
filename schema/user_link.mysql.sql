CREATE TABLE /*_*/ext_hybridldap_user_link (
	-- LDAP domain
	domain varchar(255) not null,

	-- LDAP DN
	dn varchar(255) not null,

	-- User to which this DN belongs
	user_id int not null

) /*$wgDBTableOptions*/;

CREATE INDEX /*i*/user_id on /*_*/ext_hybridldap_user_link (user_id);
CREATE INDEX /*i*/link on /*_*/ext_hybridldap_user_link (domain, dn);
