CREATE TABLE /*_*/ext_hybridauth_user_link (
	-- Domain
	domain varchar(255) not null,

	-- Provider ID
	provider_id varchar(255) not null,

	-- User to which this provider ID belongs
	user_id int not null

) /*$wgDBTableOptions*/;

CREATE INDEX /*i*/user_id on /*_*/ext_hybridauth_user_link (user_id);
CREATE INDEX /*i*/link on /*_*/ext_hybridauth_user_link (domain, provider_id);
