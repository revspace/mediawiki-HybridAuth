CREATE TABLE ext_hybridauth_user_link (
	-- Domain
	domain varchar(255) not null,

	-- Provider ID
	provider_id varchar(255) not null,

	-- User to which this ID belongs
	user_id integer not null

) /*$wgDBTableOptions*/;

CREATE INDEX user_id on ext_hybridauth_user_link (user_id);
CREATE INDEX link on ext_hybridauth_user_link (domain, provider_id);
