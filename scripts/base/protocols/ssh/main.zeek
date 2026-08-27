

@load base/utils/directions-and-hosts
@load base/protocols/conn/removal-hooks

module SSH;

export {

	redef enum Log::ID += { LOG };


	const ports = { 22/tcp } &redef;


	global log_policy: Log::PolicyHook;


	type Info: record {

		ts:              time         &log;

		uid:             string       &log;

		id:              conn_id      &log;





		version:         count        &log &optional;

		auth_success:    bool         &log &optional;




		auth_attempts:   count        &log &default=0;




		direction:       Direction    &log &optional;

		client:          string       &log &optional;

		server:          string       &log &optional;

		cipher_alg:      string       &log &optional;

		mac_alg:         string       &log &optional;

		compression_alg: string       &log &optional;

		kex_alg:         string       &log &optional;

		host_key_alg:    string       &log &optional;


		host_key_fingerprint: string       &log &optional;
	};



	option compression_algorithms = set("zlib", "zlib@openssh.com");




	option disable_analyzer_after_detection = T;



	global log_ssh: event(rec: Info);


	global finalize_ssh: Conn::RemovalHook;
}

module GLOBAL;
export {
















	global ssh_auth_failed: event(c: connection);






















	global ssh_auth_result: event(c: connection, result: bool, auth_attempts: count);
}

module SSH;

redef record Info += {

	logged:       bool         &default=F;


	capabilities: Capabilities &optional;

	analyzer_id: count         &optional;
};

redef record connection += {
	ssh: Info &optional;
};

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_SSH, ports);
	Log::create_stream(SSH::LOG, Log::Stream($columns=Info, $ev=log_ssh, $path="ssh", $policy=log_policy));
	}

function set_session(c: connection)
	{
	if ( ! c?$ssh )
		{
		local info: SSH::Info &is_assigned;
		info$ts  = network_time();
		info$uid = c$uid;
		info$id  = c$id;


		if ( Site::is_local_addr(c$id$orig_h) != Site::is_local_addr(c$id$resp_h) )
			info$direction = Site::is_local_addr(c$id$orig_h) ? OUTBOUND: INBOUND;
		c$ssh = info;
		Conn::register_removal_hook(c, finalize_ssh);
		}
	}

function set_version(c: connection)
	{

	delete c$ssh$version;




	const has_server = c$ssh?$server && |c$ssh$server| > 0;
	const has_client = c$ssh?$client && |c$ssh$client| > 0;
	if ( ! ( has_server && has_client ) )
		return;

	if ( |c$ssh$client| > 4 && |c$ssh$server| > 4 )
		{
		if ( c$ssh$client[4] == "1" && c$ssh$server[4] == "2" )
			{

			if ( ( |c$ssh$client| > 7 ) && ( c$ssh$client[6] == "9" ) && ( c$ssh$client[7] == "9" ) )
				c$ssh$version = 2;

			else
				Reporter::conn_weird("SSH_version_mismatch", c, fmt("%s vs %s", c$ssh$server, c$ssh$client));
				return;
			}
		else if ( c$ssh$client[4] == "2" && c$ssh$server[4] == "1" )
			{

			if ( ( |c$ssh$server| > 7 ) && ( c$ssh$server[6] == "9" ) && ( c$ssh$server[7] == "9" ) )
				c$ssh$version = 2;
			else

				Reporter::conn_weird("SSH_version_mismatch", c, fmt("%s vs %s", c$ssh$server, c$ssh$client));
				return;
			}
		else if ( c$ssh$client[4] == "1" && c$ssh$server[4] == "1" )
			{

			if ( ( |c$ssh$server| > 7 ) && ( c$ssh$server[6] == "9" ) && ( c$ssh$server[7] == "9" ) )
				{

				if (( |c$ssh$client| > 7 ) && ( c$ssh$client[6] == "9" ) && ( c$ssh$client[7] == "9" ))
					c$ssh$version = 2;
				else
					c$ssh$version = 1;
				}
			else
				{

				c$ssh$version = 1;
				}
			}

		else if (c$ssh$client[4] == "2" && c$ssh$server[4] == "2" )
			{
			c$ssh$version = 2;
			}

		return;
		}

	Reporter::conn_weird("SSH_cannot_determine_version", c, fmt("%s vs %s", c$ssh$server, c$ssh$client));
	}

event ssh_server_version(c: connection, version: string)
	{
	set_session(c);
	c$ssh$server = version;
	set_version(c);
	}

event ssh_client_version(c: connection, version: string)
	{
	set_session(c);
	c$ssh$client = version;
	set_version(c);
	}

event ssh_auth_attempted(c: connection, authenticated: bool) &priority=5
	{
	if ( !c?$ssh || ( c$ssh?$auth_success && c$ssh$auth_success ) )
		return;


	if ( c$ssh?$compression_alg && ( c$ssh$compression_alg in compression_algorithms ) )
		return;

	c$ssh$auth_success = authenticated;
	c$ssh$auth_attempts += 1;

	if ( authenticated && disable_analyzer_after_detection && c$ssh?$analyzer_id )
		disable_analyzer(c$id, c$ssh$analyzer_id);
	}

event ssh_auth_attempted(c: connection, authenticated: bool) &priority=-5
	{
	if ( authenticated && c?$ssh && !c$ssh$logged )
		{
		event ssh_auth_result(c, authenticated, c$ssh$auth_attempts);
		c$ssh$logged = T;
		Log::write(SSH::LOG, c$ssh);
		}
	}


function find_alg(client_algorithms: vector of string, server_algorithms: vector of string): string
	{
	for ( i in client_algorithms )
		for ( j in server_algorithms )
			if ( client_algorithms[i] == server_algorithms[j] )
				return client_algorithms[i];
	return "Algorithm negotiation failed";
	}



function find_bidirectional_alg(client_prefs: Algorithm_Prefs, server_prefs: Algorithm_Prefs): string
	{
	local c_to_s = find_alg(client_prefs$client_to_server, server_prefs$client_to_server);
	local s_to_c = find_alg(client_prefs$server_to_client, server_prefs$server_to_client);


	return c_to_s == s_to_c ? c_to_s : fmt("To server: %s, to client: %s", c_to_s, s_to_c);
	}

event ssh_capabilities(c: connection, cookie: string, capabilities: Capabilities)
	{
	if ( !c?$ssh || ( c$ssh?$capabilities && c$ssh$capabilities$is_server == capabilities$is_server ) )
		return;

	if ( !c$ssh?$capabilities )
		{
		c$ssh$capabilities = capabilities;
		return;
		}

	local client_caps = capabilities$is_server ? c$ssh$capabilities : capabilities;
	local server_caps = capabilities$is_server ? capabilities : c$ssh$capabilities;

	c$ssh$cipher_alg      = find_bidirectional_alg(client_caps$encryption_algorithms,
	                                               server_caps$encryption_algorithms);
	c$ssh$mac_alg         = find_bidirectional_alg(client_caps$mac_algorithms,
	                                               server_caps$mac_algorithms);
	c$ssh$compression_alg = find_bidirectional_alg(client_caps$compression_algorithms,
	                                               server_caps$compression_algorithms);
	c$ssh$kex_alg         = find_alg(client_caps$kex_algorithms, server_caps$kex_algorithms);
	c$ssh$host_key_alg    = find_alg(client_caps$server_host_key_algorithms,
	                                 server_caps$server_host_key_algorithms);
	}

hook finalize_ssh(c: connection)
	{
	if ( ! c?$ssh )
		return;

	if ( c$ssh$logged )
		return;


	if ( c$ssh?$client && c$ssh?$server && c$ssh?$auth_success )
		{

		if ( c$ssh$auth_success )
			return;


		event ssh_auth_failed(c);
		}

	else
		{
		c$ssh$logged = T;
		Log::write(SSH::LOG, c$ssh);
		}
	}

event ssh_auth_failed(c: connection) &priority=-5
	{

	if ( ! c?$ssh || c$ssh$logged )
		return;

	c$ssh$logged = T;
	Log::write(SSH::LOG, c$ssh);

	event ssh_auth_result(c, F, c$ssh$auth_attempts);
	}

event ssh_server_host_key_fingerprint(c: connection, fingerprint: string) &priority=5
	{
	if ( ! c?$ssh )
		return;

	c$ssh$host_key_fingerprint = fingerprint;
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &priority=20
	{
	if ( atype == Analyzer::ANALYZER_SSH )
		{
		set_session(info$c);
		info$c$ssh$analyzer_id = info$aid;
		}
	}
