


@load base/protocols/ssl
@load base/frameworks/notice
@load base/utils/directions-and-hosts

module SSL;

export {
	redef enum Notice::Type += {

		Weak_Key,

		Old_Version,

		Weak_Cipher
	};





	option notify_weak_keys = LOCAL_HOSTS;



	option notify_minimal_key_length = 2048;





	option notify_dh_length_shorter_cert_length = T;






	option tls_minimum_version = TLSv10;



	option unsafe_ciphers_regex = /(_EXPORT_)|(_RC4_)/;
}



event ssl_established(c: connection) &priority=3
	{

	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! addr_matches_host(c$id$resp_h, notify_weak_keys) ||
	     ! c$ssl$cert_chain[0]?$x509 )
		return;

	local fuid = c$ssl$cert_chain[0]$fuid;
	local cert = c$ssl$cert_chain[0]$x509$certificate;
	local hash = c$ssl$cert_chain[0]$x509$fingerprint;

	if ( !cert?$key_type || !cert?$key_length )
		return;

	if ( cert$key_type != "dsa" && cert$key_type != "rsa" )
		return;

	local key_length = cert$key_length;

	if ( key_length < notify_minimal_key_length )
		NOTICE(Notice::Info($note=Weak_Key,
		                    $msg=fmt("Host uses weak certificate with %d bit key", key_length),
		                    $conn=c, $suppress_for=1day,
		                    $identifier=cat(c$id$resp_h, c$id$resp_p, hash, key_length),
		                    $sub=fmt("Subject: %s", cert$subject),
		                    $file_desc=fmt("Fingerprint: %s", hash)
		));
	}


event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=3
	{
	if ( ! addr_matches_host(c$id$resp_h, notify_weak_keys) )
		return;

	if ( version < tls_minimum_version )
		{
		local minimum_string = version_strings[tls_minimum_version];
		local host_string = version_strings[version];
		NOTICE(Notice::Info($note=Old_Version,
		                    $msg=fmt("Host uses protocol version %s which is lower than the safe minimum %s", host_string, minimum_string),
		                    $conn=c, $suppress_for=1day,
		                    $identifier=cat(c$id$resp_h, c$id$resp_p)
		));
		}

	if ( unsafe_ciphers_regex in c$ssl$cipher )
		NOTICE(Notice::Info($note=Weak_Cipher,
		                    $msg=fmt("Host established connection using unsafe cipher suite %s", c$ssl$cipher),
		                    $conn=c, $suppress_for=1day,
		                    $identifier=cat(c$id$resp_h, c$id$resp_p, c$ssl$cipher)
		));
	}

event ssl_dh_server_params(c: connection, p: string, q: string, Ys: string) &priority=3
	{
	if ( ! addr_matches_host(c$id$resp_h, notify_weak_keys) )
		return;

	local key_length = |p| * 8;

	if ( key_length < notify_minimal_key_length )
		NOTICE(Notice::Info($note=Weak_Key,
		                    $msg=fmt("Host uses weak DH parameters with %d key bits", key_length),
		                    $conn=c, $suppress_for=1day,
		                    $identifier=cat(c$id$resp_h, c$id$resp_p, key_length)
		));

	if ( notify_dh_length_shorter_cert_length &&
	     c?$ssl && c$ssl?$cert_chain && |c$ssl$cert_chain| > 0 && c$ssl$cert_chain[0]?$x509 &&
	     c$ssl$cert_chain[0]$x509?$certificate && c$ssl$cert_chain[0]$x509$certificate?$key_type &&
	     (c$ssl$cert_chain[0]$x509$certificate$key_type == "rsa" ||
	       c$ssl$cert_chain[0]$x509$certificate$key_type == "dsa" ))
		{
		if ( c$ssl$cert_chain[0]$x509$certificate?$key_length &&
		     c$ssl$cert_chain[0]$x509$certificate$key_length > key_length )
			NOTICE(Notice::Info($note=Weak_Key,
			                    $msg=fmt("DH key length of %d bits is smaller certificate key length of %d bits",
			                             key_length, c$ssl$cert_chain[0]$x509$certificate$key_length),
			                    $conn=c, $suppress_for=1day,
			                    $identifier=cat(c$id$resp_h, c$id$resp_p)
			));
		}
	}
