



@load base/protocols/ssl
@load base/files/x509
@load base/frameworks/notice
@load base/utils/directions-and-hosts

module SSL;

export {
	redef enum Notice::Type += {


		Certificate_Expired,


		Certificate_Expires_Soon,


		Certificate_Not_Valid_Yet,
	};






	option notify_certs_expiration = LOCAL_HOSTS;



	option notify_when_cert_expiring_in = 30days;
}

event ssl_established(c: connection) &priority=3
	{

	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! addr_matches_host(c$id$resp_h, notify_certs_expiration) ||
	     ! c$ssl$cert_chain[0]?$x509 || ! c$ssl$cert_chain[0]?$sha1 )
		return;

	local fuid = c$ssl$cert_chain[0]$fuid;
	local cert = c$ssl$cert_chain[0]$x509$certificate;
	local hash = c$ssl$cert_chain[0]$sha1;

	if ( cert$not_valid_before > network_time() )
		NOTICE(Notice::Info($note=Certificate_Not_Valid_Yet,
		                    $conn=c, $suppress_for=1day,
		                    $msg=fmt("Certificate %s isn't valid until %T", cert$subject, cert$not_valid_before),
		                    $identifier=cat(c$id$resp_h, c$id$resp_p, hash),
		                    $fuid=fuid));

	else if ( cert$not_valid_after < network_time() )
		NOTICE(Notice::Info($note=Certificate_Expired,
		                    $conn=c, $suppress_for=1day,
		                    $msg=fmt("Certificate %s expired at %T", cert$subject, cert$not_valid_after),
		                    $identifier=cat(c$id$resp_h, c$id$resp_p, hash),
		                    $fuid=fuid));

	else if ( cert$not_valid_after - notify_when_cert_expiring_in < network_time() )
		NOTICE(Notice::Info($note=Certificate_Expires_Soon,
		                    $msg=fmt("Certificate %s is going to expire at %T", cert$subject, cert$not_valid_after),
		                    $conn=c, $suppress_for=1day,
		                    $identifier=cat(c$id$resp_h, c$id$resp_p, hash),
		                    $fuid=fuid));
	}
