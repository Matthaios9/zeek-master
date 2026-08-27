




@load base/frameworks/notice
@load base/utils/site

module DNS;

export {
	redef enum Notice::Type += {



		External_Name,
		};


	option skip_resp_host_port_pairs: set[addr, port] = { [[224.0.0.251, [ff02::fb]], 5353/udp] };
}

function detect_external_names(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	if ( |Site::local_zones| == 0 )
		return;

	if ( [c$id$resp_h, c$id$resp_p] in skip_resp_host_port_pairs )
		return;



	if ( Site::is_local_addr(a) &&
	     ! Site::is_local_name(ans$query) )
		{
		NOTICE(Notice::Info($note=External_Name,
		                    $msg=fmt("%s is pointing to a local host - %s.", ans$query, a),
		                    $conn=c,
		                    $identifier=cat(a,ans$query)));
		}
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	detect_external_names(c, msg, ans, a);
	}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	detect_external_names(c, msg, ans, a);
	}
