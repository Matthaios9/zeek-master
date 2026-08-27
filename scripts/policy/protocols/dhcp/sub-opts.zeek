
@load base/protocols/dhcp

module DHCP;

export {
	redef record DHCP::Info += {





		circuit_id:      string &log &optional;



		agent_remote_id: string &log &optional;





		subscriber_id:   string &log &optional;
	};
}

event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
	{
	if ( options?$sub_opt )
		{
		for ( i in options$sub_opt )
			{
			local sub_opt = options$sub_opt[i];

			if ( sub_opt$code == 1 )
				DHCP::log_info$circuit_id = sub_opt$value;

			else if ( sub_opt$code == 2 )
				DHCP::log_info$agent_remote_id = sub_opt$value;

			else if ( sub_opt$code == 6 )
				DHCP::log_info$subscriber_id = sub_opt$value;
			}
		}
	}
