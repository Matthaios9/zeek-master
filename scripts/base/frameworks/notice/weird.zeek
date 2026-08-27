








@load base/utils/conn-ids
@load base/utils/site
@load ./main

module Weird;

export {

	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;

	redef enum Notice::Type += {

		Activity,
	};


	type Info: record {

		ts:     time    &log;



		uid:    string  &log &optional;


		id:     conn_id &log &optional;


		conn:   connection &optional;


		name:   string  &log;


		addl:   string  &log &optional;


		notice:  bool   &log &default=F;




		peer:   string  &log &default=peer_description;



		source: string  &log &optional;






		identifier: string &optional;
	};


	type Action: enum {


		ACTION_UNSPECIFIED,

		ACTION_IGNORE,

		ACTION_LOG,

		ACTION_LOG_ONCE,

		ACTION_LOG_PER_CONN,

		ACTION_LOG_PER_ORIG,

		ACTION_NOTICE,

		ACTION_NOTICE_ONCE,

		ACTION_NOTICE_PER_CONN,

		ACTION_NOTICE_PER_ORIG,
	};


	const actions: table[string] of Action = {
		["unsolicited_SYN_response"]            = ACTION_IGNORE,
		["above_hole_data_without_any_acks"]    = ACTION_LOG,
		["active_connection_reuse"]             = ACTION_LOG,
		["bad_HTTP_reply"]                      = ACTION_LOG,
		["bad_HTTP_version"]                    = ACTION_LOG,
		["bad_ICMP_checksum"]                   = ACTION_LOG_PER_ORIG,
		["bad_ident_port"]                      = ACTION_LOG,
		["bad_ident_reply"]                     = ACTION_LOG,
		["bad_ident_request"]                   = ACTION_LOG,
		["bad_rlogin_prolog"]                   = ACTION_LOG,
		["bad_rsh_prolog"]                      = ACTION_LOG,
		["rsh_text_after_rejected"]             = ACTION_LOG,
		["bad_RPC"]                             = ACTION_LOG_PER_ORIG,
		["bad_RPC_program"]                     = ACTION_LOG,
		["bad_SYN_ack"]                         = ACTION_LOG,
		["bad_TCP_checksum"]                    = ACTION_LOG_PER_ORIG,
		["bad_UDP_checksum"]                    = ACTION_LOG_PER_ORIG,
		["baroque_SYN"]                         = ACTION_LOG,
		["base64_illegal_encoding"]             = ACTION_LOG,
		["connection_originator_SYN_ack"]       = ACTION_LOG_PER_ORIG,
		["contentline_size_exceeded"]           = ACTION_LOG,
		["crud_trailing_HTTP_request"]          = ACTION_LOG,
		["data_after_reset"]                    = ACTION_LOG,
		["data_before_established"]             = ACTION_LOG,
		["DNS_AAAA_neg_length"]                 = ACTION_LOG,
		["DNS_Conn_count_too_large"]            = ACTION_LOG,
		["DNS_NAME_too_long"]                   = ACTION_LOG,
		["DNS_RR_bad_length"]                   = ACTION_LOG,
		["DNS_RR_length_mismatch"]              = ACTION_LOG,
		["DNS_RR_unknown_type"]                 = ACTION_LOG,
		["DNS_label_forward_compress_offset"]   = ACTION_LOG_PER_ORIG,
		["DNS_label_len_gt_name_len"]           = ACTION_LOG_PER_ORIG,
		["DNS_label_len_gt_pkt"]                = ACTION_LOG_PER_ORIG,
		["DNS_label_too_long"]                  = ACTION_LOG_PER_ORIG,
		["DNS_truncated_RR_rdlength_lt_len"]    = ACTION_LOG,
		["DNS_truncated_ans_too_short"]         = ACTION_LOG,
		["DNS_truncated_len_lt_hdr_len"]        = ACTION_LOG,
		["DNS_truncated_quest_too_short"]       = ACTION_LOG,
		["excessive_data_without_further_acks"] = ACTION_LOG,
		["excess_RPC"]                          = ACTION_LOG_PER_ORIG,
		["FIN_advanced_last_seq"]               = ACTION_LOG,
		["FIN_after_reset"]                     = ACTION_IGNORE,
		["FIN_storm"]                           = ACTION_NOTICE_PER_ORIG,
		["FTP_max_command_length_exceeded"]     = ACTION_LOG_PER_CONN,
		["FTP_too_many_pending_commands"]       = ACTION_LOG_PER_CONN,
		["FTP_user_too_long"]                   = ACTION_LOG_PER_CONN,
		["FTP_reply_msg_too_long"]              = ACTION_LOG_PER_CONN,
		["FTP_arg_too_long"]                    = ACTION_LOG_PER_CONN,
		["FTP_password_too_long"]               = ACTION_LOG_PER_CONN,
		["HTTP_bad_chunk_size"]                 = ACTION_LOG,
		["HTTP_chunked_transfer_for_multipart_message"] = ACTION_LOG,
		["HTTP_excessive_pipelining"]           = ACTION_LOG,
		["HTTP_overlapping_messages"]           = ACTION_LOG,
		["HTTP_response_before_request"]        = ACTION_LOG,
		["unknown_HTTP_method"]                 = ACTION_LOG,
		["HTTP_version_mismatch"]               = ACTION_LOG,
		["ident_request_addendum"]              = ACTION_LOG,
		["inappropriate_FIN"]                   = ACTION_LOG,
		["inflate_failed"]                      = ACTION_LOG,
		["invalid_irc_global_users_reply"]      = ACTION_LOG,
		["irc_invalid_command"]                 = ACTION_LOG,
		["irc_invalid_dcc_message_format"]      = ACTION_LOG,
		["irc_invalid_invite_message_format"]   = ACTION_LOG,
		["irc_invalid_join_line"]               = ACTION_LOG,
		["irc_invalid_kick_message_format"]     = ACTION_LOG,
		["irc_invalid_line"]                    = ACTION_LOG,
		["irc_invalid_mode_message_format"]     = ACTION_LOG,
		["irc_invalid_names_line"]              = ACTION_LOG,
		["irc_invalid_njoin_line"]              = ACTION_LOG,
		["irc_invalid_notice_message_format"]   = ACTION_LOG,
		["irc_invalid_oper_message_format"]     = ACTION_LOG,
		["irc_invalid_privmsg_message_format"]  = ACTION_LOG,
		["irc_invalid_reply_number"]            = ACTION_LOG,
		["irc_invalid_squery_message_format"]   = ACTION_LOG,
		["irc_invalid_topic_reply"]             = ACTION_LOG,
		["irc_invalid_who_line"]                = ACTION_LOG,
		["irc_invalid_who_message_format"]      = ACTION_LOG,
		["irc_invalid_whois_channel_line"]      = ACTION_LOG,
		["irc_invalid_whois_message_format"]    = ACTION_LOG,
		["irc_invalid_whois_operator_line"]     = ACTION_LOG,
		["irc_invalid_whois_user_line"]         = ACTION_LOG,
		["irc_line_size_exceeded"]              = ACTION_LOG,
		["irc_line_too_short"]                  = ACTION_LOG,
		["irc_too_many_invalid"]                = ACTION_LOG,
		["line_terminated_with_single_CR"]      = ACTION_LOG,
		["line_terminated_with_single_LF"]      = ACTION_LOG,
		["malformed_ssh_identification"]        = ACTION_LOG,
		["malformed_ssh_version"]               = ACTION_LOG,
		["multiple_HTTP_request_elements"]      = ACTION_LOG,
		["NUL_in_line"]                         = ACTION_LOG,
		["originator_RPC_reply"]                = ACTION_LOG_PER_ORIG,
		["partial_finger_request"]              = ACTION_LOG,
		["partial_ftp_request"]                 = ACTION_LOG,
		["partial_ident_request"]               = ACTION_LOG,
		["partial_RPC"]                         = ACTION_LOG_PER_ORIG,
		["pending_data_when_closed"]            = ACTION_LOG,
		["pop3_bad_base64_encoding"]            = ACTION_LOG,
		["pop3_client_command_unknown"]         = ACTION_LOG,
		["pop3_client_sending_server_commands"] = ACTION_LOG,
		["pop3_malformed_auth_plain"]           = ACTION_LOG,
		["pop3_server_command_unknown"]         = ACTION_LOG,
		["pop3_server_sending_client_commands"] = ACTION_LOG,
		["possible_split_routing"]              = ACTION_LOG,
		["premature_connection_reuse"]          = ACTION_LOG,
		["repeated_SYN_reply_wo_ack"]           = ACTION_LOG,
		["repeated_SYN_with_ack"]               = ACTION_LOG,
		["responder_RPC_call"]                  = ACTION_LOG_PER_ORIG,
		["rlogin_text_after_rejected"]          = ACTION_LOG,
		["RPC_pending_calls_discarded"]         = ACTION_LOG,
		["RPC_rexmit_inconsistency"]            = ACTION_LOG,
		["RPC_underflow"]                       = ACTION_LOG,
		["RST_storm"]                           = ACTION_LOG,
		["RST_with_data"]                       = ACTION_LOG,
		["SSL_many_server_names"]               = ACTION_LOG,
		["simultaneous_open"]                   = ACTION_LOG_PER_CONN,
		["smtp_mail_transaction_invalid"]       = ACTION_LOG_PER_CONN,
		["smtp_excessive_invalid_mail_transactions"] = ACTION_LOG_PER_CONN,
		["spontaneous_FIN"]                     = ACTION_IGNORE,
		["spontaneous_RST"]                     = ACTION_IGNORE,
		["SMB_parsing_error"]                   = ACTION_LOG,
		["SMB_discarded_messages_state"]        = ACTION_LOG,
		["SMB_discarded_dce_rpc_analyzers"]     = ACTION_LOG,
		["no_smb_session_using_parsesambamsg"]  = ACTION_LOG,
		["smb_andx_command_failed_to_parse"]    = ACTION_LOG,
		["smb_tree_connect_andx_response_without_tree"] = ACTION_LOG_PER_CONN,
		["transaction_subcmd_missing"]          = ACTION_LOG,
		["successful_RPC_reply_to_invalid_request"] = ACTION_NOTICE_PER_ORIG,
		["SYN_after_close"]                     = ACTION_LOG,
		["SYN_after_partial"]                   = ACTION_NOTICE_PER_ORIG,
		["SYN_after_reset"]                     = ACTION_LOG,
		["SYN_inside_connection"]               = ACTION_LOG,
		["SYN_seq_jump"]                        = ACTION_LOG,
		["SYN_with_data"]                       = ACTION_LOG_PER_ORIG,
		["TCP_christmas"]                       = ACTION_LOG,
		["TCP_scale_range"]                     = ACTION_LOG,
		["truncated_ARP"]                       = ACTION_LOG,
		["truncated_NTP"]                       = ACTION_LOG,
		["UDP_datagram_length_mismatch"]        = ACTION_LOG_PER_ORIG,
		["unexpected_client_HTTP_data"]         = ACTION_LOG,
		["unexpected_multiple_HTTP_requests"]   = ACTION_LOG,
		["unexpected_server_HTTP_data"]         = ACTION_LOG,
		["unmatched_HTTP_reply"]                = ACTION_LOG,
		["unpaired_RPC_response"]               = ACTION_LOG,
		["window_recision"]                     = ACTION_LOG,
		["double_%_in_URI"]                     = ACTION_LOG,
		["illegal_%_at_end_of_URI"]             = ACTION_LOG,
		["unescaped_%_in_URI"]                  = ACTION_LOG,
		["unescaped_special_URI_char"]          = ACTION_LOG,
		["deficit_netbios_hdr_len"]             = ACTION_LOG,
		["excess_netbios_hdr_len"]              = ACTION_LOG,
		["netbios_client_session_reply"]        = ACTION_LOG,
		["netbios_raw_session_msg"]             = ACTION_LOG,
		["netbios_server_session_request"]      = ACTION_LOG,
		["unknown_netbios_type"]                = ACTION_LOG,
		["excessively_large_fragment"]          = ACTION_LOG,
		["excessively_small_fragment"]          = ACTION_LOG_PER_ORIG,
		["fragment_inconsistency"]              = ACTION_LOG_PER_ORIG,
		["fragment_overlap"]                    = ACTION_LOG_PER_ORIG,
		["fragment_protocol_inconsistency"]     = ACTION_LOG,
		["fragment_size_inconsistency"]         = ACTION_LOG_PER_ORIG,

		["fragment_with_DF"]                    = ACTION_LOG,
		["incompletely_captured_fragment"]      = ACTION_LOG,
		["bad_IP_checksum"]                     = ACTION_LOG_PER_ORIG,
		["bad_TCP_header_len"]                  = ACTION_LOG,
		["internally_truncated_header"]         = ACTION_LOG,
		["truncated_IP"]                        = ACTION_LOG,
		["truncated_header"]                    = ACTION_LOG,
		["SSH_max_packet_length_exceeded"]      = ACTION_LOG_PER_ORIG,
		["SSH_max_string_length_exceeded"]      = ACTION_LOG_PER_ORIG,
	} &default=ACTION_LOG &redef;



	option ignore_hosts: set[addr, string] = {};



	option weird_do_not_ignore_repeats = {
		"bad_IP_checksum", "bad_TCP_checksum", "bad_UDP_checksum",
		"bad_ICMP_checksum",
	};





	global weird_ignore: set[string, string] &create_expire=10min &redef;




	global did_log: set[string, string] &create_expire=1day &redef;



	global did_notice: set[string, string] &create_expire=1day &redef;





	global log_weird: event(rec: Info);

	global weird: function(w: Weird::Info) &deprecated="Remove in v9.1. Use Reporter::<granularity>_weird instead.";
}



const limiting_actions = {
	ACTION_LOG_ONCE,
	ACTION_LOG_PER_CONN,
	ACTION_LOG_PER_ORIG,
	ACTION_NOTICE_ONCE,
	ACTION_NOTICE_PER_CONN,
	ACTION_NOTICE_PER_ORIG,
};



const notice_actions = {
	ACTION_NOTICE,
	ACTION_NOTICE_PER_CONN,
	ACTION_NOTICE_PER_ORIG,
	ACTION_NOTICE_ONCE,
};

event zeek_init() &priority=5
	{
	Log::create_stream(Weird::LOG, Log::Stream($columns=Info, $ev=log_weird, $path="weird", $policy=log_policy));
	}

function flow_id_string(src: addr, dst: addr): string
	{
	return fmt("%s -> %s", src, dst);
	}

function do_weird(w: Weird::Info)
	{
	local action = actions[w$name];

	local identifier = "";
	if ( w?$identifier )
		identifier = w$identifier;
	else
		{
		if ( w?$id )
			identifier = id_string(w$id);
		}


	if ( action == ACTION_IGNORE || [w$name, identifier] in weird_ignore )
		return;

	if ( w?$conn )
		{
		w$uid = w$conn$uid;
		w$id = w$conn$id;
		}

	if ( w?$id )
		{
		if ( [w$id$orig_h, w$name] in ignore_hosts ||
				 [w$id$resp_h, w$name] in ignore_hosts )
				 return;
		}

	if ( action in limiting_actions )
		{
		local notice_identifier = identifier;
		if ( action in notice_actions )
			{

			if ( w?$id && action == ACTION_NOTICE_PER_ORIG )
				notice_identifier = fmt("%s", w$id$orig_h);
			else if ( action == ACTION_NOTICE_ONCE )
				notice_identifier = "";


			if ( [w$name, notice_identifier] in did_notice )
				return;
			add did_notice[w$name, notice_identifier];
			}
		else
			{

			if ( w?$id && action == ACTION_LOG_PER_ORIG )
				notice_identifier = fmt("%s", w$id$orig_h);
			else if ( action == ACTION_LOG_ONCE )
				notice_identifier = "";


			if ( [w$name, notice_identifier] in did_log )
				return;

			add did_log[w$name, notice_identifier];
			}
		}

	if ( action in notice_actions )
		{
		w$notice = T;

		local n: Notice::Info;
		n$note = Activity;
		n$msg = w$name;
		if ( w?$conn )
			n$conn = w$conn;
		else
			{
			if ( w?$uid )
				n$uid = w$uid;
			if ( w?$id )
				n$id = w$id;
			}
		if ( w?$addl )
			n$sub = w$addl;
		NOTICE(n);
		}


	if ( w$name !in weird_do_not_ignore_repeats )
		add weird_ignore[w$name, identifier];

	Log::write(Weird::LOG, w);
	}


function weird(w: Weird::Info)
	{
	do_weird(w);
	}


event conn_weird(name: string, c: connection, addl: string, source: string)
	{
	local i = Info($ts=network_time(), $name=name, $conn=c, $identifier=id_string(c$id));
	if ( addl != "" )
		i$addl = addl;

	if ( source != "" )
		i$source = source;

	do_weird(i);
	}

event expired_conn_weird(name: string, id: conn_id, uid: string, addl: string, source: string)
	{
	local i = Info($ts=network_time(), $name=name, $uid=uid, $id=id,
	               $identifier=id_string(id));

	if ( addl != "" )
		i$addl = addl;

	if ( source != "" )
		i$source = source;

	do_weird(i);
	}

event flow_weird(name: string, src: addr, dst: addr, addl: string, source: string)
	{


	local id = conn_id($orig_h=src, $orig_p=count_to_port(0, unknown_transport),
	                   $resp_h=dst, $resp_p=count_to_port(0, unknown_transport));

	local i = Info($ts=network_time(), $name=name, $id=id, $identifier=flow_id_string(src,dst));

	if ( addl != "" )
		i$addl = addl;

	if ( source != "" )
		i$source = source;

	do_weird(i);
	}

event net_weird(name: string, addl: string, source: string)
	{
	local i = Info($ts=network_time(), $name=name);

	if ( addl != "" )
		i$addl = addl;

	if ( source != "" )
		i$source = source;

	do_weird(i);
	}

event file_weird(name: string, f: fa_file, addl: string, source: string)
	{
	local i = Info($ts=network_time(), $name=name, $addl=f$id);

	if ( addl != "" )
		i$addl += fmt(": %s", addl);

	if ( source != "" )
		i$source = source;

	do_weird(i);
	}
