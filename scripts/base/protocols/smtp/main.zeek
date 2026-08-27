@load base/utils/addrs
@load base/utils/directions-and-hosts
@load base/utils/email
@load base/protocols/conn/removal-hooks
@load base/frameworks/notice/weird

module SMTP;

export {
	redef enum Log::ID += { LOG };


	const ports = { 25/tcp, 587/tcp } &redef;

	global log_policy: Log::PolicyHook;

	type Info: record {

		ts:                time            &log;

		uid:               string          &log;

		id:                conn_id         &log;


		trans_depth:       count           &log;

		helo:              string          &log &optional;

		mailfrom:          string          &log &optional;

		rcptto:            set[string]     &log &optional;

		date:              string          &log &optional;

		from:              string          &log &optional;

		to:                set[string]     &log &optional;

		cc:                set[string]     &log &optional;

		reply_to:          string          &log &optional;

		msg_id:            string          &log &optional;

		in_reply_to:       string          &log &optional;

		subject:           string          &log &optional;

		x_originating_ip:  addr            &log &optional;

		first_received:    string          &log &optional;

		second_received:   string          &log &optional;

		last_reply:        string          &log &optional;

		path:              vector of addr  &log &optional;

		user_agent:        string          &log &optional;


		tls:               bool            &log &default=F;


		process_received_from: bool        &default=T;

		has_client_activity:  bool            &default=F;

		process_smtp_headers:  bool        &default=T;
		entity_count:	       count	   &default=0;
	};

	type State: record {
		helo:                     string    &optional;



		messages_transferred:     count     &default=0;

		pending_messages:         set[Info] &optional;

		trans_mail_from_seen:     bool      &default=F;
		trans_rcpt_to_seen:       bool      &default=F;
		invalid_transactions:     count     &default=0;
		bdat_last_observed:       bool      &default=F;
		analyzer_id:              count     &optional;
	};






	option mail_path_capture = ALL_HOSTS;


	global describe: function(rec: Info): string;

	global log_smtp: event(rec: Info);


	global finalize_smtp: Conn::RemovalHook;





	option mail_transaction_validation = T;



	option max_invalid_mail_transactions = 25;
}

redef record connection += {
	smtp:       Info  &optional;
	smtp_state: State &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(SMTP::LOG, Log::Stream($columns=SMTP::Info, $ev=log_smtp, $path="smtp", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_SMTP, ports);
	}

function find_address_in_smtp_header(header: string): string
	{
	local ips = extract_ip_addresses(header, T);

	if ( |ips| > 1 )
		return ips[1];

	else if ( |ips| > 0 )
		return ips[0];

	else
		return "";
	}

function new_smtp_log(c: connection): Info
	{
	local l: Info;
	l$ts=network_time();
	l$uid=c$uid;
	l$id=c$id;


	l$trans_depth = c$smtp_state$messages_transferred+1;

	if ( c$smtp_state?$helo )
		l$helo = c$smtp_state$helo;



	l$path = vector(c$id$resp_h, c$id$orig_h);

	Conn::register_removal_hook(c, finalize_smtp);
	return l;
	}

function set_smtp_session(c: connection)
	{
	if ( ! c?$smtp_state )
		c$smtp_state = [];

	if ( ! c?$smtp )
		c$smtp = new_smtp_log(c);
	}

function mail_transaction_invalid(c: connection, addl: string)
	{
	Reporter::conn_weird("smtp_mail_transaction_invalid", c, addl, "SMTP");

	++c$smtp_state$invalid_transactions;

	if ( max_invalid_mail_transactions > 0
	     && c$smtp_state$invalid_transactions > max_invalid_mail_transactions
	     && c$smtp_state?$analyzer_id )
		{
		Reporter::conn_weird("smtp_excessive_invalid_mail_transactions", c, "", "SMTP");
		if ( disable_analyzer(c$id, c$smtp_state$analyzer_id) )
			delete c$smtp_state$analyzer_id;
		}
	}

function smtp_message(c: connection)
	{
	if ( c$smtp$has_client_activity )
		{
		Log::write(SMTP::LOG, c$smtp);
		c$smtp = new_smtp_log(c);
		}
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	if ( atype != Analyzer::ANALYZER_SMTP )
		return;

	set_smtp_session(info$c);
	info$c$smtp_state$analyzer_id = info$aid;
	}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string) &priority=5
	{
	set_smtp_session(c);
	local upper_command = to_upper(command);

	if ( upper_command == "HELO" || upper_command == "EHLO" )
		{
		c$smtp_state$helo = arg;
		c$smtp$helo = arg;
		}

	else if ( upper_command == "RCPT" && /^[tT][oO]:/ in arg )
		{
		if ( ! c$smtp?$rcptto )
			c$smtp$rcptto = set();

		local rcptto_addrs = extract_email_addrs_set(arg);
		for ( rcptto_addr in rcptto_addrs )
			{
			rcptto_addr = gsub(rcptto_addr, /ORCPT=rfc822;?/, "");
			add c$smtp$rcptto[rcptto_addr];
			}

		c$smtp$has_client_activity = T;
		c$smtp_state$trans_rcpt_to_seen = T;

		if ( mail_transaction_validation )
			{
			if ( ! c$smtp_state$trans_mail_from_seen )
				mail_transaction_invalid(c, "rcpt to missing mail from");
			}
		}

	else if ( upper_command == "MAIL" && /^[fF][rR][oO][mM]:/ in arg )
		{

		smtp_message(c);

		local mailfrom = extract_first_email_addr(arg);
		if ( mailfrom != "" )
			c$smtp$mailfrom = mailfrom;
		c$smtp$has_client_activity = T;

		c$smtp_state$trans_mail_from_seen = T;
		c$smtp_state$trans_rcpt_to_seen = F;
		}
	else if ( upper_command == "DATA" || upper_command == "BDAT" )
		{
		if ( mail_transaction_validation )
			{
			if ( ! c$smtp_state$trans_rcpt_to_seen )
				mail_transaction_invalid(c, "data missing rcpt to");
			}

		if ( upper_command == "BDAT" && ends_with(arg, " LAST") )
			{


			c$smtp_state$trans_mail_from_seen = F;
			c$smtp_state$trans_rcpt_to_seen = F;
			c$smtp_state$bdat_last_observed = T;
			}
		}
	else if ( upper_command == "." )
		{

		c$smtp_state$trans_mail_from_seen = F;
		c$smtp_state$trans_rcpt_to_seen = F;
		}
	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=5
	{
	set_smtp_session(c);



	c$smtp$last_reply = fmt("%d %s", code, msg);
	}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool) &priority=-5
	{
	if ( cmd == "." || (!cont_resp && cmd == "BDAT" && c$smtp_state$bdat_last_observed ) )
		{

		++c$smtp_state$messages_transferred;
		c$smtp_state$bdat_last_observed = F;
		smtp_message(c);
		c$smtp = new_smtp_log(c);
		}
	}

event mime_one_header(c: connection, h: mime_header_rec) &priority=5
	{
	if ( ! c?$smtp || ! c$smtp$process_smtp_headers ) return;

	if ( h$name == "MESSAGE-ID" )
		c$smtp$msg_id = h$value;

	else if ( h$name == "RECEIVED" )
		{
		if ( c$smtp?$first_received )
			c$smtp$second_received = c$smtp$first_received;
		c$smtp$first_received = h$value;
		}

	else if ( h$name == "IN-REPLY-TO" )
		c$smtp$in_reply_to = h$value;

	else if ( h$name == "SUBJECT" )
		c$smtp$subject = h$value;

	else if ( h$name == "FROM" )
		c$smtp$from = h$value;

	else if ( h$name == "REPLY-TO" )
		c$smtp$reply_to = h$value;

	else if ( h$name == "DATE" )
		c$smtp$date = h$value;

	else if ( h$name == "TO" )
		{
		if ( ! c$smtp?$to )
			c$smtp$to = set();

		local to_email_addrs = split_mime_email_addresses(h$value);
		for ( to_email_addr in to_email_addrs )
			{
			add c$smtp$to[to_email_addr];
			}
		}

	else if ( h$name == "CC" )
		{
		if ( ! c$smtp?$cc )
			c$smtp$cc = set();

		local cc_parts = split_mime_email_addresses(h$value);
		for ( cc_part in cc_parts )
			add c$smtp$cc[cc_part];
		}

	else if ( h$name == "X-ORIGINATING-IP" )
		{
		local addresses = extract_ip_addresses(h$value);
		if ( 0 in addresses )
			c$smtp$x_originating_ip = addresses[0] as addr;
		}

	else if ( h$name == "X-MAILER" ||
	          h$name == "USER-AGENT" ||
	          h$name == "X-USER-AGENT" )
		c$smtp$user_agent = h$value;
	}



event mime_one_header(c: connection, h: mime_header_rec) &priority=3
	{



	if ( ! c?$smtp || h$name != "RECEIVED" || ! c$smtp$process_received_from ||
	     ! c$smtp$process_smtp_headers )
		return;

	local text_ip = find_address_in_smtp_header(h$value);
	if ( text_ip == "" )
		return;
	local ip = text_ip as addr;

	if ( ! addr_matches_host(ip, mail_path_capture) &&
	     ! Site::is_private_addr(ip) )
		{
		c$smtp$process_received_from = F;
		}
	if ( c$smtp$path[|c$smtp$path|-1] != ip )
		c$smtp$path += ip;
	}



event mime_begin_entity(c: connection) &priority=5
	{
	if ( c?$smtp )
		{
		++c$smtp$entity_count;

		if ( c$smtp$entity_count > 1 )
			c$smtp$process_smtp_headers = F;
		}
	}

hook finalize_smtp(c: connection)
	{
	if ( c?$smtp )
		smtp_message(c);
	}

event smtp_starttls(c: connection) &priority=5
	{
	if ( c?$smtp )
		{
		c$smtp$tls = T;
		c$smtp$has_client_activity = T;
		}
	}

function describe(rec: Info): string
	{
	if ( rec?$mailfrom && rec?$rcptto )
		{
		local one_to = "";
		for ( email in rec$rcptto )
			{
			one_to = email;
			break;
			}
		local abbrev_subject = "";
		if ( rec?$subject )
			{
			if ( |rec$subject| > 20 )
				{
				abbrev_subject = rec$subject[0:21] + "...";
				}
			}

		return fmt("%s -> %s%s%s", rec$mailfrom, one_to,
			(|rec$rcptto|>1 ? fmt(" (plus %d others)", |rec$rcptto|-1) : ""),
			(abbrev_subject != "" ? fmt(": %s", abbrev_subject) : ""));
		}

	return "";
	}
