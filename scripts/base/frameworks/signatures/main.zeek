



@load base/frameworks/notice

module Signatures;

export {

	redef enum Notice::Type += {

		Sensitive_Signature,



		Multiple_Signatures,



		Multiple_Sig_Responders,






		Count_Signature,



		Signature_Summary,
	};


	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;




	type Action: enum {


		SIG_IGNORE,



		SIG_QUIET,

		SIG_LOG,


		SIG_FILE_BUT_NO_SCAN,

		SIG_ALARM,

		SIG_ALARM_PER_ORIG,

		SIG_ALARM_ONCE,



		SIG_COUNT_PER_RESP,

		SIG_SUMMARY,
	};


	type Info: record {


		ts:         time         &log;


		uid:        string       &log &optional;

		src_addr:   addr         &log &optional;


		src_port:   port         &log &optional;


		dst_addr:   addr         &log &optional;


		dst_port:   port         &log &optional;

		note:       Notice::Type &log;

		sig_id:     string       &log &optional;

		event_msg:  string       &log &optional;

		sub_msg:    string       &log &optional;

		sig_count:  count        &log &optional;

		host_count: count        &log &optional;
	};


	global actions: table[string] of Action =  {
		["unspecified"] = SIG_IGNORE,
	} &redef &default = SIG_ALARM;


	option ignored_ids = /NO_DEFAULT_MATCHES/;



	const horiz_scan_thresholds = { 5, 10, 50, 100, 500, 1000 } &redef;



	const vert_scan_thresholds = { 5, 10, 50, 100, 500, 1000 } &redef;



	const count_thresholds = { 5, 10, 50, 100, 500, 1000, 10000, 1000000, } &redef;



	option summary_interval = 1 day;





	global log_signature: event(rec: Info);
}

global horiz_table: table[addr, string] of addr_set &read_expire = 1 hr;
global vert_table: table[addr, addr] of string_set &read_expire = 1 hr;
global last_hthresh: table[addr] of count &default = 0 &read_expire = 1 hr;
global last_vthresh: table[addr] of count &default = 0 &read_expire = 1 hr;
global count_per_resp: table[addr, string] of count
					&default = 0 &read_expire = 1 hr;
global count_per_orig: table[addr, string] of count
					&default = 0 &read_expire = 1 hr;
global did_sig_log: set[string] &read_expire = 1 hr;


event zeek_init() &priority=5
	{
	Log::create_stream(Signatures::LOG, Log::Stream($columns=Info, $ev=log_signature, $path="signatures", $policy=log_policy));
	}

event sig_summary(orig: addr, id: string, msg: string)
	{
	NOTICE(Notice::Info($note=Signature_Summary, $src=orig,
	                    $msg=fmt("%s: %s", orig, msg),
	                    $n=count_per_orig[orig,id]));
	}

event signature_match(state: signature_state, msg: string, data: string)
	{
	local sig_id = state$sig_id;
	local action = actions[sig_id];

	if ( action == SIG_IGNORE || ignored_ids in sig_id )
		return;


	if ( |data| > 140 )
		data = fmt("%s...", sub_bytes(data, 0, 140));

	local src_addr: addr;
	local src_port: port;
	local dst_addr: addr;
	local dst_port: port;

	if ( state$is_orig )
		{
		src_addr = state$conn$id$orig_h;
		src_port = state$conn$id$orig_p;
		dst_addr = state$conn$id$resp_h;
		dst_port = state$conn$id$resp_p;
		}
	else
		{
		src_addr = state$conn$id$resp_h;
		src_port = state$conn$id$resp_p;
		dst_addr = state$conn$id$orig_h;
		dst_port = state$conn$id$orig_p;
		}

	if ( action != SIG_QUIET && action != SIG_COUNT_PER_RESP )
		{
		local info = Info($ts=network_time(),
		                  $note=Sensitive_Signature,
		                  $uid=state$conn$uid,
		                  $src_addr=src_addr,
		                  $src_port=src_port,
		                  $dst_addr=dst_addr,
		                  $dst_port=dst_port,
		                  $event_msg=fmt("%s: %s", src_addr, msg),
		                  $sig_id=sig_id,
		                  $sub_msg=data);
		Log::write(Signatures::LOG, info);
		}

	local notice = F;
	if ( action == SIG_ALARM )
		notice = T;

	if ( action == SIG_COUNT_PER_RESP )
		{
		local dst = state$conn$id$resp_h;
		if ( ++count_per_resp[dst,sig_id] in count_thresholds )
			{
			NOTICE(Notice::Info($note=Count_Signature, $conn=state$conn,
			                    $msg=msg,
			                    $n=count_per_resp[dst,sig_id],
			                    $sub=fmt("%d matches of signature %s on host %s",
			                             count_per_resp[dst,sig_id],
			                             sig_id, dst)));
			}
		}

	if ( (action == SIG_ALARM_PER_ORIG || action == SIG_SUMMARY) &&
	     ++count_per_orig[state$conn$id$orig_h, sig_id] == 1 )
		{
		if ( action == SIG_ALARM_PER_ORIG )
			notice = T;
		else
			schedule summary_interval {
				sig_summary(state$conn$id$orig_h, sig_id, msg)
			};
		}

	if ( action == SIG_ALARM_ONCE )
		{
		if ( [sig_id] !in did_sig_log )
			{
			notice = T;
			add did_sig_log[sig_id];
			}
		}

	if ( notice )
		NOTICE(Notice::Info($note=Sensitive_Signature,
		                    $conn=state$conn, $src=src_addr,
		                    $dst=dst_addr, $msg=fmt("%s: %s", src_addr, msg),
		                    $sub=data));

	if ( action == SIG_FILE_BUT_NO_SCAN || action == SIG_SUMMARY )
		return;


	local orig = state$conn$id$orig_h;
	local resp = state$conn$id$resp_h;

	if ( [orig, sig_id] !in horiz_table )
		horiz_table[orig, sig_id] = set();

	add horiz_table[orig, sig_id][resp];

	if ( [orig, resp] !in vert_table )
		vert_table[orig, resp] = set();

	add vert_table[orig, resp][sig_id];

	local hcount = |horiz_table[orig, sig_id]|;
	local vcount = |vert_table[orig, resp]|;

	if ( hcount in horiz_scan_thresholds && hcount != last_hthresh[orig] )
		{
		local horz_scan_msg =
			fmt("%s has triggered signature %s on %d hosts",
				orig, sig_id, hcount);

		Log::write(Signatures::LOG,
		           Info($ts=network_time(), $note=Multiple_Sig_Responders,
		                $src_addr=orig, $sig_id=sig_id, $event_msg=msg,
		                $host_count=hcount, $sub_msg=horz_scan_msg));

		NOTICE(Notice::Info($note=Multiple_Sig_Responders, $src=orig,
		                    $msg=msg, $n=hcount, $sub=horz_scan_msg));

		last_hthresh[orig] = hcount;
		}

	if ( vcount in vert_scan_thresholds && vcount != last_vthresh[orig] )
		{
		local vert_scan_msg =
			fmt("%s has triggered %d different signatures on host %s",
				orig, vcount, resp);

		Log::write(Signatures::LOG,
		           Info($ts=network_time(),
		                $note=Multiple_Signatures,
		                $src_addr=orig,
		                $dst_addr=resp, $sig_id=sig_id, $sig_count=vcount,
		                $event_msg=fmt("%s different signatures triggered", vcount),
		                $sub_msg=vert_scan_msg));

		NOTICE(Notice::Info($note=Multiple_Signatures, $src=orig, $dst=resp,
		                    $msg=fmt("%s different signatures triggered", vcount),
		                    $n=vcount, $sub=vert_scan_msg));

		last_vthresh[orig] = vcount;
		}
	}
