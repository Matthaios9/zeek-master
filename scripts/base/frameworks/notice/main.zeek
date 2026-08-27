





@load base/frameworks/cluster

module Notice;

export {
	redef enum Log::ID += {

		LOG,

		ALARM_LOG,
	};


	global log_policy: Log::PolicyHook;
	global log_policy_alarm: Log::PolicyHook;









	type Type: enum {

		Tally,
	};


	type Action: enum {

		ACTION_NONE,


		ACTION_LOG,



		ACTION_EMAIL,



		ACTION_ALARM,



		ACTION_DROP,
	};


	type ActionSet: set[Notice::Action];





	option default_suppression_interval = 1hrs;


	type Info: record {


		ts:             time           &log &optional;



		uid:            string         &log &optional;



		id:             conn_id        &log &optional;




		conn:           connection     &optional;




		f:              fa_file         &optional;




		fuid:           string          &log &optional;



		file_mime_type: string          &log &optional;






		file_desc:      string          &log &optional;



		proto:          transport_proto &log &optional;


		note:           Type           &log;

		msg:            string         &log &optional;

		sub:            string         &log &optional;


		src:            addr           &log &optional;

		dst:            addr           &log &optional;

		p:              port           &log &optional;

		n:              count          &log &optional;


		peer_name:      string         &optional;


		peer_descr:     string         &log &optional;


		actions:        ActionSet      &log &default=ActionSet();


		email_dest:     set[string]    &log &default=set();






		email_body_sections:  vector of string &optional;





		email_delay_tokens:   set[string] &optional;

























		identifier:          string         &optional;



		suppress_for:        interval       &log &default=default_suppression_interval;
	};


	option ignored_types: set[Notice::Type] = {};

	option emailed_types: set[Notice::Type] = {};

	option alarmed_types: set[Notice::Type] = {};

	option not_suppressed_types: set[Notice::Type] = {};


	const type_suppression_intervals: table[Notice::Type] of interval = {} &redef;


	global policy: hook(n: Notice::Info);




	option sendmail            = "/usr/sbin/sendmail";






	const mail_dest           = ""                   &redef;




	option mail_from           = "Zeek <zeek@localhost>";

	option reply_to            = "";




	option mail_subject_prefix = "[Zeek]";

	const max_email_delay     = 15secs &redef;



	type FileInfo: record {
		fuid: string;
		desc: string;

		mime: string  &optional;
		cid:  conn_id &optional;
		cuid: string  &optional;
	};








	option suppression_batch_period = 10msec;



	option suppression_batch_max_size = 50;






	global create_file_info: function(f: fa_file): Notice::FileInfo;






	global populate_file_info: function(f: fa_file, n: Notice::Info);






	global populate_file_info2: function(fi: Notice::FileInfo, n: Notice::Info);








	global log_mailing_postprocessor: function(info: Log::RotationInfo): bool;








	global notice: hook(n: Info);










	global begin_suppression: event(ts: time, suppress_for: interval, note: Type, identifier: string);




	global is_being_suppressed: function(n: Notice::Info): bool;






	global suppressed: event(n: Notice::Info);











	global email_notice_to: function(n: Info, dest: string, extend: bool);










	global email_headers: function(subject_desc: string, dest: string): string;





	global log_notice: event(rec: Info);


	global apply_policy: function(n: Notice::Info);
}

module GLOBAL;

function NOTICE(n: Notice::Info)
	{
	if ( Notice::is_being_suppressed(n) )
		return;


	Notice::apply_policy(n);


	hook Notice::notice(n);
	}

module Notice;


function per_notice_suppression_interval(t: table[Notice::Type, string] of time, idx: any): interval
	{
	local n: Notice::Type;
	local s: string;
	[n,s] = idx;

	local suppress_time = t[n,s] - network_time();
	if ( suppress_time < 0secs )
		suppress_time = 0secs;

	return suppress_time;
	}



type SuppressionInfo: record {
	ts: time;
	suppress_for: interval;
	note: Type;
	identifier: string;
};


type SuppressionBatch: record {
	ts: time &default=double_to_time(0.0);
	timer_pending: bool &default=F;
	infos: vector of SuppressionInfo;
};


global Notice::suppression_batch_internal: event(batch: SuppressionBatch);


global gbatch = SuppressionBatch();

function suppression_info(n: Notice::Info): SuppressionInfo &is_used
	{
	return SuppressionInfo(
		$ts=n$ts,
		$suppress_for=n$suppress_for,
		$note=n$note,
		$identifier=n$identifier
	);
	}

function gbatch_send_and_reset() &is_used
	{
	gbatch$ts = network_time();
	Cluster::publish(
		Cluster::manager_topic,
		Notice::suppression_batch_internal,
		gbatch
	);
	gbatch$infos = vector();
	}

event suppression_batch_timer() &is_used
	{
	gbatch$timer_pending = F;

	if ( |gbatch$infos| == 0 )
		return;

	gbatch_send_and_reset();
	}



global suppressing: table[Type, string] of time = {}
		&create_expire=0secs
		&expire_func=per_notice_suppression_interval;

function log_mailing_postprocessor(info: Log::RotationInfo): bool
	{
	if ( ! reading_traces() && mail_dest != "" )
		{
		local headers = email_headers(fmt("Log Contents: %s", info$fname),
		                              mail_dest);
		local tmpfilename = safe_shell_quote(fmt("%s.mailheaders.tmp", info$fname));
		local tmpfile = open(tmpfilename);
		write_file(tmpfile, headers);
		close(tmpfile);
		system(fmt("/bin/cat %s %s | %s -t -oi && /bin/rm %s %s",
		       tmpfilename, safe_shell_quote(info$fname), sendmail,
			   tmpfilename, safe_shell_quote(info$fname)));
		}
	return T;
	}

event zeek_init() &priority=5
	{
	Log::create_stream(Notice::LOG, Log::Stream($columns=Info, $ev=log_notice, $path="notice", $policy=log_policy));

	Log::create_stream(Notice::ALARM_LOG, Log::Stream($columns=Notice::Info, $path="notice_alarm", $policy=log_policy_alarm));



	if ( ! reading_traces() && mail_dest != "" )
		Log::add_filter(Notice::ALARM_LOG,
		                Log::Filter($name="alarm-mail", $path="alarm-mail", $writer=Log::WRITER_ASCII,
		                            $interv=24hrs, $postprocessor=log_mailing_postprocessor));
	}

function email_headers(subject_desc: string, dest: string): string
	{
	local header_text = string_cat(
		"From: ", mail_from, "\n",
		"Subject: ", mail_subject_prefix, " ", subject_desc, "\n",
		"To: ", dest, "\n",
		"User-Agent: Zeek/", zeek_version(), "\n");
	if ( reply_to != "" )
		header_text = string_cat(header_text, "Reply-To: ", reply_to, "\n");
	return header_text;
	}

event delay_sending_email(n: Notice::Info, dest: string, extend: bool)
	{
	email_notice_to(n, dest, extend);
	}

function email_notice_to(n: Notice::Info, dest: string, extend: bool)
	{
	if ( reading_traces() || dest == "" )
		return;

	if ( extend )
		{
		if ( |n$email_delay_tokens| > 0 )
			{

			if ( n$ts + max_email_delay > network_time() )
				{
				schedule 1sec { delay_sending_email(n, dest, extend) };
				return;
				}
			else
				{
				Reporter::info(fmt("Notice email delay tokens weren't released in time (%s).", n$email_delay_tokens));
				}
			}
		}

	local email_text = email_headers(fmt("%s", n$note), dest);



	email_text = string_cat(email_text, "\nMessage: ", n$msg, "\n");

	if ( n?$sub )
		email_text = string_cat(email_text, "Sub-message: ", n$sub, "\n");

	email_text = string_cat(email_text, "\n");


	if ( n?$file_desc )
		email_text = string_cat(email_text, "File Description: ", n$file_desc, "\n");

	if ( n?$file_mime_type )
		email_text = string_cat(email_text, "File MIME Type: ", n$file_mime_type, "\n");

	if ( n?$file_desc || n?$file_mime_type )
		email_text = string_cat(email_text, "\n");


	if ( n?$id )
		{
		email_text = string_cat(email_text, "Connection: ",
			fmt("%s", n$id$orig_h), ":", fmt("%d", n$id$orig_p), " -> ",
			fmt("%s", n$id$resp_h), ":", fmt("%d", n$id$resp_p), "\n");
		if ( n?$uid )
			email_text = string_cat(email_text, "Connection uid: ", n$uid, "\n");
		}
	else if ( n?$src )
		email_text = string_cat(email_text, "Address: ", fmt("%s", n$src), "\n");


	if ( extend )
		{
		email_text = string_cat(email_text, "\nEmail Extensions\n");
		email_text = string_cat(email_text,   "----------------\n");
		for ( i in n$email_body_sections )
			{
			email_text = string_cat(email_text, n$email_body_sections[i], "\n");
			}
		}

	email_text = string_cat(email_text, "\n\n--\n[Automatically generated]\n\n");
	piped_exec(fmt("%s -t -oi", sendmail), email_text);
	}

hook Notice::policy(n: Notice::Info) &priority=10
	{
	if ( n$note in Notice::ignored_types )
		break;

	if ( n$note in Notice::not_suppressed_types )
		n$suppress_for=0secs;
	if ( n$note in Notice::alarmed_types )
		add n$actions[ACTION_ALARM];
	if ( n$note in Notice::emailed_types )
		add n$actions[ACTION_EMAIL];

	if ( n$note in Notice::type_suppression_intervals )
		n$suppress_for=Notice::type_suppression_intervals[n$note];


	add n$actions[ACTION_LOG];
	}

hook Notice::notice(n: Notice::Info)
	{
	if ( ACTION_EMAIL in n$actions )
		add n$email_dest[mail_dest];
	}

hook Notice::notice(n: Notice::Info) &priority=-5
	{
	for ( dest in n$email_dest )
		email_notice_to(n, dest, T);

	if ( ACTION_LOG in n$actions )
		Log::write(Notice::LOG, n);
	if ( ACTION_ALARM in n$actions )
		Log::write(Notice::ALARM_LOG, n);



	if ( n?$identifier &&
	     [n$note, n$identifier] !in suppressing &&
	     n$suppress_for != 0secs )
		{
		event Notice::begin_suppression(n$ts, n$suppress_for, n$note, n$identifier);
		suppressing[n$note, n$identifier] = n$ts + n$suppress_for;
@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )



		local now = network_time();

		if ( suppression_batch_period == 0sec || suppression_batch_max_size == 0 ||
			(|gbatch$infos| == 0 && (now - gbatch$ts) >= suppression_batch_period) )
			{




			gbatch$infos += suppression_info(n);
			gbatch_send_and_reset();
			return;
			}

		gbatch$infos += suppression_info(n);

		if ( |gbatch$infos| == 1 && suppression_batch_max_size > 1 && ! gbatch$timer_pending )
			{



			schedule suppression_batch_period { suppression_batch_timer() };
			gbatch$timer_pending = T;
			}




		if ( |gbatch$infos| >= suppression_batch_max_size )
			gbatch_send_and_reset();
@endif
		}
	}





@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
event Notice::suppression_batch_internal(batch: SuppressionBatch)
	{
	Cluster::publish(Cluster::worker_topic, Notice::suppression_batch_internal, batch);
	Cluster::publish(Cluster::proxy_topic, Notice::suppression_batch_internal, batch);
	}
@endif


event Notice::suppression_batch_internal(batch: SuppressionBatch)
	{
	for ( _, si in batch$infos )
		event Notice::begin_suppression(si$ts, si$suppress_for, si$note, si$identifier);
	}

event Notice::begin_suppression(ts: time, suppress_for: interval, note: Type, identifier: string)
	{
	local suppress_until = ts + suppress_for;
	suppressing[note, identifier] = suppress_until;
	}

function is_being_suppressed(n: Notice::Info): bool
	{
	if ( n?$identifier && [n$note, n$identifier] in suppressing )
		{
		event Notice::suppressed(n);
		return T;
		}
	else
		return F;
	}

function create_file_info(f: fa_file): Notice::FileInfo
	{
	local fi: Notice::FileInfo = Notice::FileInfo($fuid = f$id,
	                                              $desc = Files::describe(f));

	if ( f?$info && f$info?$mime_type )
		fi$mime = f$info$mime_type;


	if ( f?$conns && |f$conns| > 0 )
		for ( id, c in f$conns )
			{
			fi$cid = id;
			fi$cuid = c$uid;
			break;
			}

	return fi;
	}

function populate_file_info(f: fa_file, n: Notice::Info)
	{
	populate_file_info2(create_file_info(f), n);
	}

function populate_file_info2(fi: Notice::FileInfo, n: Notice::Info)
	{
	if ( ! n?$fuid )
		n$fuid = fi$fuid;

	if ( ! n?$file_mime_type && fi?$mime )
		n$file_mime_type = fi$mime;

	n$file_desc = fi$desc;

	if ( fi?$cid )
		n$id = fi$cid;

	if ( fi?$cuid )
		n$uid = fi$cuid;
	}




function apply_policy(n: Notice::Info)
	{

	if ( ! n?$ts )
		n$ts = network_time();

@if ( Cluster::is_enabled() )
	if ( ! n?$peer_name )
		n$peer_name = Cluster::node;

	if ( ! n?$peer_descr )
		n$peer_descr = Cluster::node;
@endif

	if ( n?$f )
		populate_file_info(n$f, n);

	if ( n?$conn )
		{
		if ( ! n?$id )
			n$id = n$conn$id;

		if ( ! n?$uid )
			n$uid = n$conn$uid;
		}

	if ( n?$id )
		{
		if ( ! n?$src  )
			n$src = n$id$orig_h;
		if ( ! n?$dst )
			n$dst = n$id$resp_h;
		if ( ! n?$p )
			n$p = n$id$resp_p;
		}

	if ( n?$p )
		n$proto = get_port_transport_proto(n$p);

	if ( ! n?$email_body_sections )
		n$email_body_sections = vector();
	if ( ! n?$email_delay_tokens )
		n$email_delay_tokens = set();


	hook Notice::policy(n);




	if ( ! n?$suppress_for )
		n$suppress_for = default_suppression_interval;
	}
