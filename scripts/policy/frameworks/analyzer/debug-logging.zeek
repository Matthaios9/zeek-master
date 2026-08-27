

@load base/frameworks/config
@load base/frameworks/logging
@load base/frameworks/analyzer

module Analyzer::DebugLogging;

export {

	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;


	type Info: record {

		ts:             time              &log;


		cause:          string            &log;


		analyzer_kind:  string            &log;


		analyzer_name:  string            &log;

		uid:            string            &log &optional;

		fuid:           string            &log &optional;

		id:             conn_id           &log &optional;


		failure_reason: string            &log &optional;



		failure_data:   string            &log &optional;
	};



	option enable = T;






	option include_confirmations = T;





	option include_disabling = T;



	option failure_data_max_size = 40;


	option ignore_analyzers: set[AllAnalyzers::Tag] = set();
}


event zeek_init() &priority=5
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $path="analyzer_debug", $policy=log_policy,
	                                    $event_groups=set("Analyzer::DebugLogging")));

	local enable_handler = function(id: string, new_value: bool): bool {
	if ( new_value )
		Log::enable_stream(LOG);
	else
		Log::disable_stream(LOG);

	return new_value;
	};

	Option::set_change_handler("Analyzer::DebugLogging::enable", enable_handler);

	local include_confirmations_handler = function(id: string, new_value: bool): bool {
	if ( new_value )
		enable_event_group("Analyzer::DebugLogging::include_confirmations");
	else
		disable_event_group("Analyzer::DebugLogging::include_confirmations");

	return new_value;
	};

	Option::set_change_handler("Analyzer::DebugLogging::include_confirmations",
	                           include_confirmations_handler);

	local include_disabling_handler = function(id: string, new_value: bool): bool {
	if ( new_value )
		enable_event_group("Analyzer::DebugLogging::include_disabling");
	else
		disable_event_group("Analyzer::DebugLogging::include_disabling");

	return new_value;
	};

	Option::set_change_handler("Analyzer::DebugLogging::include_disabling",
	                           include_disabling_handler);



	enable_handler("Analyzer::DebugLogging::enable", Analyzer::DebugLogging::enable);
	include_confirmations_handler("Analyzer::DebugLogging::include_confirmations",
	                              Analyzer::DebugLogging::include_confirmations);
	include_disabling_handler("Analyzer::DebugLogging::include_disabling",
	                          Analyzer::DebugLogging::include_disabling);

	}

function populate_from_conn(rec: Info, c: connection)
	{
	rec$id = c$id;
	rec$uid = c$uid;
	}

function populate_from_file(rec: Info, f: fa_file)
	{
	rec$fuid = f$id;


	if ( ! rec?$uid && f?$conns && |f$conns| == 1 )
		{
		for ( _, c in f$conns )
			{
			rec$id = c$id;
			rec$uid = c$uid;
			}
		}
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &group="Analyzer::DebugLogging::include_confirmations"
	{
	if ( atype in ignore_analyzers )
		return;

	local rec = Info(
		$ts=network_time(),
		$cause="confirmation",
		$analyzer_kind=Analyzer::kind(atype),
		$analyzer_name=Analyzer::name(atype),
	);

	if ( info?$c )
		populate_from_conn(rec, info$c);

	if ( info?$f )
		populate_from_file(rec, info$f);

	Log::write(LOG, rec);
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo) &priority=6
	{
	if ( atype in ignore_analyzers )
		return;

	local rec = Info(
		$ts=network_time(),
		$cause="violation",
		$analyzer_kind=Analyzer::kind(atype),
		$analyzer_name=Analyzer::name(atype),
		$failure_reason=info$reason,
	);

	if ( info?$c )
		populate_from_conn(rec, info$c);

	if ( info?$f )
		populate_from_file(rec, info$f);

	if ( info?$data )
		{
		if ( failure_data_max_size > 0 )
			rec$failure_data = info$data[0:failure_data_max_size];
		else
			rec$failure_data = info$data;
		}

	Log::write(LOG, rec);
	}

hook Analyzer::disabling_analyzer(c: connection, atype: AllAnalyzers::Tag, aid: count) &priority=-1000 &group="Analyzer::DebugLogging::include_disabling"
	{
	if ( atype in ignore_analyzers )
		return;

	local rec = Info(
		$ts=network_time(),
		$cause="disabled",
		$analyzer_kind=Analyzer::kind(atype),
		$analyzer_name=Analyzer::name(atype),
	);

	populate_from_conn(rec, c);

	Log::write(LOG, rec);
	}
