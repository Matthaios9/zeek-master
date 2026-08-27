

@load base/frameworks/logging
@load ./main

module Analyzer::Logging;

export {

	redef enum Log::ID += { LOG };


	type Info: record {

		ts:             time              &log;


		analyzer_kind:  string            &log;


		analyzer_name:  string            &log;

		uid:            string            &log &optional;

		fuid:           string            &log &optional;

		id:             conn_id           &log &optional;

		proto:          transport_proto   &log &optional;

		failure_reason: string            &log;


		failure_data:   string            &log &optional;
	};



	option failure_data_max_size = 40;



	global log_analyzer: event(rec: Info);


	global log_policy: Log::PolicyHook;
}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $path="analyzer", $ev=log_analyzer, $policy=log_policy));
	}

function log_analyzer_failure(ts: time, atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	local rec = Info(
		$ts=ts,
		$analyzer_kind=Analyzer::kind(atype),
		$analyzer_name=Analyzer::name(atype),
		$failure_reason=info$reason
	);

	if ( info?$c )
		{
		rec$id = info$c$id;
		rec$uid = info$c$uid;
		rec$proto = get_port_transport_proto(info$c$id$orig_p);
		}

	if ( info?$f )
		{
		rec$fuid = info$f$id;


		if ( ! rec?$uid && info$f?$conns && |info$f$conns| == 1 )
			{
			for ( _, c in info$f$conns )
				{
				rec$id = c$id;
				rec$uid = c$uid;
				}
			}
		}

	if ( info?$data )
		{
		if ( failure_data_max_size > 0 )
			rec$failure_data = info$data[0:failure_data_max_size];
		else
			rec$failure_data = info$data;
		}

	Log::write(LOG, rec);
	}


event analyzer_failed(ts: time, atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	if ( ! is_protocol_analyzer(atype) )
		return;

	if ( ! info?$c )
		return;




	local analyzer_name = Analyzer::name(atype);
	if ( analyzer_name !in info$c$service || analyzer_name in info$c$failed_analyzers )
		return;

	log_analyzer_failure(ts, atype, info);
	}


event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo )
	{
	if ( is_protocol_analyzer(atype) )
		return;

	log_analyzer_failure(network_time(), atype, info);
	}
