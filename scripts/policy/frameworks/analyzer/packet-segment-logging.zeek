





module Analyzer::Logging;

export {
	redef record connection += {


		packet_segment: string &optional &log;
	};

	redef record Analyzer::Logging::Info += {


		packet_segment: string &optional &log;
	};


	option packet_segment_size: int = 255;
}


event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo) &priority=4
	{
	if ( ! is_protocol_analyzer(atype) && ! is_packet_analyzer(atype) )
		return;

	if ( ! info?$c || ! info?$aid )
		return;

	info$c$packet_segment = fmt("%s", get_current_packet()$data[:packet_segment_size]);
	}

hook Analyzer::Logging::log_policy(rec: Analyzer::Logging::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( id != Analyzer::Logging::LOG )
		return;

	if ( ! rec?$id || ! connection_exists(rec$id) )
		return;

	local c = lookup_connection(rec$id);

	if ( c?$packet_segment )
		rec$packet_segment = c$packet_segment;
	}
