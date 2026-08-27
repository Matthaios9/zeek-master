




@load base/protocols/conn
@load base/frameworks/analyzer/dpd

module Conn;

redef record Conn::Info += {



	failed_service: set[string] &log &optional &ordered;
};

event analyzer_failed(ts: time, atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	if ( ! is_protocol_analyzer(atype) && ! is_packet_analyzer(atype) )
		return;

	if ( ! info?$c )
			return;

	local c = info$c;


	local analyzer_name = Analyzer::name(atype);
	if ( analyzer_name !in c$service || analyzer_name in c$failed_analyzers )
		return;

	local aname = to_lower(Analyzer::name(atype));

	if ( c$conn?$failed_service && aname in c$conn$failed_service )
		return;

	if ( ! c$conn?$failed_service )
		c$conn$failed_service = set();

	add c$conn$failed_service[aname];
	}
