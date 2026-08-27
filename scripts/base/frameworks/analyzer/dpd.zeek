


@load ./main

module DPD;

export {

	option ignore_violations: set[Analyzer::Tag] = set();



	option ignore_violations_after = 10 * 1024;






	option track_removed_services_in_connection = F;
}

redef record connection += {


	failed_analyzers: set[string] &default=set() &ordered;
};


event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &priority=10
	{
	if ( ! is_protocol_analyzer(atype) && ! is_packet_analyzer(atype) )
		return;

	if ( ! info?$c )
		return;

	local c = info$c;
	local analyzer = Analyzer::name(atype);
	add c$service[analyzer];
	}



event analyzer_failed(ts: time, atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo) &priority=-5
	{
	if ( ! is_protocol_analyzer(atype) )
		return;

	if ( ! info?$c )
		return;

	local c = info$c;
	local analyzer = Analyzer::name(atype);


	if ( analyzer !in c$service )
		return;


	if ( ! track_removed_services_in_connection )
		delete c$service[analyzer];



	if ( analyzer !in c$failed_analyzers )
		add c$failed_analyzers[analyzer];


	if ( track_removed_services_in_connection && Analyzer::name(atype) in c$service )
		{
		local rname = cat("-", Analyzer::name(atype));
		if ( rname !in c$service )
			add c$service[rname];
		}
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo ) &priority=5
	{
	if ( ! is_protocol_analyzer(atype) )
		return;

	if ( ! info?$c || ! info?$aid )
		return;

	if ( atype in ignore_violations )
		return;

	local c = info$c;
	local aid = info$aid;
	local size = c$orig$size + c$resp$size;
	if ( ignore_violations_after > 0 && size > ignore_violations_after )
		return;



	if ( lookup_connection_analyzer_id(c$id, atype) == 0 )
		{
		event analyzer_failed(network_time(), atype, info);
		return;
		}

	local disabled = disable_analyzer(c$id, aid, F);


	if ( disabled )
		event analyzer_failed(network_time(), atype, info);
	}
