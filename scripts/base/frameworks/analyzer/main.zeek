


















@load base/frameworks/packet-filter/utils

module Analyzer;

export {



	global disable_all = F &redef;







	global enable_analyzer: function(tag: AllAnalyzers::Tag) : bool;







	global disable_analyzer: function(tag: AllAnalyzers::Tag) : bool;
















	global register_for_ports: function(tag: Analyzer::Tag, server_ports: set[port], non_server_ports: set[port] &default=set()) : bool;











	global register_for_port: function(tag: Analyzer::Tag, p: port) : bool;







	global registered_ports: function(tag: AllAnalyzers::Tag) : set[port];





	global all_registered_ports: function() : table[AllAnalyzers::Tag] of set[port];






	global name: function(tag: Analyzer::Tag) : string;








	global kind: function(tag: Analyzer::Tag) : string;









	global has_tag: function(name: string): bool;










	global get_tag: function(name: string): Analyzer::Tag;

















	global schedule_analyzer: function(orig: addr, resp: addr, resp_p: port,
	                                   analyzer: Analyzer::Tag, tout: interval) : bool;








	global analyzer_to_bpf: function(tag: Analyzer::Tag): string;




	global get_bpf: function(): string;



	global disabled_analyzers: set[AllAnalyzers::Tag] = {
		ANALYZER_TCPSTATS,
	} &redef;





	global ports: table[AllAnalyzers::Tag] of set[port];









	global requested_analyzers: set[AllAnalyzers::Tag] = {} &redef;
















	global analyzer_failed: event(ts: time, atype: AllAnalyzers::Tag, info: AnalyzerViolationInfo);
}

@load base/bif/analyzer.bif
@load base/bif/file_analysis.bif
@load base/bif/packet_analysis.bif

event zeek_init() &priority=5
	{
	if ( disable_all )
		__disable_all_analyzers();

	for ( a in disabled_analyzers )
		disable_analyzer(a);
	}

event zeek_init() &priority=-5
	{
	for ( a in requested_analyzers )
		Analyzer::enable_analyzer(a);
	}

function enable_analyzer(tag: AllAnalyzers::Tag) : bool
	{
	if ( is_packet_analyzer(tag) )
		return PacketAnalyzer::__enable_analyzer(tag);

	if ( is_file_analyzer(tag) )
		return Files::__enable_analyzer(tag);

	return __enable_analyzer(tag);
	}

function disable_analyzer(tag: AllAnalyzers::Tag) : bool
	{
	if ( is_packet_analyzer(tag) )
		return PacketAnalyzer::__disable_analyzer(tag);

	if ( is_file_analyzer(tag) )
		return Files::__disable_analyzer(tag);

	return __disable_analyzer(tag);
	}

function register_for_ports(tag: Analyzer::Tag, server_ports: set[port], non_server_ports: set[port] &default=set()) : bool
	{
	local rc = T;

	for ( p in server_ports )
		{
		if ( ! register_for_port(tag, p) )
			rc = F;
		}

	for ( p in non_server_ports )
		{
		if ( ! register_for_port(tag, p) )
			rc = F;
		}


	likely_server_ports += server_ports;

	return rc;
	}

function register_for_port(tag: Analyzer::Tag, p: port) : bool
	{
	if ( ! __register_for_port(tag, p) )
		return F;

	if ( tag !in ports )
		ports[tag] = set();

	add ports[tag][p];
	return T;
	}

function registered_ports(tag: AllAnalyzers::Tag) : set[port]
	{
	return tag in ports ? ports[tag] : set();
	}

function all_registered_ports(): table[AllAnalyzers::Tag] of set[port]
	{
	return ports;
	}

function name(atype: AllAnalyzers::Tag) : string
	{
	return __name(atype);
	}

function kind(atype: AllAnalyzers::Tag): string
	{
	if ( is_protocol_analyzer(atype) )
		return "protocol";
	else if ( is_packet_analyzer(atype) )
		return "packet";
	else if ( is_file_analyzer(atype) )
		return "file";

	Reporter::warning(fmt("Unknown kind of analyzer %s", atype));
	return "unknown";
	}

function has_tag(name: string): bool
	{
	return __has_tag(name);
	}

function get_tag(name: string): AllAnalyzers::Tag
	{
	return __tag(name);
	}

function schedule_analyzer(orig: addr, resp: addr, resp_p: port,
			   analyzer: Analyzer::Tag, tout: interval) : bool
	{
	return __schedule_analyzer(orig, resp, resp_p, analyzer, tout);
	}

function analyzer_to_bpf(tag: Analyzer::Tag): string
	{

	if ( tag !in ports )
		return "";

	local output = "";
	for ( p in ports[tag] )
		output = PacketFilter::combine_filters(output, "or", PacketFilter::port_to_bpf(p));
	return output;
	}

function get_bpf(): string
	{
	local output = "";
	for ( tag in ports )
		{
		output = PacketFilter::combine_filters(output, "or", analyzer_to_bpf(tag));
		}
	return output;
	}
