
module Cluster::Telemetry;

export {
	type Type: enum {


		INFO,


		VERBOSE,



		DEBUG,
	};


	const core_metrics: set[Type] = {
		INFO,
	} &redef;


	const websocket_metrics: set[Type] = {
		INFO,
	} &redef;




	const topic_normalizations: table[pattern] of string = {
		[/^zeek\/cluster\/nodeid\/.*/] = "zeek/cluster/nodeid/__normalized__",
	} &ordered &redef;


	const message_size_bounds: vector of double = {
		10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0,
	} &redef;
}
