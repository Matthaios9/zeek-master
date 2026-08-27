





module Telemetry;

export {


	const metrics_address = getenv("ZEEK_DEFAULT_LISTEN_ADDRESS") &redef;



	const metrics_port = 0/unknown &redef;






	const metrics_endpoint_label = "node" &redef;




	const metrics_endpoint_name = "" &redef;
}













@if ( Cluster::is_enabled() )
redef Telemetry::metrics_endpoint_name = Cluster::node;

@if ( Cluster::local_node_metrics_port() != 0/unknown )
redef Telemetry::metrics_port = Cluster::local_node_metrics_port();
@endif
@endif
