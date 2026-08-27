













@load base/utils/numbers
@load base/frameworks/cluster



@if ( Cluster::backend == Cluster::CLUSTER_BACKEND_NONE )

@if ( |Cluster::nodes| > 0 )
event zeek_init() &priority=10
	{
	Reporter::error("Cluster::nodes has entries but Cluster::backend was Cluster::CLUSTER_BACKEND_NONE");
	exit(1);
	}
@else
@load frameworks/cluster/backend/zeromq
redef Cluster::Backend::ZeroMQ::run_proxy_thread = T;
@endif
@endif

event zeek_init() &priority=-100
	{
	local listen_addr = 127.0.0.1;
	local listen_addr_env = getenv("ZEEK_WEBSOCKET_LISTEN_ADDRESS");
	if ( |listen_addr_env| > 0 )
		{
		listen_addr_env = rstrip(lstrip(listen_addr_env, "["), "]");
		listen_addr = to_addr(listen_addr_env);
		}

	local listen_port = 27759/tcp;
	local listen_port_env = getenv("ZEEK_WEBSOCKET_LISTEN_PORT");
	if ( |listen_port_env| > 0 )
		listen_port = count_to_port(extract_count(listen_port_env), tcp);

	Reporter::info(fmt("Running standalone WebSocket server on %s:%s with local cluster backend %s",
	                   listen_addr, listen_port, Cluster::backend));

	if ( ! Cluster::listen_websocket([$listen_addr=listen_addr, $listen_port=listen_port]) )
		Reporter::fatal("failed to listen");
	}
