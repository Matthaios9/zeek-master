







@load base/utils/directions-and-hosts
@load base/frameworks/cluster

@load base/frameworks/storage/async
@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

module Known;

export {

	redef enum Log::ID += { SERVICES_LOG };


	global log_policy_services: Log::PolicyHook;



	type ServicesInfo: record {

		ts:             time            &log;

		host:           addr            &log;

		port_num:       port            &log;

		port_proto:     transport_proto &log;

		service:        set[string]     &log;
	};



	const enable_services_persistence = F &redef;





	const use_service_store = F &redef &deprecated="Remove in v9.1. Store support has been disabled by default since Zeek 6.0 due to performance and will be removed.";


	option service_udp_requires_response = T;



	option service_tracking = LOCAL_HOSTS;

	type AddrPortServTriplet: record {
		host: addr;
		p: port;
		serv: string;
	};






	global service_broker_store: Cluster::StoreInfo;


	const service_store_name = "zeek/known/services" &redef;








	global service_store_backend: opaque of Storage::BackendHandle;




	const service_store_prefix = "zeekknownservices" &redef;


	const service_store_backend_type : Storage::Backend = Storage::STORAGE_BACKEND_SQLITE &redef;




	const service_store_backend_options : Storage::BackendOptions = [ $sqlite = [
		$database_path=fmt("%s/known/services.sqlite", Cluster::default_store_dir),
		$table_name=Known::service_store_prefix ]] &redef;




	const service_store_expiry = 1day &redef;




	option service_store_timeout = 15sec;









	global services: table[addr, port] of set[string] &create_expire=1day;



	global log_known_services: event(rec: ServicesInfo);
}

redef record connection += {


	known_services_done: bool &default=F;
};


function check(info: ServicesInfo) : bool
	{
	if ( [info$host, info$port_num] !in Known::services )
		return F;

	for ( s in info$service )
		{
		if ( s !in Known::services[info$host, info$port_num] )
			return F;
		}

	return T;
	}

event zeek_init()
	{
@pragma push ignore-deprecations
	if ( ! Known::use_service_store && ! Known::enable_services_persistence )
		return;
@pragma pop ignore-deprecations

@pragma push ignore-deprecations
	if ( Known::use_service_store )
		{
		Known::service_broker_store = Cluster::create_store(Known::service_store_name);
@pragma pop ignore-deprecations
		}
	else
		{
		mkdir(fmt("%s/known", Cluster::default_store_dir));
		local res = Storage::Sync::open_backend(Known::service_store_backend_type, Known::service_store_backend_options, Known::AddrPortServTriplet, bool);
		if ( res$code == Storage::SUCCESS )
			Known::service_store_backend = res$value;
		else
			Reporter::error(fmt("%s: Failed to open backend connection: %s", Known::service_store_prefix, res$error_str));
		}
	}

event service_info_commit(info: ServicesInfo)
	{
@pragma push ignore-deprecations
	if ( ! Known::use_service_store && ! Known::enable_services_persistence )
		return;
@pragma pop ignore-deprecations

	local tempservs = info$service;

	for ( s in tempservs )
		{
		local key = AddrPortServTriplet($host = info$host, $p = info$port_num, $serv = s);

@pragma push ignore-deprecations
		if ( Known::use_service_store )
@pragma pop ignore-deprecations
			{
			when [info, s, key] ( local r = Broker::put_unique(Known::service_broker_store$store, key,
			                                    T, Known::service_store_expiry) )
				{
				if ( r$status == Broker::SUCCESS )
					{
					if ( r$result as bool ) {
						info$service = set(s);
						Log::write(Known::SERVICES_LOG, info);
						}
					}
				else
					Reporter::error(fmt("%s: data store put_unique failure",
					                    Known::service_store_name));
				}
			timeout Known::service_store_timeout
				{
				Log::write(Known::SERVICES_LOG, info);
				}
			}
		else
			{
			when [info, s, key] ( local put_res = Storage::Async::put(Known::service_store_backend, [$key=key, $value=T, $overwrite=F,
			                                                    $expire_time=Known::service_store_expiry]) )
				{
				if ( put_res$code == Storage::SUCCESS )
					{
					info$service = set(s);
					Log::write(Known::SERVICES_LOG, info);
					}
				else if ( put_res$code != Storage::KEY_EXISTS )
					Reporter::error(fmt("%s: data store put_unique failure: %s",
					                    Known::service_store_name, put_res$error_str));
				}
			timeout Known::service_store_timeout
				{
				Log::write(Known::SERVICES_LOG, info);
				}
			}
		}
	}

event known_service_add(info: ServicesInfo)
	{
@pragma push ignore-deprecations
	if ( Known::use_service_store || Known::enable_services_persistence )
		return;
@pragma pop ignore-deprecations

	if ( check(info) )
		return;

	if ( [info$host, info$port_num] !in Known::services )
		Known::services[info$host, info$port_num] = set();


	local info_to_log: ServicesInfo;
	info_to_log$ts = info$ts;
	info_to_log$host = info$host;
	info_to_log$port_num = info$port_num;
	info_to_log$port_proto = info$port_proto;
	info_to_log$service = set();

	for ( s in info$service )
		{
		if ( s !in Known::services[info$host, info$port_num] )
			{
			add Known::services[info$host, info$port_num][s];
			add info_to_log$service[s];
			}
		}

	@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
	Log::write(Known::SERVICES_LOG, info_to_log);
	@endif
	}

event Cluster::node_up(name: string, id: string)
	{
@pragma push ignore-deprecations
	if ( Known::use_service_store || Known::enable_services_persistence )
		return;
@pragma pop ignore-deprecations

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;


	clear_table(Known::services);
	}

event Cluster::node_down(name: string, id: string)
	{
@pragma push ignore-deprecations
	if ( Known::use_service_store || Known::enable_services_persistence )
		return;
@pragma pop ignore-deprecations

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;


	clear_table(Known::services);
	}

event service_info_commit(info: ServicesInfo)
	{
@pragma push ignore-deprecations
	if ( Known::use_service_store || Known::enable_services_persistence )
		return;
@pragma pop ignore-deprecations

	if ( check(info) )
		return;

	local key = cat(info$host, info$port_num);
	Cluster::publish_hrw(Cluster::proxy_pool, key, known_service_add, info);
	event known_service_add(info);
	}

function has_active_service(c: connection): bool
	{
	local proto = get_port_transport_proto(c$id$resp_p);

	switch ( proto ) {
	case tcp:

		if ( c$resp$state == TCP_ESTABLISHED ||
			 c$resp$state == TCP_CLOSED ||
			 c$resp$state == TCP_PARTIAL ||
		     /h/ in c$history )
			return T;
		return F;
	case udp:


		if ( Known::service_udp_requires_response )
			return c$resp$state == UDP_ACTIVE;
		return T;
	case icmp:

		return F;
	default:

		return F;
	}
	}

function known_services_done(c: connection)
	{
	local id = c$id;

	if ( ! addr_matches_host(id$resp_h, service_tracking) )
		return;

	if ( |c$service| == 1 )
		{
		if ( "ftp-data" in c$service )

			return;

		if ( "DNS" in c$service && c$resp$size == 0 )

			return;
		}

	if ( ! has_active_service(c) )




		return;

	c$known_services_done = T;


	local tempservs: set[string];
		for (s in c$service)
			if ( s[0] != "-" )
				add tempservs[s];

	local info = ServicesInfo($ts = network_time(), $host = id$resp_h,
	                          $port_num = id$resp_p,
	                          $port_proto = get_port_transport_proto(id$resp_p),
	                          $service = tempservs);



	if ( |c$service| == 0 )
		{

		add info$service[""];
		schedule 5min { service_info_commit(info) };
		}
	else
		event service_info_commit(info);
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) &priority=-5
	{
	if ( info?$c )
		known_services_done(info$c);
	}


event connection_state_remove(c: connection) &priority=-5
	{
	if ( c$known_services_done )
		return;

	known_services_done(c);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(Known::SERVICES_LOG, Log::Stream($columns=ServicesInfo,
	                                                    $ev=log_known_services,
	                                                    $path="known_services",
	                                                    $policy=log_policy_services));
	}
