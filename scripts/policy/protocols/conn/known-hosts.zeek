




@load base/utils/directions-and-hosts
@load base/frameworks/cluster

@load base/frameworks/storage/async
@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

module Known;

export {

	redef enum Log::ID += { HOSTS_LOG };


	global log_policy_hosts: Log::PolicyHook;


	type HostsInfo: record {

		ts:      time &log;


		host:    addr &log;
	};



	const enable_hosts_persistence = F &redef;





	const use_host_store = F &redef &deprecated="Remove in v9.1. Store support has been disabled by default since Zeek 6.0 due to performance and will be removed.";



	option host_tracking = LOCAL_HOSTS;



	global host_broker_store: Cluster::StoreInfo;


	const host_store_name = "zeek/known/hosts" &redef;






	global host_store_backend: opaque of Storage::BackendHandle;




	const host_store_prefix = "zeekknownhosts" &redef;


	const host_store_backend_type : Storage::Backend = Storage::STORAGE_BACKEND_SQLITE &redef;




	const host_store_backend_options : Storage::BackendOptions = [ $sqlite = [
		$database_path=fmt("%s/known/hosts.sqlite", Cluster::default_store_dir),
		$table_name=Known::host_store_prefix ]] &redef;




	const host_store_expiry = 1day &redef;



	option host_store_timeout = 15sec;









	global hosts: set[addr] &create_expire=1day &redef;



	global log_known_hosts: event(rec: HostsInfo);
}

event zeek_init()
	{
@pragma push ignore-deprecations
	if ( ! Known::use_host_store && ! Known::enable_hosts_persistence )
		return;
@pragma pop ignore-deprecations

@pragma push ignore-deprecations
	if ( Known::use_host_store )
		{
		Known::host_broker_store = Cluster::create_store(Known::host_store_name);
@pragma pop ignore-deprecations
		}
	else
		{
		mkdir(fmt("%s/known", Cluster::default_store_dir));
		local res = Storage::Sync::open_backend(Known::host_store_backend_type, Known::host_store_backend_options, addr, bool);
		if ( res$code == Storage::SUCCESS )
			Known::host_store_backend = res$value;
		else
			Reporter::error(fmt("%s: Failed to open backend connection: %s", Known::host_store_prefix, res$error_str));
		}
	}

event Known::host_found(info: HostsInfo)
	{
@pragma push ignore-deprecations
	if ( ! Known::use_host_store && ! Known::enable_hosts_persistence )
		return;
@pragma pop ignore-deprecations

@pragma push ignore-deprecations
	if ( Known::use_host_store )
		{
@pragma pop ignore-deprecations
		when [info] ( local r = Broker::put_unique(Known::host_broker_store$store, info$host,
		                                    T, Known::host_store_expiry) )
			{
			if ( r$status == Broker::SUCCESS )
				{
				if ( r$result as bool )
					Log::write(Known::HOSTS_LOG, info);
				}
			else
				Reporter::error(fmt("%s: data store put_unique failure",
				                    Known::host_store_name));
			}
		timeout Known::host_store_timeout
			{

			Log::write(Known::HOSTS_LOG, info);
			}
		}
	else
		{
		when [info] ( local put_res = Storage::Async::put(Known::host_store_backend, [$key=info$host, $value=T, $overwrite=F,
		                                                    $expire_time=Known::host_store_expiry]) )
			{
			if ( put_res$code == Storage::SUCCESS )
				Log::write(Known::HOSTS_LOG, info);
			else if ( put_res$code != Storage::KEY_EXISTS )
				Reporter::error(fmt("%s: data store put_unique failure: %s",
				                    Known::host_store_name, put_res$error_str));
			}
		timeout Known::host_store_timeout
			{
			Log::write(Known::HOSTS_LOG, info);
			}
		}
	}

event known_host_add(info: HostsInfo)
	{
@pragma push ignore-deprecations
	if ( use_host_store || Known::enable_hosts_persistence )
		return;
@pragma pop ignore-deprecations

	if ( info$host in Known::hosts )
		return;

	add Known::hosts[info$host];

	@if ( ! Cluster::is_enabled() ||
	      Cluster::local_node_type() == Cluster::PROXY )
		Log::write(Known::HOSTS_LOG, info);
	@endif
	}

event Cluster::node_up(name: string, id: string)
	{
@pragma push ignore-deprecations
	if ( use_host_store || Known::enable_hosts_persistence )
		return;
@pragma pop ignore-deprecations

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;


	clear_table(Known::hosts);
	}

event Cluster::node_down(name: string, id: string)
	{
@pragma push ignore-deprecations
	if ( use_host_store || Known::enable_hosts_persistence )
		return;
@pragma pop ignore-deprecations

	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;


	clear_table(Known::hosts);
	}

event Known::host_found(info: HostsInfo)
	{
@pragma push ignore-deprecations
	if ( use_host_store || Known::enable_hosts_persistence )
		return;
@pragma pop ignore-deprecations

	if ( info$host in Known::hosts )
		return;

	Cluster::publish_hrw(Cluster::proxy_pool, info$host, known_host_add, info);
	event known_host_add(info);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(Known::HOSTS_LOG, Log::Stream($columns=HostsInfo, $ev=log_known_hosts, $path="known_hosts", $policy=log_policy_hosts));
	}

event connection_established(c: connection) &priority=5
	{
	if ( c$orig$state != TCP_ESTABLISHED )
		return;

	if ( c$resp$state != TCP_ESTABLISHED )
		return;

	local id = c$id;

	for ( host in set(id$orig_h, id$resp_h) )
		if ( addr_matches_host(host, host_tracking) )
			event Known::host_found(Known::HostsInfo($ts = network_time(), $host = host));
	}
