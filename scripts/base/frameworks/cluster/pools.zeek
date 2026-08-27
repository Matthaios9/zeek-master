


@load ./main
@load base/utils/hash_hrw

module Cluster;

export {

	type PoolNode: record {

		name: string;


		alias: string;

		site_id: count;

		alive: bool &default=F;

		topic: string;
	};


	type PoolSpec: record {

		topic: string;

		node_type: Cluster::NodeType;




		max_nodes: count &optional;



		exclusive: bool &default = F;
	};

	type PoolNodeTable: table[string] of PoolNode;
	type RoundRobinTable: table[string] of int;


	type Pool: record {

		spec: PoolSpec;

		nodes: PoolNodeTable &default = PoolNodeTable();

		node_list: vector of PoolNode &default = vector();

		hrw_pool: HashHRW::Pool &default = HashHRW::Pool();



		rr_key_seq: RoundRobinTable &default = RoundRobinTable();

		alive_count: count &default = 0;
	};


	global proxy_pool_spec: PoolSpec =
		PoolSpec($topic = "zeek/cluster/pool/proxy",
				 $node_type = Cluster::PROXY) &redef;


	global worker_pool_spec: PoolSpec =
		PoolSpec($topic = "zeek/cluster/pool/worker",
				 $node_type = Cluster::WORKER) &redef;


	global logger_pool_spec: PoolSpec =
		PoolSpec($topic = "zeek/cluster/pool/logger",
				 $node_type = Cluster::LOGGER) &redef;




	global proxy_pool: Pool;




	global worker_pool: Pool;




	global logger_pool: Pool;


	global register_pool: function(spec: PoolSpec): Pool;











	global hrw_topic: function(pool: Pool, key: any): string;















	global rr_topic: function(pool: Pool, key: string &default=""): string;






	global rr_log_topic: function(id: Log::ID, path: string): string;
}








global init_pool_node: function(pool: Pool, name: string): bool;









global mark_pool_node_alive: function(pool: Pool, name: string): bool;









global mark_pool_node_dead: function(pool: Pool, name: string): bool;

global registered_pools: vector of Pool = vector();

function register_pool(spec: PoolSpec): Pool
	{
	local rval = Pool($spec = spec);
	registered_pools += rval;
	return rval;
	}

function hrw_topic(pool: Pool, key: any): string
	{
	if ( |pool$hrw_pool$sites| == 0 )
		return "";

	local site = HashHRW::get_site(pool$hrw_pool, key);
	local pn: PoolNode = site$user_data;
	return pn$topic;
	}

function rr_topic(pool: Pool, key: string): string
	{
	if ( key !in pool$rr_key_seq )
		pool$rr_key_seq[key] = 0;

	local next_idx = pool$rr_key_seq[key];
	local start = next_idx;
	local rval = "";

	if ( next_idx >= |pool$node_list| )
		return rval;

	while ( T )
		{
		local pn = pool$node_list[next_idx];

		++next_idx;

		if ( next_idx == |pool$node_list| )
			next_idx = 0;

		if ( pn$alive )
			{
			rval = pn$topic;
			break;
			}

		if ( next_idx == start )

			break;
		}

	pool$rr_key_seq[key] = next_idx;
	return rval;
	}

function rr_log_topic(id: Log::ID, path: string): string
	{
	local rval = rr_topic(logger_pool, "Cluster::rr_log_topic");

	if ( rval != "" )
		return rval;

	rval = Broker::default_log_topic(id, path);
	return rval;
	}

event Cluster::node_up(name: string, id: string) &priority=10
	{
	for ( i in registered_pools )
		{
		local pool = registered_pools[i];

		if ( name in pool$nodes )
			mark_pool_node_alive(pool, name);
		}
	}

event Cluster::node_down(name: string, id: string) &priority=10
	{
	for ( i in registered_pools )
		{
		local pool = registered_pools[i];

		if ( name in pool$nodes )
			mark_pool_node_dead(pool, name);
		}
	}

function site_id_in_pool(pool: Pool, site_id: count): bool
	{
	for ( _, pn in pool$nodes )
		{
		if ( pn$site_id == site_id )
			return T;
		}

	return F;
	}

function init_pool_node(pool: Pool, name: string): bool
	{
	if ( name in pool$nodes )
		return F;

	local loop = T;
	local c = 0;

	while ( loop )
		{



		local alias = name + fmt(".%s", c);
		local site_id = fnv1a32(alias);

		if ( site_id_in_pool(pool, site_id) )
			++c;
		else
			{
			local pn = PoolNode($name=name, $alias=alias, $site_id=site_id,
			                    $alive=Cluster::node == name, $topic=Cluster::node_topic(name));
			pool$nodes[name] = pn;
			pool$node_list += pn;

			if ( pn$alive )
				++pool$alive_count;

			loop = F;
			}
		}

	return T;
	}

function mark_pool_node_alive(pool: Pool, name: string): bool
	{
	if ( name !in pool$nodes )
		return F;

	local pn = pool$nodes[name];

	if ( ! pn$alive )
		{
		pn$alive = T;
		++pool$alive_count;
		}

	HashHRW::add_site(pool$hrw_pool, HashHRW::Site($id=pn$site_id, $user_data=pn));
	return T;
	}

function mark_pool_node_dead(pool: Pool, name: string): bool
	{
	if ( name !in pool$nodes )
		return F;

	local pn = pool$nodes[name];

	if ( pn$alive )
		{
		pn$alive = F;
		--pool$alive_count;
		}

	HashHRW::rem_site(pool$hrw_pool, HashHRW::Site($id=pn$site_id, $user_data=pn));
	return T;
	}

event zeek_init()
	{
	worker_pool = register_pool(worker_pool_spec);
	proxy_pool = register_pool(proxy_pool_spec);
	logger_pool = register_pool(logger_pool_spec);
	}

type PoolEligibilityTracking: record {
	eligible_nodes: vector of NamedNode &default = vector();
	next_idx: count &default = 0;
	excluded: count &default = 0;
};

global pool_eligibility: table[Cluster::NodeType] of PoolEligibilityTracking = table();

function pool_sorter(a: Pool, b: Pool): int
	{
	return strcmp(a$spec$topic, b$spec$topic);
	}


event zeek_init() &priority=-5
	{
	if ( ! Cluster::is_enabled() )
		return;



	sort(registered_pools, pool_sorter);

	pool_eligibility[Cluster::WORKER] =
		PoolEligibilityTracking($eligible_nodes = nodes_with_type(Cluster::WORKER));
	pool_eligibility[Cluster::PROXY] =
		PoolEligibilityTracking($eligible_nodes = nodes_with_type(Cluster::PROXY));
	pool_eligibility[Cluster::LOGGER] =
		PoolEligibilityTracking($eligible_nodes = nodes_with_type(Cluster::LOGGER));

	if ( manager_is_logger )
		{
		local mgr = nodes_with_type(Cluster::MANAGER);

		if ( |mgr| > 0 )
			{
			local eln = pool_eligibility[Cluster::LOGGER]$eligible_nodes;
			eln += mgr[0];
			}
		}

	local pool: Pool;
	local pet: PoolEligibilityTracking;
	local en: vector of NamedNode;

	for ( i in registered_pools )
		{
		pool = registered_pools[i];

		if ( pool$spec$node_type !in pool_eligibility )
			Reporter::fatal(fmt("invalid pool node type: %s", pool$spec$node_type));

		if ( ! pool$spec$exclusive )
			next;

		if ( ! pool$spec?$max_nodes )
			Reporter::fatal("Cluster::PoolSpec 'max_nodes' field must be set when using the 'exclusive' flag");

		pet = pool_eligibility[pool$spec$node_type];
		pet$excluded += pool$spec$max_nodes;
		}

	for ( nt, pet in pool_eligibility )
		{
		if ( pet$excluded > |pet$eligible_nodes| )
			Reporter::fatal(fmt("not enough %s nodes to satisfy pool exclusivity requirements: need %d nodes", nt, pet$excluded));
		}

	for ( i in registered_pools )
		{
		pool = registered_pools[i];

		if ( ! pool$spec$exclusive )
			next;

		pet = pool_eligibility[pool$spec$node_type];

		local e = 0;

		while ( e < pool$spec$max_nodes )
			{
			init_pool_node(pool, pet$eligible_nodes[e]$name);
			++e;
			}

		local nen: vector of NamedNode = vector();

		for ( j in pet$eligible_nodes )
			{
			if ( j < e )
				next;

			nen += pet$eligible_nodes[j];
			}

		pet$eligible_nodes = nen;
		}

	for ( i in registered_pools )
		{
		pool = registered_pools[i];

		if ( pool$spec$exclusive )
			next;

		pet = pool_eligibility[pool$spec$node_type];
		local nodes_to_init = |pet$eligible_nodes|;

		if ( pool$spec?$max_nodes &&
			 pool$spec$max_nodes < |pet$eligible_nodes| )
			nodes_to_init = pool$spec$max_nodes;

		local nodes_inited = 0;

		while ( nodes_inited < nodes_to_init )
			{
			init_pool_node(pool, pet$eligible_nodes[pet$next_idx]$name);
			++nodes_inited;
			++pet$next_idx;

			if ( pet$next_idx == |pet$eligible_nodes| )
				pet$next_idx = 0;
			}
		}
	}
