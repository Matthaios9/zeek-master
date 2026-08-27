





@load base/frameworks/cluster
@load ./main

module SumStats;

export {





	const cluster_request_global_view_percent = 0.2 &redef;






	const max_outstanding_global_views = 10 &redef;



	global cluster_ss_request: event(uid: string, ss_name: string, cleanup: bool);





	global cluster_get_result: event(uid: string, ss_name: string, key: Key, cleanup: bool);



	global cluster_send_result: event(uid: string, ss_name: string, key: Key, result: Result, cleanup: bool);




	global cluster_key_intermediate_response: event(ss_name: string, key: SumStats::Key);


	global send_data: event(uid: string, ss_name: string, data: ResultTable, cleanup: bool);

	global get_a_key: event(uid: string, ss_name: string, cleanup: bool &default=F);

	global send_a_key: event(uid: string, ss_name: string, key: Key);
	global send_no_key: event(uid: string, ss_name: string);


	global cluster_threshold_crossed: event(ss_name: string, key: SumStats::Key, thold_index: count);
}



global recent_global_view_keys: set[string, Key] &create_expire=1min;

@if ( Cluster::local_node_type() != Cluster::MANAGER )



global sending_results: table[string] of ResultTable = table() &read_expire=1min;



function data_added(ss: SumStat, key: Key, result: Result)
	{

	if ( [ss$name, key] in recent_global_view_keys )
		return;




	if ( check_thresholds(ss, key, result, cluster_request_global_view_percent) )
		{

		Cluster::publish(Cluster::manager_topic, SumStats::cluster_key_intermediate_response,
		                 ss$name, key);
		add recent_global_view_keys[ss$name, key];
		}
	}

event SumStats::get_a_key(uid: string, ss_name: string, cleanup: bool)
	{
	if ( uid in sending_results )
		{
		if ( |sending_results[uid]| == 0 )
			{
			Cluster::publish(Cluster::manager_topic, SumStats::send_no_key,
			                 uid, ss_name);
			}
		else
			{
			for ( key in sending_results[uid] )
				{
				Cluster::publish(Cluster::manager_topic, SumStats::send_a_key,
				                 uid, ss_name, key);

				break;
				}
			}
		}
	else if ( !cleanup && ss_name in result_store && |result_store[ss_name]| > 0 )
		{
		if ( |result_store[ss_name]| == 0 )
			{
			event SumStats::send_no_key(uid, ss_name);
			}
		else
			{
			for ( key in result_store[ss_name] )
				{
				Cluster::publish(Cluster::manager_topic, SumStats::send_a_key,
				                 uid, ss_name, key);

				break;
				}
			}
		}
	else
		{
		Cluster::publish(Cluster::manager_topic, SumStats::send_no_key,
				 uid, ss_name);
		}
	}

event SumStats::cluster_ss_request(uid: string, ss_name: string, cleanup: bool)
	{



	sending_results[uid] = (ss_name in result_store) ? result_store[ss_name] : table();




	if ( cleanup && ss_name in stats_store )
		reset(stats_store[ss_name]);
	}

event SumStats::cluster_get_result(uid: string, ss_name: string, key: Key, cleanup: bool)
	{


	if ( cleanup )
		{
		if ( uid in sending_results && key in sending_results[uid] )
			{
			Cluster::publish(Cluster::manager_topic, SumStats::cluster_send_result,
			                 uid, ss_name, key, sending_results[uid][key], cleanup);
			delete sending_results[uid][key];
			}
		else
			{


			Cluster::publish(Cluster::manager_topic, SumStats::cluster_send_result,
			                 uid, ss_name, key, table(), cleanup);
			}
		}
	else
		{
		if ( ss_name in result_store && key in result_store[ss_name] )
			{
			Cluster::publish(Cluster::manager_topic, SumStats::cluster_send_result,
			                 uid, ss_name, key, result_store[ss_name][key], cleanup);
			}
		else
			{


			Cluster::publish(Cluster::manager_topic, SumStats::cluster_send_result,
			                 uid, ss_name, key, table(), cleanup);
			}
		}
	}

event SumStats::cluster_threshold_crossed(ss_name: string, key: SumStats::Key, thold_index: count)
	{
	if ( ss_name !in threshold_tracker )
		threshold_tracker[ss_name] = table();

	threshold_tracker[ss_name][key] = thold_index;
	}









function request_key(ss_name: string, key: Key): Result
	{
	return Result();
	}

@endif


@if ( Cluster::local_node_type() == Cluster::MANAGER )




global stats_keys: table[string] of set[Key] &read_expire=1min
	&expire_func=function(s: table[string] of set[Key], idx: string): interval
		{
		Reporter::warning(fmt("SumStat key request for the %s SumStat uid took longer than 1 minute and was automatically cancelled.", idx));
		return 0secs;
		};






global done_with: table[string] of count &read_expire=1min &default=0;




global key_requests: table[string] of Result &read_expire=1min;



global dynamic_requests: set[string] &read_expire=1min;





global outstanding_global_views: table[string] of set[string] &read_expire=1min;

const zero_time = double_to_time(0.0);

event SumStats::finish_epoch(ss: SumStat)
	{
	if ( network_time() > zero_time )
		{

		local uid = unique_id("");

		if ( uid in stats_keys )
			delete stats_keys[uid];
		stats_keys[uid] = set();


		Cluster::publish(Cluster::worker_topic, SumStats::cluster_ss_request,
		                 uid, ss$name, T);

		done_with[uid] = 0;


		Cluster::publish(Cluster::worker_topic, SumStats::get_a_key,
		                 uid, ss$name, T);
		}


	if ( ss$epoch != 0secs )
		schedule ss$epoch { SumStats::finish_epoch(ss) };
	}



function data_added(ss: SumStat, key: Key, result: Result)
	{
	if ( check_thresholds(ss, key, result, 1.0) )
		{
		threshold_crossed(ss, key, result);
		Cluster::publish(Cluster::worker_topic, SumStats::cluster_threshold_crossed,
		                 ss$name, key, threshold_tracker[ss$name][key]);
		}
	}

function handle_end_of_result_collection(uid: string, ss_name: string, key: Key, cleanup: bool)
	{
	if ( uid !in key_requests )
		{
		Reporter::warning(fmt("Tried to handle end of result collection with missing uid in key_request sumstat:%s, key:%s.", ss_name, key));
		return;
		}

	local ss = stats_store[ss_name];
	local ir = key_requests[uid];
	if ( check_thresholds(ss, key, ir, 1.0) )
		{
		threshold_crossed(ss, key, ir);
		Cluster::publish(Cluster::worker_topic, SumStats::cluster_threshold_crossed,
		                 ss_name, key, threshold_tracker[ss_name][key]);
		}

	if ( cleanup )
		{


		if ( ss?$epoch_result && |ir| > 0 )
			{
			local now = network_time();
			ss$epoch_result(now, key, ir);
			}

		}

	if ( ss_name in outstanding_global_views )
		delete outstanding_global_views[ss_name][uid];

	delete key_requests[uid];
	delete done_with[uid];
	}

function request_all_current_keys(uid: string, ss_name: string, cleanup: bool)
	{

	if ( uid in stats_keys && |stats_keys[uid]| > 0 )
		{

		local key: Key;
		for ( k in stats_keys[uid] )
			{
			key = k;
			break;
			}

		done_with[uid] = 0;
		Cluster::publish(Cluster::worker_topic, SumStats::cluster_get_result,
		                 uid, ss_name, key, cleanup);
		delete stats_keys[uid][key];
		}
	else
		{

		done_with[uid] = 0;

		Cluster::publish(Cluster::worker_topic, SumStats::get_a_key,
		                 uid, ss_name, cleanup);
		}
	}

event SumStats::send_no_key(uid: string, ss_name: string)
	{


	if ( uid !in done_with )
		done_with[uid] = 0;

	++done_with[uid];
	if ( Cluster::get_active_node_count(Cluster::WORKER) == done_with[uid] )
		{
		delete done_with[uid];

		if ( uid in stats_keys && |stats_keys[uid]| > 0 )
			{



			request_all_current_keys(uid, ss_name, T);
			}
		else
			{

			local ss = stats_store[ss_name];
			if ( ss?$epoch_finished )
				ss$epoch_finished(network_time());

			delete stats_keys[uid];
			reset(ss);
			}
		}
	}

event SumStats::send_a_key(uid: string, ss_name: string, key: Key)
	{

	if ( uid !in stats_keys )
		{
		Reporter::warning(fmt("Manager received a uid for an unknown request.  SumStat: %s, Key: %s", ss_name, key));
		return;
		}

	if ( key !in stats_keys[uid] )
		add stats_keys[uid][key];

	++done_with[uid];
	if ( Cluster::get_active_node_count(Cluster::WORKER) == done_with[uid] )
		{
		delete done_with[uid];

		if ( |stats_keys[uid]| > 0 )
			{



			request_all_current_keys(uid, ss_name, T);
			}
		else
			{

			local ss = stats_store[ss_name];
			if ( ss?$epoch_finished )
				ss$epoch_finished(network_time());

			reset(ss);
			}
		}
	}

event SumStats::cluster_send_result(uid: string, ss_name: string, key: Key, result: Result, cleanup: bool)
	{





	if ( uid !in key_requests || |key_requests[uid]| == 0 )
		key_requests[uid] = result;
	else
		key_requests[uid] = compose_results(key_requests[uid], result);


	if ( uid !in done_with )
		done_with[uid] = 0;


	++done_with[uid];

	if ( uid !in dynamic_requests &&
	     uid in done_with && Cluster::get_active_node_count(Cluster::WORKER) == done_with[uid] )
		{
		handle_end_of_result_collection(uid, ss_name, key, cleanup);

		if ( cleanup )
			request_all_current_keys(uid, ss_name, cleanup);
		}
	}


event SumStats::cluster_key_intermediate_response(ss_name: string, key: Key)
	{



	if ( [ss_name, key] in recent_global_view_keys )
		return;
	add recent_global_view_keys[ss_name, key];

	if ( ss_name !in outstanding_global_views)
		outstanding_global_views[ss_name] = set();
	else if ( |outstanding_global_views[ss_name]| > max_outstanding_global_views )
		{



		return;
		}

	local uid = unique_id("");
	add outstanding_global_views[ss_name][uid];
	done_with[uid] = 0;

	Cluster::publish(Cluster::worker_topic, SumStats::cluster_get_result,
	                 uid, ss_name, key, F);
	}

function request_key(ss_name: string, key: Key): Result
	{
	local uid = unique_id("");
	done_with[uid] = 0;
	key_requests[uid] = table();
	add dynamic_requests[uid];

	Cluster::publish(Cluster::worker_topic, SumStats::cluster_get_result,
	                 uid, ss_name, key, F);
	return when [uid, ss_name, key] ( uid in done_with &&
		Cluster::get_active_node_count(Cluster::WORKER) == done_with[uid] )
		{

		local result = key_requests[uid];

		delete key_requests[uid];
		delete done_with[uid];
		delete dynamic_requests[uid];

		return result;
		}
	timeout 1.1min
		{
		Reporter::warning(fmt("Dynamic SumStat key request for %s in SumStat %s took longer than 1 minute and was automatically cancelled.", key, ss_name));
		return Result();
		}
	}

@endif
