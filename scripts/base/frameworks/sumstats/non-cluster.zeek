@load ./main

module SumStats;

event SumStats::process_epoch_result(ss: SumStat, now: time, data: ResultTable)
	{

	local i = 50;
	local keys_to_delete: vector of SumStats::Key = vector();

	for ( key, res in data )
		{
		ss$epoch_result(now, key, res);
		keys_to_delete += key;

		if ( --i == 0 )
			break;
		}

	for ( idx in keys_to_delete )
		delete data[keys_to_delete[idx]];

	if ( |data| > 0 )

		schedule 0.01 secs { SumStats::process_epoch_result(ss, now, data) };
	else if ( ss?$epoch_finished )
		ss$epoch_finished(now);
	}


function do_finish_epoch(ss: SumStat)
	{
	if ( ss$name !in result_store || ! ss?$epoch_result )
		return;

	local data = result_store[ss$name];
	local now = network_time();
	if ( zeek_is_terminating() )
		{
		for ( key, val in data )
			ss$epoch_result(now, key, val);

		if ( ss?$epoch_finished )
			ss$epoch_finished(now);
		}
	else
		{
		if ( |data| > 0 )
			event SumStats::process_epoch_result(ss, now, copy(data));
		else
			{
			if ( ss?$epoch_finished )
				ss$epoch_finished(now);
			}
		}


	reset(ss);

	if ( ss$epoch != 0secs )
		schedule ss$epoch { SumStats::finish_epoch(ss) };
	}

event SumStats::finish_epoch(ss: SumStat)
	{
	if ( zeek_is_terminating() )
		return;

	do_finish_epoch(ss);
	}




event zeek_done() &priority=10
	{
	for ( name, ss in stats_store )
		{
		if ( ss$epoch != 0sec )
			do_finish_epoch(ss);
		}
	}

function data_added(ss: SumStat, key: Key, result: Result)
	{
	if ( check_thresholds(ss, key, result, 1.0) )
		threshold_crossed(ss, key, result);
	}

function request_key(ss_name: string, key: Key): Result
	{

	return when [ss_name, key] ( T )
		{
		if ( ss_name in result_store && key in result_store[ss_name] )
			return result_store[ss_name][key];
		else
			return table();
		}
	}
