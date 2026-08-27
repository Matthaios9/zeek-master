



module SumStats;

export {


	type Calculation: enum {
		PLACEHOLDER
	};



	type Key: record {









		str:  string &optional;


		host: addr &optional;
	};



	type Observation: record {

		num:  count  &optional;

		dbl:  double &optional;

		str:  string &optional;
	};


	type Reducer: record {


		stream:         string;


		apply:          set[Calculation];



		pred:           function(key: SumStats::Key, obs: SumStats::Observation): bool &optional;



		normalize_key:  function(key: SumStats::Key): Key &optional;
	};



	type ResultVal: record {


		begin:  time;



		end:    time;


		num:    count &default=0;
	};



	type Result: table[string] of ResultVal;


	type ResultTable: table[Key] of Result;









	type SumStat: record {


		name:               string;











		epoch:              interval;


		reducers:           set[Reducer];






		threshold_val:      function(key: SumStats::Key, result: SumStats::Result): double &optional;




		threshold:          double            &optional;





		threshold_series:   vector of double  &optional;





		threshold_crossed:  function(key: SumStats::Key, result: SumStats::Result) &optional;




		epoch_result:       function(ts: time, key: SumStats::Key, result: SumStats::Result) &optional;




		epoch_finished:     function(ts:time) &optional;
	};




	global create: function(ss: SumStats::SumStat);










	global observe: function(id: string, key: SumStats::Key, obs: SumStats::Observation);












	global request_key: function(ss_name: string, key: Key): Result;







	global key2str: function(key: SumStats::Key): string;
















	global next_epoch: function(ss_name: string): bool;
}


type ObserveFunc: function(r: Reducer, val: double, data: Observation, rv: ResultVal);

redef record Reducer += {

	ssname: string &optional;

	calc_funcs: vector of Calculation &optional;
};




global threshold_tracker: table[string] of table[Key] of count;

function increment_threshold_tracker(ss_name: string, key: Key)
	{
	if ( ss_name !in threshold_tracker )
		threshold_tracker[ss_name] = table();
	if ( key !in threshold_tracker[ss_name] )
		threshold_tracker[ss_name][key] = 0;

	++threshold_tracker[ss_name][key];
	}

function get_threshold_index(ss_name: string, key: Key): count
	{
	if ( ss_name !in threshold_tracker )
		return 0;
	if ( key !in threshold_tracker[ss_name] )
		return 0;

	return threshold_tracker[ss_name][key];
	}


global init_resultval_hook: hook(r: Reducer, rv: ResultVal);


global compose_resultvals_hook: hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal);


global stats_store: table[string] of SumStat = table();


global reducer_store: table[string] of set[Reducer] = table();


global result_store: table[string] of ResultTable = table();


global thresholds_store: table[string, Key] of bool = table();


global calc_store: table[Calculation] of ObserveFunc = table();


global calc_deps: table[Calculation] of vector of Calculation = table();


global register_observe_plugins: hook();




global data_added: function(ss: SumStat, key: Key, result: Result);



global finish_epoch: event(ss: SumStat);

function next_epoch(ss_name: string): bool
	{
	if ( ss_name !in stats_store )
		return F;

	local ss = stats_store[ss_name];
	if ( ss$epoch != 0secs )
		return F;

	event SumStats::finish_epoch(ss);
	return T;
	}

function key2str(key: Key): string
	{
	local out = "";
	if ( key?$host )
		out = fmt("%shost=%s", out, key$host);
	if ( key?$str )
		out = fmt("%s%sstr=%s", out, |out|==0 ? "" : ", ", key$str);
	return fmt("sumstats_key(%s)", out);
	}

function register_observe_plugin(calc: Calculation, func: ObserveFunc)
	{
	calc_store[calc] = func;
	}

function add_observe_plugin_dependency(calc: Calculation, depends_on: Calculation)
	{
	if ( calc !in calc_deps )
		calc_deps[calc] = vector();
	calc_deps[calc] += depends_on;
	}

event zeek_init() &priority=100000
	{

	hook register_observe_plugins();
	}

function init_resultval(r: Reducer): ResultVal
	{
	local rv = ResultVal($begin=network_time(), $end=network_time());
	hook init_resultval_hook(r, rv);
	return rv;
	}

function compose_resultvals(rv1: ResultVal, rv2: ResultVal): ResultVal
	{
	local result: ResultVal;

	result$begin = (rv1$begin < rv2$begin) ? rv1$begin : rv2$begin;
	result$end = (rv1$end > rv2$end) ? rv1$end : rv2$end;
	result$num = rv1$num + rv2$num;


	hook compose_resultvals_hook(result, rv1, rv2);
	return result;
	}

function compose_results(r1: Result, r2: Result): Result &is_used
	{
	local result: Result = table();

	for ( id, rv in r1 )
		{
		result[id] = rv;
		}

	for ( id, rv in r2 )
		{
		if ( id in r1 )
			result[id] = compose_resultvals(r1[id], rv);
		else
			result[id] = rv;
		}

	return result;
	}


function reset(ss: SumStat)
	{
	if ( ss$name in result_store )
		delete result_store[ss$name];

	result_store[ss$name] = table();

	if ( ss$name in threshold_tracker )
		{
		delete threshold_tracker[ss$name];
		threshold_tracker[ss$name] = table();
		}
	}



function add_calc_deps(calcs: vector of Calculation, c: Calculation)
	{

	for ( i in calc_deps[c] )
		{
		local skip_calc=F;
		for ( j in calcs )
			{
			if ( calcs[j] == calc_deps[c][i] )
				skip_calc=T;
			}
		if ( ! skip_calc )
			{
			if ( calc_deps[c][i] in calc_deps )
				add_calc_deps(calcs, calc_deps[c][i]);
			calcs += calc_deps[c][i];

			}
		}

	}

function create(ss: SumStat)
	{
	if ( (ss?$threshold || ss?$threshold_series) && ! ss?$threshold_val )
		{
		Reporter::error("SumStats given a threshold with no $threshold_val function");
		}

	stats_store[ss$name] = ss;

	if ( ss?$threshold || ss?$threshold_series )
		threshold_tracker[ss$name] = table();

	for ( reducer in ss$reducers )
		{
		reducer$ssname = ss$name;
		reducer$calc_funcs = vector();
		for ( calc in reducer$apply )
			{

			if ( calc in calc_deps )
				add_calc_deps(reducer$calc_funcs, calc);




			local skip_calc=F;
			for ( j in reducer$calc_funcs )
				{
				if ( calc == reducer$calc_funcs[j] )
					skip_calc=T;
				}
			if ( ! skip_calc )
				reducer$calc_funcs += calc;
			}

		if ( reducer$stream !in reducer_store )
			reducer_store[reducer$stream] = set();
		add reducer_store[reducer$stream][reducer];
		}

	reset(ss);


	if ( ss$epoch != 0secs )
		schedule ss$epoch { SumStats::finish_epoch(ss) };
	}

function observe(id: string, orig_key: Key, obs: Observation)
	{
	if ( id !in reducer_store )
		return;


	for ( r in reducer_store[id] )
		{
		local key = r?$normalize_key ? r$normalize_key(copy(orig_key)) : orig_key;



		if ( r?$pred && ! r$pred(key, obs) )
			next;

		local ss = stats_store[r$ssname];









		if ( ! ss?$epoch_result &&
			 r$ssname in threshold_tracker &&
		     ( ss?$threshold &&
		       key in threshold_tracker[r$ssname] &&
		       threshold_tracker[r$ssname][key] != 0 ) ||
		     ( ss?$threshold_series &&
		       key in threshold_tracker[r$ssname] &&
		       threshold_tracker[r$ssname][key] == |ss$threshold_series| ) )
			{
			next;
			}

		if ( r$ssname !in result_store )
			result_store[r$ssname] = table();
		local results = result_store[r$ssname];

		if ( key !in results )
			results[key] = table();
		local result = results[key];

		if ( id !in result )
			result[id] = init_resultval(r);
		local result_val = result[id];

		++result_val$num;

		result_val$end=network_time();


		local val = 1.0;
		if ( obs?$num )
			val = obs$num;
		else if ( obs?$dbl )
			val = obs$dbl;

		for ( i in r$calc_funcs )
			calc_store[r$calc_funcs[i]](r, val, obs, result_val);
		data_added(ss, key, result);
		}
	}



function check_thresholds(ss: SumStat, key: Key, result: Result, modify_pct: double): bool
	{
	if ( ! (ss?$threshold || ss?$threshold_series || ss?$threshold_crossed) )
		return F;




	if ( |ss$reducers| != |result| )
		{
		for ( reducer in ss$reducers )
			{
			if ( reducer$stream !in result )
				result[reducer$stream] = init_resultval(reducer);
			}
		}

	local watch = ss$threshold_val(key, result);

	if ( modify_pct < 1.0 && modify_pct > 0.0 )
		watch = watch/modify_pct;

	local t_index = get_threshold_index(ss$name, key);

	if ( ss?$threshold &&
	     t_index == 0 &&
	     watch >= ss$threshold )
		{

		return T;
		}

	if ( ss?$threshold_series &&
	     |ss$threshold_series| > t_index &&
	     watch >= ss$threshold_series[t_index] )
		{


		return T;
		}

	return F;
	}

function threshold_crossed(ss: SumStat, key: Key, result: Result) &is_used
	{

	if ( ! ss?$threshold_crossed )
		return;

	increment_threshold_tracker(ss$name,key);


	if ( |ss$reducers| != |result| )
		{
		for ( reducer in ss$reducers )
			{
			if ( reducer$stream !in result )
				result[reducer$stream] = init_resultval(reducer);
			}
		}

	ss$threshold_crossed(key, result);
	}
