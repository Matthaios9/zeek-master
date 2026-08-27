


@load base/frameworks/telemetry

module Telemetry;

export {
	redef enum Log::ID += { LOG, LOG_HISTOGRAM };


	option log_interval = 60sec;










	option log_prefixes: set[string] = {"process", "zeek"};


	type Info: record {

		ts: time &log;


		peer: string &log;



		metric_type: string &log;


		name: string &log;


		labels: vector of string &log;


		label_values: vector of string &log;


		value: double &log;
	};


	type HistogramInfo: record {

		ts: time &log;


		peer: string &log;


		name: string &log;


		labels: vector of string &log;


		label_values: vector of string &log;


		bounds: vector of double &log;


		values: vector of double &log;


		sum: double &log;


		observations: double &log;
	};


	global log_policy: Log::PolicyHook;


	global log_policy_histogram: Log::PolicyHook;


	global log_telemetry: event(rec: Info);


	global log_telemetry_histogram: event(rec: HistogramInfo);
}

function do_log()
	{
	local ts = network_time();



	local metrics : vector of Telemetry::Metric;
	if ( |log_prefixes| > 0 )
		{
		for ( prefix in log_prefixes )
			{
			metrics += Telemetry::collect_metrics(prefix, "*");
			}
		}
	else
		{
		metrics = Telemetry::collect_metrics();
		}

	for ( i in metrics )
		{
		local m = metrics[i];


		if ( m$opts$metric_type == HISTOGRAM )
			next;



		local metric_type = "unknown";
		switch ( m$opts$metric_type ) {
			case COUNTER:
				metric_type = "counter";
				break;
			case GAUGE:
				metric_type = "gauge";
				break;
		}

		local rec = Info($ts=ts,
		                 $peer=peer_description,
		                 $metric_type=metric_type,
		                 $name=m$opts$name,
		                 $labels=m$label_names,
		                 $label_values=m$label_values,
		                 $value=m$value);

		Log::write(LOG, rec);
		}


	ts = network_time();

	local histogram_metrics : vector of Telemetry::HistogramMetric;
	if ( |log_prefixes| > 0 )
		{
		for ( prefix in log_prefixes )
			{
			histogram_metrics += Telemetry::collect_histogram_metrics(prefix, "*");
			}
		}
	else
		{
		histogram_metrics = Telemetry::collect_histogram_metrics();
		}

	for ( i in histogram_metrics )
		{
		local hm = histogram_metrics[i];

		local hrec = HistogramInfo($ts=ts,
		                           $peer=peer_description,
		                           $name=hm$opts$name,
		                           $labels=hm$label_names,
		                           $label_values=hm$label_values,
		                           $bounds=hm$opts$bounds,
		                           $values=hm$values,
		                           $sum=hm$sum,
		                           $observations=hm$observations);

		Log::write(LOG_HISTOGRAM, hrec);
		}
	}

event Telemetry::log()
	{


	if ( zeek_is_terminating() )
		return;

	do_log();
	schedule log_interval { Telemetry::log() };
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $ev=log_telemetry, $path="telemetry", $policy=log_policy));
	Log::create_stream(LOG_HISTOGRAM, Log::Stream($columns=HistogramInfo, $ev=log_telemetry_histogram, $path="telemetry_histogram", $policy=log_policy_histogram));

	schedule log_interval { Telemetry::log() };
	}



event zeek_done() &priority=-1000
	{
	do_log();
	}
