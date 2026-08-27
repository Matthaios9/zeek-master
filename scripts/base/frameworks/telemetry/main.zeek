





@load base/misc/version
@load base/bif/telemetry_functions.bif
@load base/frameworks/telemetry/options

module Telemetry;

export {

	type labels_vector: vector of string;






	type CounterFamily: record {
		__family: opaque of counter_metric_family;
		__labels: vector of string;
	};









	type Counter: record {
		__metric: opaque of counter_metric;
	};


	global register_counter_family: function(opts: MetricOpts): CounterFamily;


	global counter_with: function(cf: CounterFamily,
	                              label_values: labels_vector &default=vector()): Counter;









	global counter_inc: function(c: Counter, amount: double &default=1.0): bool;












	global counter_set: function(c: Counter, value: double): bool;












	global counter_family_inc: function(cf: CounterFamily,
	                                    label_values: labels_vector &default=vector(),
	                                    amount: double &default=1.0): bool;













	global counter_family_set: function(cf: CounterFamily,
	                                    label_values: labels_vector,
	                                    value: double): bool;







	type GaugeFamily: record {
		__family: opaque of gauge_metric_family;
		__labels: vector of string;
	};








	type Gauge: record {
		__metric: opaque of gauge_metric;
	};


	global register_gauge_family: function(opts: MetricOpts): GaugeFamily;



	global gauge_with: function(gf: GaugeFamily,
	                            label_values: labels_vector &default=vector()): Gauge;








	global gauge_inc: function(g: Gauge, amount: double &default=1.0): bool;








	global gauge_dec: function(g: Gauge, amount: double &default=1.0): bool;








	global gauge_set: function(g: Gauge, value: double): bool;













	global gauge_family_inc: function(gf: GaugeFamily,
	                                  label_values: labels_vector &default=vector(),
	                                  amount: double &default=1.0): bool;












	global gauge_family_dec: function(gf: GaugeFamily,
	                                  label_values: labels_vector &default=vector(),
	                                  amount: double &default=1.0): bool;












	global gauge_family_set: function(g: GaugeFamily,
	                                  label_values: labels_vector,
	                                  value: double): bool;





	type HistogramFamily: record {
		__family: opaque of histogram_metric_family;
		__labels: vector of string;
	};



	type Histogram: record {
		__metric: opaque of histogram_metric;
	};


	global register_histogram_family: function(opts: MetricOpts): HistogramFamily;


	global histogram_with: function(hf: HistogramFamily,
	                                label_values: labels_vector &default=vector()): Histogram;








	global histogram_observe: function(h: Histogram, measurement: double): bool;












	global histogram_family_observe: function(hf: HistogramFamily,
	                                          label_values: labels_vector,
	                                          measurement: double): bool;







	global collect_metrics: function(prefix: string &default="*",
	                                 name: string &default="*"): vector of Metric;






	global collect_histogram_metrics: function(prefix: string &default="*",
	                                           name: string &default="*"): vector of HistogramMetric;
}


function make_labels(keys: vector of string, values: labels_vector): table[string] of string
	{
	local labels: table[string] of string;
	for ( i in keys )
		labels[keys[i]] = values[i];

	return labels;
	}

function register_counter_family(opts: MetricOpts): CounterFamily
	{
	local f = Telemetry::__counter_family(
		opts$prefix,
		opts$name,
		opts$label_names,
		opts$help_text,
		opts$unit
	);
	return CounterFamily($__family=f, $__labels=opts$label_names);
	}


global error_counter_cf = register_counter_family(MetricOpts(
	$prefix="zeek",
	$name="telemetry_counter_usage_error",
	$unit="",
	$help_text="This counter is returned when label usage for counters is wrong. Check reporter.log if non-zero."
));

function counter_with(cf: CounterFamily, label_values: labels_vector): Counter
	{
	if ( |cf$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |cf$__labels|, |label_values|));
		return counter_with(error_counter_cf);
		}

	local labels = make_labels(cf$__labels, label_values);
	local m = Telemetry::__counter_metric_get_or_add(cf$__family, labels);
	return Counter($__metric=m);
	}

function counter_inc(c: Counter, amount: double): bool
	{
	return Telemetry::__counter_inc(c$__metric, amount);
	}

function counter_set(c: Counter, value: double): bool
	{
	local cur_value: double = Telemetry::__counter_value(c$__metric);
	if (value < cur_value)
		{
		Reporter::error(fmt("Attempted to set lower counter value=%s cur_value=%s", value, cur_value));
		return F;
		}
	return Telemetry::__counter_inc(c$__metric, value - cur_value);
	}

function counter_family_inc(cf: CounterFamily, label_values: labels_vector, amount: double): bool
	{
	return counter_inc(counter_with(cf, label_values), amount);
	}

function counter_family_set(cf: CounterFamily, label_values: labels_vector, value: double): bool
	{
	return counter_set(counter_with(cf, label_values), value);
	}

function register_gauge_family(opts: MetricOpts): GaugeFamily
	{
	local f = Telemetry::__gauge_family(
		opts$prefix,
		opts$name,
		opts$label_names,
		opts$help_text,
		opts$unit
	);
	return GaugeFamily($__family=f, $__labels=opts$label_names);
	}


global error_gauge_cf = register_gauge_family(MetricOpts(
	$prefix="zeek",
	$name="telemetry_gauge_usage_error",
	$unit="",
	$help_text="This gauge is returned when label usage for gauges is wrong. Check reporter.log if non-zero."
));

function gauge_with(gf: GaugeFamily, label_values: labels_vector): Gauge
	{
	if ( |gf$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |gf$__labels|, |label_values|));
		return gauge_with(error_gauge_cf);
		}
	local labels = make_labels(gf$__labels, label_values);
	local m = Telemetry::__gauge_metric_get_or_add(gf$__family, labels);
	return Gauge($__metric=m);
	}

function gauge_inc(g: Gauge, amount: double &default=1.0): bool
	{
	return Telemetry::__gauge_inc(g$__metric, amount);
	}

function gauge_dec(g: Gauge, amount: double &default=1.0): bool
	{
	return Telemetry::__gauge_dec(g$__metric, amount);
	}

function gauge_set(g: Gauge, value: double): bool
	{


	local cur_value: double = Telemetry::__gauge_value(g$__metric);
	if (value > cur_value)
		return Telemetry::__gauge_inc(g$__metric, value - cur_value);

	return Telemetry::__gauge_dec(g$__metric, cur_value - value);
	}

function gauge_family_inc(gf: GaugeFamily, label_values: labels_vector, value: double): bool
	{
	return gauge_inc(gauge_with(gf, label_values), value);
	}

function gauge_family_dec(gf: GaugeFamily, label_values: labels_vector, value: double): bool
	{
	return gauge_dec(gauge_with(gf, label_values), value);
	}

function gauge_family_set(gf: GaugeFamily, label_values: labels_vector, value: double): bool
	{
	return gauge_set(gauge_with(gf, label_values), value);
	}

function register_histogram_family(opts: MetricOpts): HistogramFamily
	{
	local f = Telemetry::__histogram_family(
		opts$prefix,
		opts$name,
		opts$label_names,
		opts$bounds,
		opts$help_text,
		opts$unit
	);
	return HistogramFamily($__family=f, $__labels=opts$label_names);
	}


global error_histogram_hf = register_histogram_family(MetricOpts(
	$prefix="zeek",
	$name="telemetry_histogram_usage_error",
	$unit="",
	$help_text="This histogram is returned when label usage for histograms is wrong. Check reporter.log if non-zero.",
	$bounds=vector(1.0)
));

function histogram_with(hf: HistogramFamily, label_values: labels_vector): Histogram
	{
	if ( |hf$__labels| != |label_values| )
		{
		Reporter::error(fmt("Invalid label values expected %s, have %s", |hf$__labels|, |label_values|));
		return histogram_with(error_histogram_hf);
		}

	local labels = make_labels(hf$__labels, label_values);
	local m = Telemetry::__histogram_metric_get_or_add(hf$__family, labels);
	return Histogram($__metric=m);
	}

function histogram_observe(h: Histogram, measurement: double): bool
	{
	return Telemetry::__histogram_observe(h$__metric, measurement);
	}

function histogram_family_observe(hf: HistogramFamily, label_values: labels_vector, measurement: double): bool
	{
	return histogram_observe(histogram_with(hf, label_values), measurement);
	}

function collect_metrics(prefix: string, name: string): vector of Metric
	{
	return Telemetry::__collect_metrics(prefix, name);
	}

function collect_histogram_metrics(prefix: string, name: string): vector of HistogramMetric
	{
	return Telemetry::__collect_histogram_metrics(prefix, name);
	}


global version_gauge_family = Telemetry::register_gauge_family(Telemetry::MetricOpts(
	$prefix="zeek",
	$name="version_info",
	$unit="",
	$help_text="The Zeek version",
	$label_names=vector("version_number", "major", "minor", "patch", "commit",
                            "beta", "debug","version_string")
));

event zeek_init()
	{
	if ( getenv("ZEEKCTL_CHECK_CONFIG") == "" && (Telemetry::metrics_port as count) != 0 )
		{
		local expose_services_json = Cluster::local_node_type() == Cluster::MANAGER;
		local listen_addr = |Telemetry::metrics_address| > 0 ? Telemetry::metrics_address : "0.0.0.0";

		Telemetry::listen_prometheus(listen_addr, Telemetry::metrics_port, expose_services_json);
		}

	local v = Version::info;
	local labels = vector(cat(v$version_number),
	                      cat(v$major), cat(v$minor), cat (v$patch),
	                      cat(v$commit),
	                      v$beta ? "true" : "false",
	                      v$debug ? "true" : "false",
	                      v$version_string);

	Telemetry::gauge_family_set(version_gauge_family, labels, 1.0);
	}
