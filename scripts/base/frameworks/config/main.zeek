



@load base/frameworks/cluster

module Config;

export {

	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;


	type Info: record {

		ts: time &log;

		id: string &log;

		old_value: string &log;

		new_value: string &log;

		location: string &optional &log;
	};



	global log_config: event(rec: Info);














	global set_value: function(ID: string, val: any, location: string &default = ""): bool;
}

@if ( Cluster::is_enabled() )
type OptionCacheValue: record {
	val: any;
	location: string;
};

global option_cache: table[string] of OptionCacheValue;

global Config::cluster_set_option: event(ID: string, val: any, location: string);

function broadcast_option(ID: string, val: any, location: string) &is_used
	{
	for ( topic in Cluster::broadcast_topics )
		Cluster::publish(topic, Config::cluster_set_option, ID, val, location);
	}

event Config::cluster_set_option(ID: string, val: any, location: string)
	{
@if ( Cluster::local_node_type() == Cluster::MANAGER )
	option_cache[ID] = OptionCacheValue($val=val, $location=location);
	broadcast_option(ID, val, location);
@endif

	Option::set(ID, val, location);
	}

function set_value(ID: string, val: any, location: string &default = ""): bool
	{




	val = copy(val);


	if ( ! Option::set(ID, val, location) )
		return F;

@if ( Cluster::local_node_type() == Cluster::MANAGER )
	option_cache[ID] = OptionCacheValue($val=val, $location=location);
	broadcast_option(ID, val, location);
@else
	Cluster::publish(Cluster::manager_topic, Config::cluster_set_option,
	                ID, val, location);
@endif

	return T;
	}
@else
function set_value(ID: string, val: any, location: string &default = ""): bool
	{
	return Option::set(ID, val, location);
	}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )

event Cluster::node_up(name: string, id: string) &priority=-10
	{

	if ( name in Cluster::nodes )
		for ( ID in option_cache )
			Cluster::publish(Cluster::node_topic(name), Config::cluster_set_option, ID, option_cache[ID]$val, option_cache[ID]$location);
	}
@endif


function format_value(value: any) : string
	{
	local tn = type_name(value);
	local part: string_vec = vector();

	if ( /^set/ in tn && strstr(tn, ",") == 0 )
		{
		local vec = Option::any_set_to_any_vec(value);
		for ( sv in vec )
			part += cat(vec[sv]);
		return join_string_vec(part, ",");
		}
	else if ( /^vector/ in tn )
		{
		local vit: vector of any = value;
		for ( i in vit )
			part += cat(vit[i]);
		return join_string_vec(part, ",");
		}
	else if ( tn == "string" )
		return value;

	return cat(value);
	}

function config_option_changed(ID: string, new_value: any, location: string): any &is_used
	{

	if ( location == "<skip-config-log>" )
		return new_value;
	local log = Info($ts=network_time(), $id=ID, $old_value=format_value(lookup_ID(ID)), $new_value=format_value(new_value));
	if ( location != "" )
		log$location = location;
	Log::write(LOG, log);
	return new_value;
	}

event zeek_init() &priority=10
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $ev=log_config, $path="config", $policy=log_policy));


@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )


	for ( opt in global_options() )
		Option::set_change_handler(opt, config_option_changed, -100);
@endif
	}
