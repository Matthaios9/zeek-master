





@load base/frameworks/notice
@load base/frameworks/analyzer
@load ./utils

module PacketFilter;

export {

	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;


	redef enum Notice::Type += {

		Compile_Failure,


		Install_Failure,


		Too_Long_To_Compile_Filter
	};



	type Info: record {

		ts:     time   &log;




		node:   string &log &optional;


		filter: string &log;


		init:   bool   &log &default=F;


		success: bool  &log &default=T;


		failure_reason: string &log &optional;
	};




	const default_capture_filter = "ip or not ip" &redef;



	const unrestricted_filter = "" &redef;




	const restricted_filter = "" &redef;





	const max_filter_compile_time = 100msec &redef;












	global exclude: function(filter_id: string, filter: string): bool;














	global exclude_for: function(filter_id: string, filter: string, span: interval): bool;









	global remove_exclude: function(filter_id: string): bool;



	global install: function(): bool;


	type FilterPlugin: record {

		func : function();
	};


	global register_filter_plugin: function(fp: FilterPlugin);





	const enable_auto_protocol_capture_filters = F &redef;



	global current_filter = "<not set yet>";
}

global dynamic_restrict_filters: table[string] of string = {};




global currently_building = F;


global filter_changed = F;

global filter_plugins: set[FilterPlugin] = {};

redef enum PcapFilterID += {
	DefaultPcapFilter,
	FilterTester,
};

function test_filter(filter: string): bool
	{
	if ( ! Pcap::precompile_pcap_filter(FilterTester, filter) )
		{


		return F;
		}
	return T;
	}



event filter_change_tracking()
	{
	if ( filter_changed )
		install();

	schedule 5min { filter_change_tracking() };
	}

event zeek_init() &priority=5
	{
	Log::create_stream(PacketFilter::LOG, Log::Stream($columns=Info, $path="packet_filter", $policy=log_policy));


	for ( id, cf in capture_filters )
		{
		if ( ! test_filter(cf) )
			Reporter::fatal(fmt("Invalid capture_filter named '%s' - '%s'", id, cf));
		}

	for ( id, rf in restrict_filters )
		{
		if ( ! test_filter(restrict_filters[id]) )
			Reporter::fatal(fmt("Invalid restrict filter named '%s' - '%s'", id, rf));
		}
	}

event zeek_init() &priority=-6
	{
	install();

	event filter_change_tracking();
	}

function register_filter_plugin(fp: FilterPlugin)
	{
	add filter_plugins[fp];
	}

event remove_dynamic_filter(filter_id: string)
	{
	remove_exclude(filter_id);
	}

function remove_exclude(filter_id: string): bool
	{
	if ( filter_id in dynamic_restrict_filters )
		{
		delete dynamic_restrict_filters[filter_id];
		install();
		return T;
		}
	return F;
	}

function exclude(filter_id: string, filter: string): bool
	{
	if ( ! test_filter(filter) )
		return F;

	dynamic_restrict_filters[filter_id] = filter;
	install();
	return T;
	}

function exclude_for(filter_id: string, filter: string, span: interval): bool
	{
	if ( exclude(filter_id, filter) )
		{
		schedule span { remove_dynamic_filter(filter_id) };
		return T;
		}
	return F;
	}

function build(): string
	{
	if ( cmd_line_bpf_filter != "" )

		return cmd_line_bpf_filter;

	currently_building = T;


	for ( plugin in filter_plugins )
		{
		plugin$func();
		}

	local cfilter = "";
	if ( |capture_filters| == 0 && ! enable_auto_protocol_capture_filters )
		cfilter = default_capture_filter;

	for ( _, cf in capture_filters )
		cfilter = combine_filters(cfilter, "or", cf);

	if ( enable_auto_protocol_capture_filters )
		cfilter = combine_filters(cfilter, "or", Analyzer::get_bpf());


	local rfilter = "";
	for ( _, rf in restrict_filters )
		rfilter = combine_filters(rfilter, "and", rf);


	for ( _, drf in dynamic_restrict_filters )
		rfilter = combine_filters(rfilter, "and", string_cat("not (", drf, ")"));


	local filter = combine_filters(cfilter, "and", rfilter);

	if ( unrestricted_filter != "" )
		filter = combine_filters(unrestricted_filter, "or", filter);
	if ( restricted_filter != "" )
		filter = combine_filters(restricted_filter, "and", filter);

	currently_building = F;
	return filter;
	}

function install(): bool
	{
	if ( currently_building )
		return F;

	local tmp_filter = build();


	if ( tmp_filter == current_filter )
		return F;

	local ts = current_time();

	if ( ! Pcap::precompile_pcap_filter(DefaultPcapFilter, tmp_filter) )
		{
		local state = Pcap::get_filter_state(DefaultPcapFilter);
		local error_string : string;
		if ( state == Pcap::fatal )
			{
			NOTICE(Notice::Info($note=Compile_Failure,
			                    $msg=fmt("Compiling packet filter failed"),
			                    $sub=tmp_filter));

			error_string = fmt("Bad pcap filter '%s': %s", tmp_filter,
			                   Pcap::get_filter_state_string(DefaultPcapFilter));

			if ( network_time() == 0.0 )
				Reporter::fatal(error_string);
			else
				Reporter::warning(error_string);
			}
		else if ( state == Pcap::warning )
			{
			error_string = fmt("Warning while compiling pcap filter '%s': %s",
			                   tmp_filter,
			                   Pcap::get_filter_state_string(DefaultPcapFilter));

			Reporter::warning(error_string);
			}
		}
	local diff = current_time()-ts;
	if ( diff > max_filter_compile_time )
		NOTICE(Notice::Info($note=Too_Long_To_Compile_Filter,
		                    $msg=fmt("A BPF filter is taking longer than %0.1f seconds to compile", diff)));


	current_filter = tmp_filter;


	local info: Info;
	info$ts = network_time();
	info$node = peer_description;

	if ( info$ts == 0.0 )
		{
		info$ts = current_time();
		info$init = T;
		}
	info$filter = current_filter;

	if ( ! Pcap::install_pcap_filter(DefaultPcapFilter) )
		{

		info$success = F;
		info$failure_reason = Pcap::get_filter_state_string(DefaultPcapFilter);

		NOTICE(Notice::Info($note=Install_Failure,
		                    $msg=fmt("Installing packet filter failed"),
		                    $sub=current_filter));
		}

	if ( reading_live_traffic() || reading_traces() )
		Log::write(PacketFilter::LOG, info);


	filter_changed = F;
	return T;
	}
