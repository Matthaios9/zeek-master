




module Log;

export {




	type Log::ID: enum {

		UNKNOWN,

		PRINTLOG
	};


	const enable_local_logging = T &redef;


	const enable_remote_logging = T &redef;


	const default_writer = WRITER_ASCII &redef;







	const default_logdir = "" &redef;



	const separator = "\t" &redef;



	const set_separator = "," &redef;




	const empty_field = "(empty)" &redef;



	const unset_field = "-" &redef;


















	global default_path_func: function(id: ID, path: string, rec: any) : string &redef;



	type PrintLogInfo: record {

		ts:                  time              &log;

		vals:                string_vec        &log;
	};


	type PrintLogType: enum {

		REDIRECT_NONE,


		REDIRECT_STDOUT,

		REDIRECT_ALL
	};


	global log_print: event(rec: PrintLogInfo);


	const print_to_log: PrintLogType = REDIRECT_NONE &redef;



	const print_log_path = "print" &redef;




	type RotationInfo: record {
		writer: Writer;
		fname: string;
		path: string;
		open: time;
		close: time;
		terminating: bool;
	};


	type RotationPostProcessorFunc: function(info: Log::RotationInfo): bool;



	type RotationFmtInfo: record {
		writer: Writer;
		path: string;
		open: time;
		close: time;
		terminating: bool;

		postprocessor: RotationPostProcessorFunc &optional;
	};






	const default_rotation_interval = 0secs &redef;





	option default_rotation_dir = "";



	type RotationPath: record {






		dir: string &default = default_rotation_dir;









		file_basename: string;
	};


	const rotation_format_func: function(ri: RotationFmtInfo): RotationPath &redef;



	const default_rotation_date_format = "%Y-%m-%d-%H-%M-%S" &redef;


	const default_rotation_postprocessor_cmd = "" &redef;







	option default_rotation_postprocessor_cmd_env: table[string] of string = {};



	const default_rotation_postprocessors: table[Writer] of function(info: RotationInfo) : bool &redef;






	const default_mail_alarms_interval = 0secs &redef;




	const default_field_name_map: table[string] of string = table() &redef;





	const default_scope_sep = "." &redef;




	const Log::default_ext_prefix: string = "_" &redef;






	const Log::default_ext_func: function(path: string): any =
		function(path: string) { } &redef;




	const default_max_delay_interval = 200msec &redef;





	const default_max_delay_queue_size = 1000 &redef;


	type Filter: record {

		name: string;


		writer: Writer &default=default_writer;















		path: string &optional;


























		path_func: function(id: ID, path: string, rec: any): string &optional;



		include: set[string] &optional;



		exclude: set[string] &optional;


		log_local: bool &default=enable_local_logging;


		log_remote: bool &default=enable_remote_logging;



		field_name_map: table[string] of string &default=default_field_name_map;



		scope_sep: string &default=default_scope_sep;




		ext_prefix: string &default=default_ext_prefix;




		ext_func: function(path: string): any &default=default_ext_func;


		interv: interval &default=default_rotation_interval;



		postprocessor: function(info: RotationInfo) : bool &optional;




		config: table[string] of string &default=table();
	};











	type StreamPolicyHook: hook(rec: any, id: ID);

















	type PolicyHook: hook(rec: any, id: ID, filter: Filter);




	redef record Filter += {







		policy: PolicyHook &optional;
	};


	type Stream: record {

		columns: any;




		ev: any &optional;



		path: string &optional;









		policy: PolicyHook &optional;














		event_groups: set[string] &default=set();








		max_delay_interval: interval &default=default_max_delay_interval;








		max_delay_queue_size: count &default=default_max_delay_queue_size;




		max_field_string_bytes: count &default=Log::default_max_field_string_bytes;




		max_total_string_bytes: count &default=Log::default_max_total_string_bytes;




		max_field_container_elements: count &default=Log::default_max_field_container_elements;




		max_total_container_elements: count &default=Log::default_max_total_container_elements;
	};


	const no_filter = Filter($name="<not found>");











	global create_stream: function(id: ID, stream: Stream) : bool;








	global remove_stream: function(id: ID) : bool;










	global enable_stream: function(id: ID) : bool;










	global disable_stream: function(id: ID) : bool;















	global add_filter: function(id: ID, filter: Filter) : bool;














	global remove_filter: function(id: ID, name: string) : bool;











	global get_filter_names: function(id: ID) : set[string];















	global get_filter: function(id: ID, name: string) : Filter;
















	global write: function(id: ID, columns: any) : bool;














	global set_buf: function(id: ID, buffered: bool): bool;












	global flush: function(id: ID): bool;













	global add_default_filter: function(id: ID) : bool;











	global remove_default_filter: function(id: ID) : bool;



















	global run_rotation_postprocessor_cmd: function(info: RotationInfo, npath: string) : bool;




	global active_streams: table[ID] of Stream = table();






	global log_stream_policy: Log::StreamPolicyHook;








	type PostDelayCallback: function(rec: any, id: ID): bool;




	type DelayToken: opaque of LogDelayToken;



	global empty_post_delay_cb: PostDelayCallback;































	global delay: function(id: ID, rec: any, post_delay_cb: PostDelayCallback &default=empty_post_delay_cb): DelayToken;














	global delay_finish: function(id: ID, rec: any, token: DelayToken): bool;















	global set_max_delay_interval: function(id: Log::ID, max_delay: interval): bool;














	global set_max_delay_queue_size: function(id: Log::ID, queue_size: count): bool;






	global get_delay_queue_size: function(id: Log::ID): int;
}

global all_streams: table[ID] of Stream = table();

global stream_filters: table[ID] of set[string] = table();


global filters: table[ID, string] of Filter;

@load base/bif/logging.bif

module Log;


function __default_rotation_postprocessor(info: RotationInfo) : bool &is_used
	{
	if ( info$writer in default_rotation_postprocessors )
		return default_rotation_postprocessors[info$writer](info);
	else

		return T;
	}

function default_path_func(id: ID, path: string, rec: any) : string
	{


	if ( path != "" )
		return path;

	local id_str = fmt("%s", id);

	local parts = split_string1(id_str, /::/);
	if ( |parts| == 2 )
		{

		if ( parts[1] == "LOG" )
			{
			local module_parts = split_string_n(parts[0], /[^A-Z][A-Z][a-z]*/, T, 4);
			local output = "";
			if ( 0 in module_parts )
				output = module_parts[0];
			if ( 1 in module_parts && module_parts[1] != "" )
				output = cat(output, sub_bytes(module_parts[1],1,1), "_", sub_bytes(module_parts[1], 2, |module_parts[1]|));
			if ( 2 in module_parts && module_parts[2] != "" )
				output = cat(output, "_", module_parts[2]);
			if ( 3 in module_parts && module_parts[3] != "" )
				output = cat(output, sub_bytes(module_parts[3],1,1), "_", sub_bytes(module_parts[3], 2, |module_parts[3]|));
			return to_lower(output);
			}


		if ( /_LOG$/ in parts[1] )
			parts[1] = sub(parts[1], /_LOG$/, "");

		return cat(to_lower(parts[0]),"_",to_lower(parts[1]));
		}
	else
		return to_lower(id_str);
	}


function run_rotation_postprocessor_cmd(info: RotationInfo, npath: string) : bool
	{
	local pp_cmd = default_rotation_postprocessor_cmd;

	if ( pp_cmd == "" )
		return T;


	local writer = subst_string(to_lower(fmt("%s", info$writer)), "log::writer_", "");






	system_env(fmt("%s %s %s %s %s %d %s",
	               pp_cmd, safe_shell_quote(npath), safe_shell_quote(info$path),
	               strftime("%y-%m-%d_%H.%M.%S", info$open),
	               strftime("%y-%m-%d_%H.%M.%S", info$close),
	               info$terminating, writer),
	           Log::default_rotation_postprocessor_cmd_env);

	return T;
	}



function default_ascii_rotation_postprocessor_func(info: Log::RotationInfo): bool
	{

	return Log::run_rotation_postprocessor_cmd(info, info$fname);
	}

redef Log::default_rotation_postprocessors += {
	[Log::WRITER_ASCII] = default_ascii_rotation_postprocessor_func
};

function Log::rotation_format_func(ri: Log::RotationFmtInfo): Log::RotationPath
	{
	local rval: Log::RotationPath;
	local open_str: string;






	if ( ri$postprocessor == __default_rotation_postprocessor &&
	    ri$writer == WRITER_ASCII &&
	    ri$writer in default_rotation_postprocessors &&
	    default_rotation_postprocessors[WRITER_ASCII] == default_ascii_rotation_postprocessor_func)
		{
		open_str = strftime(Log::default_rotation_date_format, ri$open);
		rval = RotationPath($file_basename=fmt("%s.%s", ri$path, open_str));
		}
	else
		{
		open_str = strftime("%y-%m-%d_%H.%M.%S", ri$open);
		rval = RotationPath($file_basename=fmt("%s-%s", ri$path, open_str));
		}

	return rval;
	}

function create_stream(id: ID, stream: Stream) : bool
	{
	if ( ! __create_stream(id, stream) )
		return F;

	active_streams[id] = stream;
	all_streams[id] = stream;

	return add_default_filter(id);
	}

function remove_stream(id: ID) : bool
	{
	delete active_streams[id];
	delete all_streams[id];

	if ( id in stream_filters )
		{
		for ( i in stream_filters[id] )
			delete filters[id, i];

		delete stream_filters[id];
		}
	return __remove_stream(id);
	}

function disable_stream(id: ID) : bool
	{
	delete active_streams[id];

	if ( id in all_streams )
		{
		for ( group in all_streams[id]$event_groups )
			{
			if ( has_module_events(group) )
				disable_module_events(group);

			if ( has_event_group(group) )
				disable_event_group(group);
			}
		}

	return __disable_stream(id);
	}

function enable_stream(id: ID) : bool
	{
	if ( ! __enable_stream(id) )
		return F;

	if ( id in all_streams )
		{
		active_streams[id] = all_streams[id];
		for ( group in all_streams[id]$event_groups )
			{
			if ( has_module_events(group) )
				enable_module_events(group);

			if ( has_event_group(group) )
				enable_event_group(group);
			}
		}

	return T;
	}


function add_stream_filters(id: ID, name: string)
	{
	if ( id in stream_filters )
		add stream_filters[id][name];
	else
		stream_filters[id] = set(name);
	}

function add_filter(id: ID, filter: Filter) : bool
	{
	local stream = all_streams[id];

	if ( stream?$path && ! filter?$path )
		filter$path = stream$path;

	if ( ! filter?$path && ! filter?$path_func )
		filter$path_func = default_path_func;

	local res = __add_filter(id, filter);
	if ( res )
		{
		add_stream_filters(id, filter$name);
		filters[id, filter$name] = filter;
		}
	return res;
	}

function remove_filter(id: ID, name: string) : bool
	{
	if ( id in stream_filters )
		delete stream_filters[id][name];

	delete filters[id, name];

	return __remove_filter(id, name);
	}

function get_filter(id: ID, name: string) : Filter
	{
	if ( [id, name] in filters )
		return filters[id, name];

	return no_filter;
	}

function get_filter_names(id: ID) : set[string]
	{
	if ( id in stream_filters )
		return stream_filters[id];
	else
		return set();
	}

function write(id: ID, columns: any) : bool
	{
	return __write(id, columns);
	}

function set_buf(id: ID, buffered: bool): bool
	{
	return __set_buf(id, buffered);
	}

function flush(id: ID): bool
	{
	return __flush(id);
	}

function add_default_filter(id: ID) : bool
	{
	return add_filter(id, Filter($name="default"));
	}

function remove_default_filter(id: ID) : bool
	{
	return remove_filter(id, "default");
	}

event zeek_init() &priority=5
	{
	if ( print_to_log != REDIRECT_NONE )
		Log::create_stream(PRINTLOG, Log::Stream($columns=PrintLogInfo, $ev=log_print, $path=print_log_path));
	}

function empty_post_delay_cb(rec: any, id: ID): bool {
	return T;
}

function delay(id: ID, rec: any, post_delay_cb: PostDelayCallback &default=empty_post_delay_cb): DelayToken
	{
	return Log::__delay(id, rec, post_delay_cb);
	}

function delay_finish(id: ID, rec: any, token: DelayToken): bool
	{
	return Log::__delay_finish(id, rec, token);
	}

function set_max_delay_interval(id: Log::ID, max_delay: interval): bool
	{

	if ( id !in all_streams )
		return F;


	if ( all_streams[id]$max_delay_interval >= max_delay )
		return T;

	if ( ! Log::__set_max_delay_interval(id, max_delay) )
		return F;

	all_streams[id]$max_delay_interval = max_delay;

	return T;
	}

function set_max_delay_queue_size(id: Log::ID, max_size: count): bool
	{
	if ( id !in all_streams )
		return F;

	if ( ! Log::__set_max_delay_queue_size(id, max_size) )
		return F;

	all_streams[id]$max_delay_queue_size = max_size;

	return T;
	}

function get_delay_queue_size(id: Log::ID): int
	{
	return Log::__get_delay_queue_size(id);
	}
