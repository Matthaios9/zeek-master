


@load base/bif/file_analysis.bif
@load base/frameworks/analyzer
@load base/frameworks/logging
@load base/utils/site

module Files;

export {
	redef enum Log::ID += {

		LOG
	};


	global log_policy: Log::PolicyHook;


	type AnalyzerArgs: record {




		chunk_event: event(f: fa_file, data: string, off: count) &optional;




		stream_event: event(f: fa_file, data: string) &optional;
	} &redef;




	type Info: record {

		ts: time &log;


		fuid: string &log;



		uid: string &log &optional;



		id: conn_id &log &optional;




		source: string &log &optional;





		depth: count &default=0 &log;


		analyzers: set[string] &default=string_set() &log;






		mime_type: string &log &optional;




		filename: string &log &optional;


		duration: interval &log &default=0secs;




		local_orig: bool &log &optional;




		is_orig: bool &log &optional;




		seen_bytes: count &log &default=0;


		total_bytes: count &log &optional;





		missing_bytes: count &log &default=0;




		overflow_bytes: count &log &default=0;


		timedout: bool &log &default=F;



		parent_fuid: string &log &optional;
	} &redef;



	const disable: table[Files::Tag] of bool = table() &redef;



	const analyze_by_mime_type_automatically = T &redef;


	option enable_reassembler = T;


	const reassembly_buffer_size = 524288 &redef;






	global file_exists: function(fuid: string): bool;






	global lookup_file: function(fuid: string): fa_file;





	global enable_reassembly: function(f: fa_file);





	global disable_reassembly: function(f: fa_file);







	global set_reassembly_buffer_size: function(f: fa_file, max: count);













	global set_timeout_interval: function(f: fa_file, t: interval): bool;






	global enable_analyzer: function(tag: Files::Tag): bool;






	global disable_analyzer: function(tag: Files::Tag): bool;






	global analyzer_enabled: function(tag: Files::Tag): bool;












	global add_analyzer: function(f: fa_file,
	                              tag: Files::Tag,
	                              args: AnalyzerArgs &default=AnalyzerArgs()): bool;











	global remove_analyzer: function(f: fa_file,
	                                 tag: Files::Tag,
	                                 args: AnalyzerArgs &default=AnalyzerArgs()): bool;








	global stop: function(f: fa_file): bool;







	global analyzer_name: function(tag: Files::Tag): string;







	global describe: function(f: fa_file): string;

	type ProtoRegistration: record {


		get_file_handle: function(c: connection, is_orig: bool): string;




		describe: function(f: fa_file): string
				&default=function(f: fa_file): string { return ""; };
	};










	global register_protocol: function(tag: Analyzer::Tag, reg: ProtoRegistration): bool;









	global register_analyzer_add_callback: function(tag: Files::Tag, callback: function(f: fa_file, args: AnalyzerArgs));











	global register_for_mime_types: function(tag: Files::Tag, mts: set[string]) : bool;










	global register_for_mime_type: function(tag: Files::Tag, mt: string) : bool;






	global registered_mime_types: function(tag: Files::Tag) : set[string];





	global all_registered_mime_types: function() : table[Files::Tag] of set[string];



	global log_files: event(rec: Info);
}

redef record fa_file += {
	info: Info &optional;
};


global registered_protocols: table[Analyzer::Tag] of ProtoRegistration = table();


global mime_types: table[Files::Tag] of set[string];
global mime_type_to_analyzers: table[string] of set[Files::Tag];

global analyzer_add_callbacks: table[Files::Tag] of function(f: fa_file, args: AnalyzerArgs) = table();

event zeek_init() &priority=5
	{
	Log::create_stream(Files::LOG, Log::Stream($columns=Info, $ev=log_files, $path="files", $policy=log_policy));
	}

function set_info(f: fa_file)
	{
	if ( ! f?$info )
		{
		local tmp: Info = Info($ts=f$last_active,
		                       $fuid=f$id);
		f$info = tmp;
		}

	if ( f?$parent_id )
		f$info$parent_fuid = f$parent_id;
	if ( f?$source )
		f$info$source = f$source;
	f$info$duration = f$last_active - f$info$ts;
	f$info$seen_bytes = f$seen_bytes;
	if ( f?$total_bytes )
		f$info$total_bytes = f$total_bytes;
	f$info$missing_bytes = f$missing_bytes;
	f$info$overflow_bytes = f$overflow_bytes;
	if ( f?$is_orig )
		f$info$is_orig = f$is_orig;
	}

function file_exists(fuid: string): bool
	{
	return __file_exists(fuid);
	}

function lookup_file(fuid: string): fa_file
	{
	return __lookup_file(fuid);
	}

function set_timeout_interval(f: fa_file, t: interval): bool
	{
	return __set_timeout_interval(f$id, t);
	}

function enable_reassembly(f: fa_file)
	{
	__enable_reassembly(f$id);
	}

function disable_reassembly(f: fa_file)
	{
	__disable_reassembly(f$id);
	}

function set_reassembly_buffer_size(f: fa_file, max: count)
	{
	__set_reassembly_buffer(f$id, max);
	}

function enable_analyzer(tag: Files::Tag): bool
	{
	return __enable_analyzer(tag);
	}

function disable_analyzer(tag: Files::Tag): bool
	{
	return __disable_analyzer(tag);
	}

function analyzer_enabled(tag: Files::Tag): bool
	{
	return __analyzer_enabled(tag);
	}

function add_analyzer(f: fa_file, tag: Files::Tag, args: AnalyzerArgs): bool
	{
	if ( ! Files::analyzer_enabled(tag) )
		return F;

	add f$info$analyzers[Files::analyzer_name(tag)];

	if ( tag in analyzer_add_callbacks )
		analyzer_add_callbacks[tag](f, args);

	if ( ! __add_analyzer(f$id, tag, args) )
		{
		Reporter::warning(fmt("Analyzer %s not added successfully to file %s.", tag, f$id));
		return F;
		}
	return T;
	}

function register_analyzer_add_callback(tag: Files::Tag, callback: function(f: fa_file, args: AnalyzerArgs))
	{
	analyzer_add_callbacks[tag] = callback;
	}

function remove_analyzer(f: fa_file, tag: Files::Tag, args: AnalyzerArgs): bool
	{
	return __remove_analyzer(f$id, tag, args);
	}

function stop(f: fa_file): bool
	{
	return __stop(f$id);
	}

function analyzer_name(tag: Files::Tag): string
	{
	return __analyzer_name(tag);
	}

function register_protocol(tag: Analyzer::Tag, reg: ProtoRegistration): bool
	{
	local result = (tag !in registered_protocols);
	registered_protocols[tag] = reg;
	return result;
	}

function register_for_mime_types(tag: Files::Tag, mime_types: set[string]) : bool
	{
	local rc = T;

	for ( mt in mime_types )
		{
		if ( ! register_for_mime_type(tag, mt) )
			rc = F;
		}

	return rc;
	}

function register_for_mime_type(tag: Files::Tag, mt: string) : bool
	{
	if ( tag !in mime_types )
		{
		mime_types[tag] = set();
		}
	add mime_types[tag][mt];

	if ( mt !in mime_type_to_analyzers )
		{
		mime_type_to_analyzers[mt] = set();
		}
	add mime_type_to_analyzers[mt][tag];

	return T;
	}

function registered_mime_types(tag: Files::Tag) : set[string]
	{
	return tag in mime_types ? mime_types[tag] : set();
	}

function all_registered_mime_types(): table[Files::Tag] of set[string]
	{
	return mime_types;
	}

function describe(f: fa_file): string
	{
	if ( ! Analyzer::has_tag(f$source) )
		return "";

	local tag = Analyzer::get_tag(f$source);
	if ( tag !in registered_protocols )
		return "";

	local handler = registered_protocols[tag];
	return handler$describe(f);
	}


global missing_get_file_handle_warned: table[Analyzer::Tag] of bool &default=F;

event get_file_handle(tag: Analyzer::Tag, c: connection, is_orig: bool) &priority=5
	{
	if ( tag !in registered_protocols )
		{
		if ( ! missing_get_file_handle_warned[tag] )
			{
			missing_get_file_handle_warned[tag] = T;
			Reporter::warning(fmt("get_file_handle() handler missing for %s", tag));
			}

		set_file_handle(fmt("%s-fallback-%s-%s-%s", tag, c$uid, is_orig, network_time()));
		return;
		}

	local handler = registered_protocols[tag];
	set_file_handle(handler$get_file_handle(c, is_orig));
	}

event file_new(f: fa_file) &priority=10
	{
	set_info(f);

	if ( enable_reassembler )
		{
		Files::enable_reassembly(f);
		Files::set_reassembly_buffer_size(f, reassembly_buffer_size);
		}
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=10
	{
	set_info(f);

	local cid = c$id;
	if( |Site::local_nets| > 0 )
		f$info$local_orig=Site::is_local_addr(f$is_orig ? cid$orig_h : cid$resp_h);
	}

event file_sniff(f: fa_file, meta: fa_metadata) &priority=10
	{
	set_info(f);

	if ( ! meta?$mime_type )
		return;

	f$info$mime_type = meta$mime_type;

	if ( analyze_by_mime_type_automatically &&
	     meta$mime_type in mime_type_to_analyzers )
		{
		local analyzers = mime_type_to_analyzers[meta$mime_type];
		for ( a in analyzers )
			Files::add_analyzer(f, a);
		}
	}

event file_timeout(f: fa_file) &priority=10
	{
	set_info(f);
	f$info$timedout = T;
	}

event file_state_remove(f: fa_file) &priority=10
	{
	set_info(f);
	}

event file_state_remove(f: fa_file) &priority=-10
	{


	if ( ! f?$conns || |f$conns| == 0 )
		{
		Log::write(Files::LOG, f$info);
		return;
		}






	for ( [cid], c in f$conns )
		{




		local info = |f$conns| > 1 ? copy(f$info) : f$info;
		info$uid = c$uid;
		info$id = c$id;
		Log::write(Files::LOG, info);
		}
	}
