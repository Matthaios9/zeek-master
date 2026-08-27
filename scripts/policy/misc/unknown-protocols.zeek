




@load base/frameworks/notice

module UnknownProtocol;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {

		ts:           time     &log;


		analyzer:     string   &log;


		protocol_id:  string   &log;




		protocol_id_num: count;



		first_bytes:  string   &log;




		analyzer_history: vector of string &log;
	};
}

event unknown_protocol(analyzer_name: string, protocol: count, first_bytes: string,
	analyzer_history: string_vec)
	{
	local info : Info;
	info$ts = network_time();
	info$analyzer = analyzer_name;
	info$protocol_id = fmt("0x%x", protocol);
	info$protocol_id_num = protocol;
	info$first_bytes = bytestring_to_hexstr(first_bytes);
	info$analyzer_history = analyzer_history;

	Log::write(LOG, info);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $path="unknown_protocols", $policy=log_policy));
	}
