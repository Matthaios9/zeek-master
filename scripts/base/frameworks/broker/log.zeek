@load ./main

module Broker;

export {

	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;


	type Type: enum {

		STATUS,

		ERROR,

		CRITICAL_EVENT,

		ERROR_EVENT,

		WARNING_EVENT,

		INFO_EVENT,

		VERBOSE_EVENT,

		DEBUG_EVENT,
	};


	type Info: record {

		ts:                  time   &log;

		ty:                  Type &log;

		ev:                  string &log;


		peer:                NetworkInfo &log &optional;

		message:             string &log &optional;
	};
}

event zeek_init() &priority=5
	{
	Log::create_stream(Broker::LOG, Log::Stream($columns=Info, $path="broker", $policy=log_policy));
	}

function log_status(ev: string, endpoint: EndpointInfo, msg: string)
	{
	local r: Info;

	r = Broker::Info($ts = network_time(),
	                 $ev = ev,
	                 $ty = STATUS,
	                 $message = msg);

	if ( endpoint?$network )
		r$peer = endpoint$network;

	Log::write(Broker::LOG, r);
	}

event Broker::peer_added(endpoint: EndpointInfo, msg: string)
	{
	log_status("peer-added", endpoint, msg);
	}

event Broker::peer_removed(endpoint: EndpointInfo, msg: string)
	{
	log_status("peer-removed", endpoint, msg);
	}

event Broker::peer_lost(endpoint: EndpointInfo, msg: string)
	{
	log_status("connection-terminated", endpoint, msg);
	}

event Broker::error(code: ErrorCode, msg: string)
	{
	local ev = cat(code);
	ev = subst_string(ev, "Broker::", "");
	ev = subst_string(ev, "_", "-");
	ev = to_lower(ev);

	Log::write(Broker::LOG, Info($ts = network_time(),
	           $ev = ev,
	           $ty = ERROR,
	           $message = msg));

	Reporter::error(fmt("Broker error (%s): %s", code, msg));
	}

event Broker::internal_log_event(lvl: LogSeverityLevel, id: string, description: string)
	{
	local severity = Broker::CRITICAL_EVENT;
	switch lvl {
		case Broker::LOG_ERROR:
			severity = Broker::ERROR_EVENT;
			break;
		case Broker::LOG_WARNING:
			severity = Broker::WARNING_EVENT;
			break;
		case Broker::LOG_INFO:
			severity = Broker::INFO_EVENT;
			break;
		case Broker::LOG_VERBOSE:
			severity = Broker::VERBOSE_EVENT;
			break;
		case Broker::LOG_DEBUG:
			severity = Broker::DEBUG_EVENT;
			break;
	}
	Log::write(Broker::LOG, Info($ts = network_time(),
	           $ty = severity,
	           $ev = id,
	           $message = description));
	}
