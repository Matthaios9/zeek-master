


@load base/frameworks/openflow
@load base/frameworks/logging

module OpenFlow;

export {
	redef enum Plugin += {
		OFLOG,
	};

	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;








	global log_new: function(dpid: count, success_event: bool &default=T): OpenFlow::Controller;

	redef record ControllerState += {

		log_dpid: count &optional;

		log_success_event: bool &optional;
	};


	type Info: record {

		ts: time &log;

		dpid: count &log;

		match: ofp_match &log;

		flow_mod: ofp_flow_mod &log;
	};



	global log_openflow: event(rec: Info);
}

event zeek_init() &priority=5
	{
	Log::create_stream(OpenFlow::LOG, Log::Stream($columns=Info, $ev=log_openflow, $path="openflow", $policy=log_policy));
	}

function log_flow_mod(state: ControllerState, match: ofp_match, flow_mod: OpenFlow::ofp_flow_mod): bool
	{
	Log::write(LOG, Info($ts=network_time(), $dpid=state$log_dpid, $match=match, $flow_mod=flow_mod));
	if ( state$log_success_event )
		event OpenFlow::flow_mod_success(state$_name, match, flow_mod);

	return T;
	}

function log_describe(state: ControllerState): string
	{
	return fmt("Log-%d", state$log_dpid);
	}

function log_new(dpid: count, success_event: bool &default=T): OpenFlow::Controller
	{
	local c = OpenFlow::Controller($state=OpenFlow::ControllerState($log_dpid=dpid, $log_success_event=success_event),
		$flow_mod=log_flow_mod, $describe=log_describe, $supports_flow_removed=F);

	register_controller(OpenFlow::OFLOG, cat(dpid), c);

	return c;
	}
