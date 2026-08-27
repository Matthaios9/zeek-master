

@load base/frameworks/openflow
@load base/utils/active-http
@load base/utils/exec

module OpenFlow;

export {
	redef enum Plugin += {
		RYU,
	};










	global ryu_new: function(host: addr, host_port: count, dpid: count): OpenFlow::Controller;

	redef record ControllerState += {

		ryu_host: addr &optional;

		ryu_port: count &optional;

		ryu_dpid: count &optional;

		ryu_debug: bool &default=F;
	};
}


const RYU_FLOWENTRY_PATH = "/stats/flowentry/";




type ryu_flow_action: record {

	_type: string;

	_port: count &optional;
};




type ryu_ofp_flow_mod: record {
	dpid: count;
	cookie: count &optional;
	cookie_mask: count &optional;
	table_id: count &optional;
	idle_timeout: count &optional;
	hard_timeout: count &optional;
	priority: count &optional;
	flags: count &optional;
	match: OpenFlow::ofp_match;
	actions: vector of ryu_flow_action;
	out_port: count &optional;
	out_group: count &optional;
};


const ryu_url: table[ofp_flow_mod_command] of string = {
	[OFPFC_ADD] = "add",
	[OFPFC_MODIFY] = "modify",
	[OFPFC_MODIFY_STRICT] = "modify_strict",
	[OFPFC_DELETE] = "delete",
	[OFPFC_DELETE_STRICT] = "delete_strict",
};


function ryu_flow_mod(state: OpenFlow::ControllerState, match: ofp_match, flow_mod: OpenFlow::ofp_flow_mod): bool
	{
	if ( state$_plugin != RYU )
		{
		Reporter::error("Ryu openflow plugin was called with state of non-ryu plugin");
		return F;
		}


	local flow_actions: vector of ryu_flow_action = vector();

	for ( i in flow_mod$actions$out_ports )
		flow_actions += ryu_flow_action($_type="OUTPUT", $_port=flow_mod$actions$out_ports[i]);


	local mod: ryu_ofp_flow_mod = ryu_ofp_flow_mod(
		$dpid=state$ryu_dpid,
		$cookie=flow_mod$cookie,
		$idle_timeout=flow_mod$idle_timeout,
		$hard_timeout=flow_mod$hard_timeout,
		$priority=flow_mod$priority,
		$flags=flow_mod$flags,
		$match=match,
		$actions=flow_actions
	);

	if ( flow_mod?$out_port )
		mod$out_port = flow_mod$out_port;
	if ( flow_mod?$out_group )
		mod$out_group = flow_mod$out_group;


	local command_type: string;

	if ( flow_mod$command in ryu_url )
		command_type = ryu_url[flow_mod$command];
	else
			{
			Reporter::warning(fmt("The given OpenFlow command type '%s' is not available", cat(flow_mod$command)));
			return F;
			}

	local url=cat("http://", cat(state$ryu_host), ":", cat(state$ryu_port), RYU_FLOWENTRY_PATH, command_type);

	if ( state$ryu_debug )
		{
		print url;
		print to_json(mod);
		event OpenFlow::flow_mod_success(state$_name, match, flow_mod);
		return T;
		}


	local request: ActiveHTTP::Request = ActiveHTTP::Request(
		$url=url,
		$method="POST",
		$client_data=to_json(mod)
	);


	when [state, match, flow_mod, request] ( local result = ActiveHTTP::request(request) )
		{
		if (result$code == 200)
			event OpenFlow::flow_mod_success(state$_name, match, flow_mod, result$body);
		else
			{
			Reporter::warning(fmt("Flow modification failed with error: %s", result$body));
			event OpenFlow::flow_mod_failure(state$_name, match, flow_mod, result$body);
			return F;
			}
		}

	return T;
	}

function ryu_flow_clear(state: OpenFlow::ControllerState): bool
	{
	local url=cat("http://", cat(state$ryu_host), ":", cat(state$ryu_port), RYU_FLOWENTRY_PATH, "clear", "/", state$ryu_dpid);

	if ( state$ryu_debug )
		{
		print url;
		return T;
		}

	local request: ActiveHTTP::Request = ActiveHTTP::Request(
		$url=url,
		$method="DELETE"
	);

	when [request] ( local result = ActiveHTTP::request(request) )
		{
		}

	return T;
	}

function ryu_describe(state: ControllerState): string
	{
	return fmt("Ryu-%d-http://%s:%d", state$ryu_dpid, state$ryu_host, state$ryu_port);
	}


function ryu_new(host: addr, host_port: count, dpid: count): OpenFlow::Controller
	{
	local c = OpenFlow::Controller($state=OpenFlow::ControllerState($ryu_host=host, $ryu_port=host_port, $ryu_dpid=dpid),
		$flow_mod=ryu_flow_mod, $flow_clear=ryu_flow_clear, $describe=ryu_describe, $supports_flow_removed=F);

	register_controller(OpenFlow::RYU, cat(host,host_port,dpid), c);

	return c;
	}
