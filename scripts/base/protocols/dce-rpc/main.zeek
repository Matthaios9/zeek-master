@load ./consts
@load base/protocols/conn/removal-hooks

module DCE_RPC;

export {
	redef enum Log::ID += { LOG };


	const ports = { 135/tcp } &redef;

	global log_policy: Log::PolicyHook;

	type Info: record {

		ts         : time     &log;

		uid        : string   &log;

		id         : conn_id  &log;



		rtt        : interval &log &optional;














		named_pipe : string   &log &optional;

		endpoint   : string   &log &optional;

		operation  : string   &log &optional;
	};



	option ignored_operations: table[string] of set[string] = {
		["winreg"] = set("BaseRegCloseKey", "BaseRegGetVersion", "BaseRegOpenKey", "BaseRegQueryValue", "BaseRegDeleteKeyEx", "OpenLocalMachine", "BaseRegEnumKey", "OpenClassesRoot"),
		["spoolss"] = set("RpcSplOpenPrinter", "RpcClosePrinter"),
		["wkssvc"] = set("NetrWkstaGetInfo"),
	};

	type State: record {
		uuid       : string &optional;
		named_pipe : string &optional;
		ctx_to_uuid: table[count] of string &optional;
	};



	type BackingState: record {
		info: Info;
		state: State;
	};


	global finalize_dce_rpc: Conn::RemovalHook;
}

redef DPD::ignore_violations += { Analyzer::ANALYZER_DCE_RPC };

redef record connection += {
	dce_rpc: Info &optional;
	dce_rpc_state: State &optional;
	dce_rpc_backing: table[count] of BackingState &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(DCE_RPC::LOG, Log::Stream($columns=Info, $path="dce_rpc", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_DCE_RPC, ports);
	}

function normalize_named_pipe_name(pn: string): string
	{
	local parts = split_string(pn, /\\[pP][iI][pP][eE]\\/);
	if ( 1 in parts )
		return to_lower(parts[1]);
	else
		return to_lower(pn);
	}

function set_state(c: connection, state_x: BackingState)
	{
	c$dce_rpc = state_x$info;
	c$dce_rpc_state = state_x$state;

	if ( c$dce_rpc_state?$uuid )
		c$dce_rpc$endpoint = uuid_endpoint_map[c$dce_rpc_state$uuid];
	if ( c$dce_rpc_state?$named_pipe )
		c$dce_rpc$named_pipe = c$dce_rpc_state$named_pipe;
	}

function set_session(c: connection, fid: count)
	{
	if ( ! c?$dce_rpc_backing )
		{
		c$dce_rpc_backing = table();
		Conn::register_removal_hook(c, finalize_dce_rpc);
		}

	if ( fid !in c$dce_rpc_backing )
		{
		local info = Info($ts=network_time(),$id=c$id,$uid=c$uid);
		c$dce_rpc_backing[fid] = BackingState($info=info, $state=State());
		}

	local state_x = c$dce_rpc_backing[fid];
	set_state(c, state_x);
	}

event dce_rpc_bind(c: connection, fid: count, ctx_id: count, uuid: string, ver_major: count, ver_minor: count) &priority=5
	{
	set_session(c, fid);

	local uuid_str = uuid_to_string(uuid);

	if ( ! c$dce_rpc_state?$ctx_to_uuid )
		c$dce_rpc_state$ctx_to_uuid = table();

	c$dce_rpc_state$ctx_to_uuid[ctx_id] = uuid_str;
	c$dce_rpc_state$uuid = uuid_str;
	c$dce_rpc$endpoint = uuid_endpoint_map[uuid_str];
	}

event dce_rpc_alter_context(c: connection, fid: count, ctx_id: count, uuid: string, ver_major: count, ver_minor: count) &priority=5
	{
	set_session(c, fid);

	local uuid_str = uuid_to_string(uuid);

	if ( ! c$dce_rpc_state?$ctx_to_uuid )
		c$dce_rpc_state$ctx_to_uuid = table();

	c$dce_rpc_state$ctx_to_uuid[ctx_id] = uuid_str;
	c$dce_rpc_state$uuid = uuid_str;
	c$dce_rpc$endpoint = uuid_endpoint_map[uuid_str];
	}

event dce_rpc_bind_ack(c: connection, fid: count, sec_addr: string) &priority=5
	{
	set_session(c, fid);

	if ( sec_addr != "" )
		{
		c$dce_rpc_state$named_pipe = sec_addr;
		c$dce_rpc$named_pipe = sec_addr;
		}
	}

event dce_rpc_alter_context_resp(c: connection, fid: count) &priority=5
	{
	set_session(c, fid);
	}

event dce_rpc_request(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count) &priority=5
	{
	set_session(c, fid);

	if ( c?$dce_rpc )
		{
		c$dce_rpc$ts = network_time();
		}
	}

event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count) &priority=5
	{
	set_session(c, fid);




	if ( ! c$dce_rpc?$endpoint && c$dce_rpc?$named_pipe )
		{
		local npn = normalize_named_pipe_name(c$dce_rpc$named_pipe);
		if ( npn in pipe_name_to_common_uuid )
			{
			c$dce_rpc_state$uuid = pipe_name_to_common_uuid[npn];
			}
		}

	if ( c?$dce_rpc )
		{
		if ( c$dce_rpc?$endpoint )
			{
			c$dce_rpc$operation = operations[c$dce_rpc_state$uuid, opnum];
			if ( c$dce_rpc$ts != network_time() )
				c$dce_rpc$rtt = network_time() - c$dce_rpc$ts;
			}

		if ( c$dce_rpc_state?$ctx_to_uuid &&
		     ctx_id in c$dce_rpc_state$ctx_to_uuid )
			{
			local u = c$dce_rpc_state$ctx_to_uuid[ctx_id];
			c$dce_rpc$endpoint = uuid_endpoint_map[u];
			c$dce_rpc$operation = operations[u, opnum];
			}
		}
	}

event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count) &priority=-5
	{
	if ( c?$dce_rpc )
		{


		if ( ( c$dce_rpc?$endpoint && c$dce_rpc?$operation ) &&
		     ( c$dce_rpc$endpoint !in ignored_operations
		       ||
		       ( c$dce_rpc?$endpoint && c$dce_rpc?$operation &&
		        c$dce_rpc$operation !in ignored_operations[c$dce_rpc$endpoint] &&
		        "*" !in ignored_operations[c$dce_rpc$endpoint] ) ) )
			{
			Log::write(LOG, c$dce_rpc);
			}
		delete c$dce_rpc;
		}
	}

event smb_discarded_dce_rpc_analyzers(c: connection)
	{



	delete c$dce_rpc_backing;
	Reporter::conn_weird("SMB_discarded_dce_rpc_analyzers", c, "", "SMB");
	}


event smb2_close_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID) &priority=-5
	{
	local fid = file_id$persistent + file_id$volatile;
	if ( c?$dce_rpc_backing )
		delete c$dce_rpc_backing[fid];
	}

hook finalize_dce_rpc(c: connection)
	{
	if ( ! c?$dce_rpc )
		return;


	for ( _, x in c$dce_rpc_backing )
		{
		set_state(c, x);




		if ( ! c$dce_rpc?$endpoint && c$dce_rpc?$named_pipe )
			{
			local npn = normalize_named_pipe_name(c$dce_rpc$named_pipe);
			if ( npn in pipe_name_to_common_uuid )
				{
				c$dce_rpc_state$uuid = pipe_name_to_common_uuid[npn];
				}
			}

		if ( ( c$dce_rpc?$endpoint && c$dce_rpc?$operation ) &&
		     ( c$dce_rpc$endpoint !in ignored_operations
		       ||
		       ( c$dce_rpc?$endpoint && c$dce_rpc?$operation &&
		        c$dce_rpc$operation !in ignored_operations[c$dce_rpc$endpoint] &&
		        "*" !in ignored_operations[c$dce_rpc$endpoint] ) ) )
			{
			Log::write(LOG, c$dce_rpc);
			}
		}
	}
