@load ./main

module SMB1;

redef record SMB::CmdInfo += {

	smb1_offered_dialects: string_vec &optional;
};

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=5
	{
	if ( ! c?$smb_state )
		{
		local state: SMB::State;
		state$fid_map = table();
		state$tid_map = table();
		state$pipe_map = table();
		state$pending_cmds = table();
		c$smb_state = state;
		}

	local smb_state = c$smb_state;
	local tid = hdr$tid;
	local mid = hdr$mid;

	if ( tid !in smb_state$tid_map )
		{
		smb_state$tid_map[tid] = SMB::TreeInfo($uid=c$uid, $id=c$id);
		}
	smb_state$current_tree = smb_state$tid_map[tid];
	if ( smb_state$current_tree?$path )
		{
		smb_state$current_cmd$tree = smb_state$current_tree$path;
		}

	if ( smb_state$current_tree?$service )
		{
		smb_state$current_cmd$tree_service = smb_state$current_tree$service;
		}

	if ( mid !in smb_state$pending_cmds )
		{
		local tmp_cmd = SMB::CmdInfo($uid=c$uid, $id=c$id, $version="SMB1", $command = SMB1::commands[hdr$command]);

		local tmp_file = SMB::FileInfo($uid=c$uid, $id=c$id);
		tmp_cmd$referenced_file = tmp_file;
		tmp_cmd$referenced_tree = smb_state$current_tree;

		smb_state$pending_cmds[mid] = tmp_cmd;
		}

	smb_state$current_cmd = smb_state$pending_cmds[mid];

	if ( !is_orig )
		{
		smb_state$current_cmd$rtt = network_time() - smb_state$current_cmd$ts;
		smb_state$current_cmd$status = SMB::statuses[hdr$status]$id;
		}
	}

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=-5
	{
	if ( is_orig )
		return;

	delete c$smb_state$pending_cmds[hdr$mid];
	}


event smb1_transaction2_request(c: connection, hdr: SMB1::Header, args: SMB1::Trans2_Args, sub_cmd: count)
	{
	c$smb_state$current_cmd$sub_command = SMB1::trans2_sub_commands[sub_cmd];
	}


event smb1_negotiate_request(c: connection, hdr: SMB1::Header, dialects: string_vec) &priority=5
	{
	c$smb_state$current_cmd$smb1_offered_dialects = dialects;
	}

event smb1_negotiate_response(c: connection, hdr: SMB1::Header, response: SMB1::NegotiateResponse) &priority=5
	{
	if ( c$smb_state$current_cmd?$smb1_offered_dialects )
		{
		local offered_dialects = c$smb_state$current_cmd$smb1_offered_dialects;
		if ( response?$ntlm && response$ntlm$dialect_index < |offered_dialects| )
			{
			c$smb_state$current_cmd$argument = offered_dialects[response$ntlm$dialect_index];
			}

		delete c$smb_state$current_cmd$smb1_offered_dialects;
		}
	}

event smb1_negotiate_response(c: connection, hdr: SMB1::Header, response: SMB1::NegotiateResponse) &priority=-5
	{
	}

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string) &priority=5
	{
	local tmp_tree = SMB::TreeInfo($uid=c$uid, $id=c$id, $path=path, $service=service);

	c$smb_state$current_cmd$referenced_tree = tmp_tree;
	c$smb_state$current_cmd$argument = path;
	}

event smb1_tree_connect_andx_response(c: connection, hdr: SMB1::Header, service: string, native_file_system: string) &priority=5
	{


	if ( ! c$smb_state$current_cmd?$referenced_tree )
		{
		local addl = fmt("current_cmd=%s", c$smb_state$current_cmd$command);
		Reporter::conn_weird("smb_tree_connect_andx_response_without_tree", c, addl);
		return;
		}

	c$smb_state$current_cmd$referenced_tree$service = service;
	if ( service == "IPC" )
		c$smb_state$current_cmd$referenced_tree$share_type = "PIPE";

	c$smb_state$current_cmd$tree_service = service;

	if ( native_file_system != "" )
		c$smb_state$current_cmd$referenced_tree$native_file_system = native_file_system;

	c$smb_state$current_tree = c$smb_state$current_cmd$referenced_tree;
	c$smb_state$tid_map[hdr$tid] = c$smb_state$current_tree;
	}

event smb1_tree_connect_andx_response(c: connection, hdr: SMB1::Header, service: string, native_file_system: string) &priority=-5
	{
	Log::write(SMB::MAPPING_LOG, c$smb_state$current_tree);
	}

event smb1_nt_create_andx_request(c: connection, hdr: SMB1::Header, name: string) &priority=5
	{
	local tmp_file = SMB::FileInfo($uid=c$uid, $id=c$id);
	c$smb_state$current_cmd$referenced_file = tmp_file;

	c$smb_state$current_cmd$referenced_file$name = name;
	c$smb_state$current_cmd$referenced_file$action = SMB::FILE_OPEN;
	c$smb_state$current_file = c$smb_state$current_cmd$referenced_file;
	c$smb_state$current_cmd$argument = name;
	}

event smb1_nt_create_andx_response(c: connection, hdr: SMB1::Header, file_id: count, file_size: count, times: SMB::MACTimes) &priority=5
	{
	c$smb_state$current_cmd$referenced_file$action = SMB::FILE_OPEN;
	c$smb_state$current_cmd$referenced_file$fid = file_id;
	c$smb_state$current_cmd$referenced_file$size = file_size;


	if ( times$modified as double > 0.0 )
		c$smb_state$current_cmd$referenced_file$times = times;



	c$smb_state$fid_map[file_id] = c$smb_state$current_cmd$referenced_file;

	c$smb_state$current_file = c$smb_state$fid_map[file_id];

	SMB::write_file_log(c$smb_state);
	}

event smb1_read_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, length: count) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id);
	c$smb_state$current_file$action = SMB::FILE_READ;
	if ( c$smb_state$current_file?$name )
		c$smb_state$current_cmd$argument = c$smb_state$current_file$name;
	}

event smb1_read_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, length: count) &priority=-5
	{
	if ( c$smb_state$current_tree?$path && !c$smb_state$current_file?$path )
		c$smb_state$current_file$path = c$smb_state$current_tree$path;

	SMB::write_file_log(c$smb_state);
	}

event smb1_write_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, data_len: count) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id);
	c$smb_state$current_file$action = SMB::FILE_WRITE;
	if ( !c$smb_state$current_cmd?$argument &&

	     c$smb_state$current_file?$name )
		c$smb_state$current_cmd$argument = c$smb_state$current_file$name;
	}

event smb1_write_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, data_len: count) &priority=-5
	{
	if ( c$smb_state$current_tree?$path && !c$smb_state$current_file?$path )
		c$smb_state$current_file$path = c$smb_state$current_tree$path;



	}






event smb1_close_request(c: connection, hdr: SMB1::Header, file_id: count) &priority=5
	{
	SMB::set_current_file(c$smb_state, file_id);
	c$smb_state$current_file$action = SMB::FILE_CLOSE;
	}

event smb1_close_request(c: connection, hdr: SMB1::Header, file_id: count) &priority=-5
	{
	if ( file_id in c$smb_state$fid_map )
		{
		local fl = c$smb_state$fid_map[file_id];

		if ( c$smb_state$current_tree?$path )
			fl$path = c$smb_state$current_tree$path;

		if ( fl?$name )
			c$smb_state$current_cmd$argument = fl$name;

		delete c$smb_state$fid_map[file_id];

		SMB::write_file_log(c$smb_state);
		}
	else
		{



		}
	}

event smb1_trans2_get_dfs_referral_request(c: connection, hdr: SMB1::Header, file_name: string)
	{
	c$smb_state$current_cmd$argument = file_name;
	}

event smb1_trans2_query_path_info_request(c: connection, hdr: SMB1::Header, file_name: string)
	{
	c$smb_state$current_cmd$argument = file_name;
	}

event smb1_trans2_find_first2_request(c: connection, hdr: SMB1::Header, args: SMB1::Find_First2_Request_Args)
	{
	c$smb_state$current_cmd$argument = args$file_name;
	}

event smb1_session_setup_andx_request(c: connection, hdr: SMB1::Header, request: SMB1::SessionSetupAndXRequest) &priority=5
	{

	}

event smb1_session_setup_andx_response(c: connection, hdr: SMB1::Header, response: SMB1::SessionSetupAndXResponse) &priority=-5
	{

	}

event smb1_transaction_request(c: connection, hdr: SMB1::Header, name: string, sub_cmd: count, parameters: string, data: string)
	{
	c$smb_state$current_cmd$sub_command = SMB1::trans_sub_commands[sub_cmd];
	}

event smb1_write_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, data_len: count)
	{
	if ( ! c$smb_state?$current_file || ! c$smb_state$current_file?$uuid )
		{

		return;
		}

	c$smb_state$pipe_map[file_id] = c$smb_state$current_file$uuid;
	}
