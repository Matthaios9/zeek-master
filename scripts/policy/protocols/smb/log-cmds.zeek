


@load base/protocols/smb

module SMB;

export {
	redef enum Log::ID += {
		CMD_LOG,
	};

	global log_policy: Log::PolicyHook;


	option ignored_command_statuses: set[string] = {
		"MORE_PROCESSING_REQUIRED",
	};
}



const deferred_logging_cmds: set[string] = {
	"NEGOTIATE",
	"READ_ANDX",
	"SESSION_SETUP_ANDX",
	"TREE_CONNECT_ANDX",
};

event zeek_init() &priority=5
	{
	Log::create_stream(SMB::CMD_LOG, Log::Stream($columns=SMB::CmdInfo, $path="smb_cmd", $policy=log_policy));
	}

event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) &priority=-5
	{
	if ( is_orig )
		return;

	if ( c$smb_state$current_cmd$status in SMB::ignored_command_statuses )
		return;

	if ( c$smb_state$current_cmd$command in SMB::deferred_logging_cmds )
		return;

	Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
	}

event smb1_error(c: connection, hdr: SMB1::Header, is_orig: bool)
	{
	if ( is_orig )
		return;




	if ( c$smb_state$current_cmd$status in SMB::ignored_command_statuses )
		return;

	if ( c$smb_state$current_cmd$command !in SMB::deferred_logging_cmds )
		return;

	Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
	}

event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool) &priority=-5
	{
	if ( is_orig )
		return;




	if ( c$smb_state$current_cmd$status == "PENDING" )
		return;

	if ( c$smb_state$current_cmd$status in SMB::ignored_command_statuses )
		return;

	if ( c$smb_state$current_cmd$command in SMB::deferred_logging_cmds )
		return;

	Log::write(SMB::CMD_LOG, c$smb_state$current_cmd);
	}
