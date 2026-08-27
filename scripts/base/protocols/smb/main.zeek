@load ./consts
@load ./const-dos-error
@load ./const-nt-status

module SMB;

export {
	redef enum Log::ID += {
		MAPPING_LOG,
		FILES_LOG
	};


	const ports = { 139/tcp, 445/tcp } &redef;

	global log_policy_files: Log::PolicyHook;
	global log_policy_mapping: Log::PolicyHook;


	type Action: enum {
		FILE_READ,
		FILE_WRITE,
		FILE_OPEN,
		FILE_CLOSE,
		FILE_DELETE,
		FILE_RENAME,
		FILE_SET_ATTRIBUTE,

		PIPE_READ,
		PIPE_WRITE,
		PIPE_OPEN,
		PIPE_CLOSE,

		PRINT_READ,
		PRINT_WRITE,
		PRINT_OPEN,
		PRINT_CLOSE,
	};


	option logged_file_actions: set[Action] = {
		FILE_OPEN,
		FILE_RENAME,
		FILE_DELETE,

		PRINT_OPEN,
		PRINT_CLOSE,
	};






	option enable_clear_script_state = T;


	type FileInfo: record {

		ts				: time    &log &default=network_time();

		uid				: string  &log;

		id				: conn_id &log;

		fuid			: string  &log &optional;


		action			: Action  &log &optional;

		path			: string  &log &optional;

		name			: string  &log &optional;

		size			: count   &log &default=0;


		prev_name		: string  &log &optional;

		times			: SMB::MACTimes &log &optional;
	};


	type TreeInfo: record {

		ts                  : time   &log &default=network_time();

		uid                 : string  &log;

		id                  : conn_id &log;


		path                : string &log &optional;

		service             : string &log &optional;

		native_file_system  : string &log &optional;


		share_type          : string &log &default="DISK";
	};


	type CmdInfo: record {

		ts				: time &log &default=network_time();

		uid				: string &log;

		id				: conn_id &log;


		command			: string &log;

		sub_command		: string &log &optional;

		argument		: string &log &optional;


		status			: string &log &optional;

		rtt				: interval &log &optional;

		version			: string &log;


		username		: string &log &optional;



		tree			: string &log &optional;

		tree_service	: string &log &optional;


		referenced_file	: FileInfo &log &optional;

		referenced_tree	: TreeInfo &optional;
	};



	type State: record {

		current_cmd    : CmdInfo     &optional;

		current_file   : FileInfo    &optional;

		current_tree   : TreeInfo    &optional;


		pending_cmds : table[count] of CmdInfo   &optional;

		fid_map      : table[count] of FileInfo  &optional;

		tid_map      : table[count] of TreeInfo  &optional;

		pipe_map     : table[count] of string    &optional;




		recent_files : set[string] &default=set() &read_expire=3min;
	};



	redef record connection += {
		smb_state : State &optional;
	};


	const set_current_file: function(smb_state: State, file_id: count) &redef;


	const write_file_log: function(state: State) &redef;
}

redef record FileInfo += {

	fid  : count   &optional;


	uuid : string &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(SMB::FILES_LOG, Log::Stream($columns=SMB::FileInfo, $path="smb_files", $policy=log_policy_files));
	Log::create_stream(SMB::MAPPING_LOG, Log::Stream($columns=SMB::TreeInfo, $path="smb_mapping", $policy=log_policy_mapping));

	Analyzer::register_for_ports(Analyzer::ANALYZER_SMB, ports);
	}

function set_current_file(smb_state: State, file_id: count)
	{
	if ( file_id !in smb_state$fid_map )
		{
		smb_state$fid_map[file_id] = smb_state$current_cmd$referenced_file;
		smb_state$fid_map[file_id]$fid = file_id;
		}

	smb_state$current_cmd$referenced_file = smb_state$fid_map[file_id];
	smb_state$current_file = smb_state$current_cmd$referenced_file;
	}

function write_file_log(state: State)
	{
	local f = state$current_file;
	if ( f?$name &&
	     f$action in logged_file_actions )
		{



		if ( f?$times )
			{



			local times = copy(f$times);
			times$accessed_raw = 0;
			times$accessed = double_to_time(0.0);
			local file_ident = cat(f$action,
			                       f?$fuid ? f$fuid : "",
			                       f?$name ? f$name : "",
			                       f?$path ? f$path : "",
			                       f$size,
			                       times);
			if ( file_ident in state$recent_files )
				{

				return;
				}
			else
				add state$recent_files[file_ident];
			}

		Log::write(FILES_LOG, f);
		}
	}

event smb_pipe_connect_heuristic(c: connection) &priority=5
	{
	c$smb_state$current_tree$path = "<unknown>";
	c$smb_state$current_tree$share_type = "PIPE";
	}

event file_state_remove(f: fa_file) &priority=-5
	{
	if ( f$source != "SMB" )
		return;

	for ( _, c in f$conns )
		{
		if ( c?$smb_state && c$smb_state?$current_file)
			{
			write_file_log(c$smb_state);
			}
		return;
		}
	}
