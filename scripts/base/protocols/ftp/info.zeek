

module FTP;

@load ./utils-commands

export {



	option default_capture_password = F;


	type ExpectedDataChannel: record {

		passive: bool &log;

		orig_h: addr &log;

		resp_h: addr &log;


		resp_p: port &log;
	};

	type Info: record {

		ts:               time        &log;

		uid:              string      &log;

		id:               conn_id     &log;

		user:             string      &log &default="<unknown>";

		password:         string      &log &optional;

		command:          string      &log &optional;

		arg:              string      &log &optional;


		mime_type:        string      &log &optional;

		file_size:        count       &log &optional;


		reply_code:       count       &log &optional;

		reply_msg:        string      &log &optional;


		data_channel:     ExpectedDataChannel &log &optional;





		cwd:                string  &default=".";


		cmdarg:             CmdArg  &optional;


		pending_commands:   PendingCmds;


		command_seq:        count &default=0;


		passive:            bool &default=F;


		capture_password:   bool &default=default_capture_password;

		logged_command_seen: bool &default=F;


		fuid: string &optional &log;
	};
}
