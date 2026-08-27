module FTP;

export {
	type CmdArg: record {

		ts:   time;

		cmd:  string &default="<unknown>";

		arg:  string &default="";

		seq:  count &default=0;


		cwd_consumed: bool &default=F;
	};




	type PendingCmds: table[count] of CmdArg;


	option cmd_reply_code: set[string, count] = {

		["<init>", [120, 220, 421]],
		["USER", [230, 331, 332, 421, 530, 500, 501]],
		["PASS", [230, 202, 332, 421, 530, 500, 501, 503]],
		["ACCT", [230, 202, 421, 530, 500, 501, 503]],
		["CWD",  [250, 421, 500, 501, 502, 530, 550]],
		["CDUP", [200, 250, 421, 500, 501, 502, 530, 550]],
		["SMNT", [202, 250, 421, 500, 501, 502, 530, 550]],
		["REIN", [120, 220, 421, 500, 502]],
		["QUIT", [221, 500]],
		["PORT", [200, 421, 500, 501, 530]],
		["PASV", [227, 421, 500, 501, 502, 530]],
		["MODE", [200, 421, 500, 501, 502, 504, 530]],
		["TYPE", [200, 421, 500, 501, 504, 530]],
		["STRU", [200, 421, 500, 501, 504, 530]],
		["ALLO", [200, 202, 421, 500, 501, 504, 530]],
		["REST", [200, 350, 421, 500, 501, 502, 530]],
		["STOR", [110, 125, 150, 226, 250, 421, 425, 426, 451, 551, 552, 532, 450, 452, 553, 500, 501, 530, 550]],
		["STOU", [110, 125, 150, 226, 250, 421, 425, 426, 451, 551, 552, 532, 450, 452, 553, 500, 501, 530, 550]],
		["RETR", [110, 125, 150, 226, 250, 421, 425, 426, 451, 450, 500, 501, 530, 550]],
		["LIST", [125, 150, 226, 250, 421, 425, 426, 451, 450, 500, 501, 502, 530, 550]],
		["NLST", [125, 150, 226, 250, 421, 425, 426, 451, 450, 500, 501, 502, 530, 550]],
		["APPE", [125, 150, 226, 250, 421, 425, 426, 451, 551, 552, 532, 450, 550, 452, 553, 500, 501, 502, 530]],
		["RNFR", [350, 421, 450, 550, 500, 501, 502, 530]],
		["RNTO", [250, 421, 532, 553, 500, 501, 502, 503, 530]],
		["DELE", [250, 421, 450, 550, 500, 501, 502, 530]],
		["RMD",  [250, 421, 500, 501, 502, 530, 550]],
		["MKD",  [257, 421, 500, 501, 502, 530, 550]],
		["PWD",  [257, 421, 500, 501, 502, 550]],
		["ABOR", [225, 226, 421, 500, 501, 502]],
		["SYST", [215, 421, 500, 501, 502, 530]],
		["STAT", [211, 212, 213, 421, 450, 500, 501, 502, 530]],
		["HELP", [200, 211, 214, 421, 500, 501, 502]],
		["SITE", [200, 202, 214, 500, 501, 502, 530]],
		["NOOP", [200, 421, 500]],


		["LPRT", [500, 501, 521]],
		["FEAT", [211, 500, 502]],
		["OPTS", [200, 451, 501]],
		["EPSV", [229, 500, 501]],
		["EPRT", [200, 500, 501, 522]],
		["SIZE", [213, 500, 501, 550]],
		["MDTM", [213, 500, 501, 550]],
		["MLST", [150, 226, 250, 500, 501, 550]],
		["MLSD", [150, 226, 250, 500, 501, 550]],

		["CLNT", [200, 500]],
		["MACB", [200, 500, 550]],

		["<init>", 0],
		["<missing>", 0],
		["QUIT", 0],
	};
}

function add_pending_cmd(pc: PendingCmds, seq: count, cmd: string, arg: string): CmdArg
	{
	local ca = CmdArg($cmd = cmd, $arg = arg, $seq=seq, $ts=network_time());
	pc[ca$seq] = ca;

	return ca;
	}



function get_pending_cmd(pc: PendingCmds, reply_code: count, reply_msg: string): CmdArg
	{
	local best_match: CmdArg &is_assigned;
	local best_seq = 0;
	local best_score: int = -1;

	for ( cmd_seq, cmd in pc )
		{
		local score: int = 0;



		if ( reply_code == 500 || [cmd$cmd, reply_code] in cmd_reply_code )
			score = score + 100;


		if ( strstr(reply_msg, cmd$cmd) > 0 )
			score = score + 20;
		if ( strstr(reply_msg, cmd$arg) > 0 )
			score = score + 10;

		if ( score > best_score ||
		     ( score == best_score && best_seq > cmd_seq ) )
			{
			best_score = score;
			best_seq = cmd_seq;
			best_match = cmd;
			}
		}





	return best_match;
	}

function remove_pending_cmd(pc: PendingCmds, ca: CmdArg): bool
	{
	if ( ca$seq in pc )
		{
		delete pc[ca$seq];
		return T;
		}
	else
		return F;
	}
