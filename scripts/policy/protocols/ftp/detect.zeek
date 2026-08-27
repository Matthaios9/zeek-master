

@load base/frameworks/notice
@load base/protocols/ftp

module FTP;

export {
	redef enum Notice::Type += {


		Site_Exec_Success,
	};
}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) &priority=3
	{
	local response_xyz = parse_ftp_reply_code(code);


	if ( response_xyz$x == 2 &&
	     c$ftp$cmdarg$cmd == "SITE" &&
	     /[Ee][Xx][Ee][Cc]/ in c$ftp$cmdarg$arg )
		{
		NOTICE(Notice::Info($note=Site_Exec_Success, $conn=c,
		                    $msg=fmt("FTP command: %s %s", c$ftp$cmdarg$cmd, c$ftp$cmdarg$arg),
		                    $identifier=cat(c$id$orig_h, c$id$resp_h, "SITE EXEC")));
		}
	}
