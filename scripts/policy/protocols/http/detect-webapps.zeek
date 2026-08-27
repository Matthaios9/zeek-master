

@load base/frameworks/signatures
@load base/frameworks/software
@load base/protocols/http

@load-sigs ./detect-webapps.sig

module HTTP;


redef Signatures::ignored_ids += /^webapp-/;

export {
	redef enum Software::Type += {

		WEB_APPLICATION,
	};

	redef record Software::Info += {

		url:   string &optional &log;
	};
}

event signature_match(state: signature_state, msg: string, data: string) &priority=5
	{
	if ( /^webapp-/ !in state$sig_id ) return;

	local c = state$conn;
	local si: Software::Info;
	si = Software::Info($name=msg, $unparsed_version=msg, $host=c$id$resp_h, $host_p=c$id$resp_p, $software_type=WEB_APPLICATION);
	si$url = build_url_http(c$http);
	Software::found(c$id, si);
	}

event Software::register(info: Software::Info) &priority=5
	{
	if ( info$host !in Software::tracked_software )
		return;

	local ss = Software::tracked_software[info$host];

	if ( info$name !in ss )
		return;

	if ( ! ss[info$name]?$last )
		return;

	local old_info = ss[info$name]$last;

	if ( ! info?$url )
		return;




	local is_substring = 0;

	if ( |info$url| <= |old_info$url| )
		is_substring = strstr(old_info$url, info$url);

	if ( is_substring != 1 )
		return;

	old_info$url = info$url;


	info$force_log = T;
	}
