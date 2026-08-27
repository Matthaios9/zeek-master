


@load ./exec

module ActiveHTTP;

export {

	option default_max_time = 1min;


	option default_method = "GET";

	type Response: record {

		code:      count;

		msg:       string;

		body:      string                  &optional;

		headers:   table[string] of string &optional;
	};

	type Request: record {

		url:             string;

		method:          string                  &default=default_method;



		client_data:     string                  &optional;






		max_time:        interval                &default=default_max_time;



		addl_curl_args:  string                  &optional;
	};








	global request: function(req: ActiveHTTP::Request): ActiveHTTP::Response;
}

function request2curl(r: Request, bodyfile: string, headersfile: string): string
	{
	local cmd = fmt("curl -s -g -o %s -D %s -X %s",
	                safe_shell_quote(bodyfile),
	                safe_shell_quote(headersfile),
	                safe_shell_quote(r$method));

	cmd = fmt("%s -m %.0f", cmd, r$max_time);

	if ( r?$client_data )
		cmd = fmt("%s -d @-", cmd);

	if ( r?$addl_curl_args )
		cmd = fmt("%s %s", cmd, r$addl_curl_args);

	cmd = fmt("%s %s", cmd, safe_shell_quote(r$url));

	cmd = fmt("%s && touch %s", cmd, safe_shell_quote(bodyfile));
	return cmd;
	}

function request(req: Request): ActiveHTTP::Response
	{
	local resp: Response;
	resp$code = 0;
	resp$msg = "";
	resp$body = "";
	resp$headers = table();


	if ( req$method != /[A-Za-z]+/ )
		{
		Reporter::error(fmt("There was an illegal method specified with ActiveHTTP (\"%s\").", req$method));
		return resp;
		}

	local tmp_dir = getenv("TEMP");
	if ( tmp_dir == "" )
		tmp_dir = getenv("TMPDIR");
	if ( tmp_dir == "" )
		tmp_dir = "/tmp";
	tmp_dir = gsub(tmp_dir, /\\/, "/");

	local tmpfile     = tmp_dir + "/zeek-activehttp-" + unique_id("");
	local bodyfile    = fmt("%s_body", tmpfile);
	local headersfile = fmt("%s_headers", tmpfile);

	local cmd = request2curl(req, bodyfile, headersfile);
	local stdin_data = req?$client_data ? req$client_data : "";

	return when [req, resp, cmd, stdin_data, bodyfile, headersfile] ( local result = Exec::run(Exec::Command($cmd=cmd, $stdin=stdin_data, $read_files=set(bodyfile, headersfile))) )
		{

		if ( ! (result?$files && headersfile in result$files) )
			{
			Reporter::error(fmt("There was a failure when requesting \"%s\" with ActiveHTTP.", req$url));
			return resp;
			}

		local headers = result$files[headersfile];
		for ( i in headers )
			{

			if ( i == 0 )
				{
				local response_line = split_string_n(headers[0], /[[:blank:]]+/, F, 2);
				if ( |response_line| != 3 )
					return resp;

				resp$code = response_line[1] as count;
				resp$msg = response_line[2];
				resp$body = join_string_vec(result$files[bodyfile], "");
				}
			else
				{
				local line = headers[i];
				local h = split_string1(line, /:/);
				if ( |h| != 2 )
					next;
				resp$headers[h[0]] = sub_bytes(h[1], 0, |h[1]|-1);
				}
			}
		return resp;
		}
	}
