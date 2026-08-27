




















@load ./info
@load ./main
@load base/protocols/conn
@load base/protocols/ssl
@load base/frameworks/notice

module GridFTP;

export {


	option size_threshold = 1073741824;



	option max_time = 2 min;



	option skip_data = T;




	global data_channel_detected: event(c: connection);













	const data_channel_initial_criteria: function(c: connection): bool &redef;
}

redef record FTP::Info += {
	last_auth_requested: string &optional;
};

event ftp_request(c: connection, command: string, arg: string) &priority=4
	{
	if ( command == "AUTH" && c?$ftp )
		c$ftp$last_auth_requested = arg;
	}

event ConnThreshold::bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
	{
	if ( threshold < size_threshold || "gridftp-data" in c$service || c$duration > max_time )
		return;

	if ( ! data_channel_initial_criteria(c) )
		return;

	add c$service["gridftp-data"];
	event GridFTP::data_channel_detected(c);

	if ( skip_data )
		skip_further_processing(c$id);
	}

event gridftp_possibility_timeout(c: connection)
	{


	if ( "gridftp-data" !in c$service && ! (c?$conn && c$conn?$service) )
		{
		ConnThreshold::delete_bytes_threshold(c, size_threshold, T);
		ConnThreshold::delete_bytes_threshold(c, size_threshold, F);
		}
	}

event ssl_established(c: connection) &priority=5
	{


	if ( c?$ftp && c$ftp?$last_auth_requested &&
	     /GSSAPI/ in c$ftp$last_auth_requested )
		add c$service["gridftp"];
	}

function data_channel_initial_criteria(c: connection): bool
	{
	return ( c?$ssl && c$ssl?$cert_chain && c$ssl?$client_cert_chain &&
	         |c$ssl$cert_chain| > 0 && |c$ssl$client_cert_chain| > 0 &&
	         c$ssl?$cipher && /WITH_NULL/ in c$ssl$cipher );
	}

event ssl_established(c: connection) &priority=-3
	{


	if ( data_channel_initial_criteria(c) )
		{
		ConnThreshold::set_bytes_threshold(c, size_threshold, T);
		ConnThreshold::set_bytes_threshold(c, size_threshold, F);
		schedule max_time { gridftp_possibility_timeout(c) };
		}
	}
