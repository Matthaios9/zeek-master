







@load base/frameworks/input
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/ssl

module SSL;



redef SSL::disable_analyzer_after_detection = F;

export {



	const keylog_file = getenv("ZEEK_TLS_KEYLOG_FILE") &redef;


	const secret_expiration = 5 mins &redef;






	global add_keys: event(client_random: string, keys: string);






	global add_secret: event(client_random: string, secrets: string);
}

@if ( keylog_file == "" )


global secrets: table[string] of string = {} &redef;
global keys: table[string] of string = {} &redef;
@else
global secrets: table[string] of string = {} &read_expire=secret_expiration &redef;
global keys: table[string] of string = {} &read_expire=secret_expiration &redef;
@endif


redef record SSL::Info += {

	client_random: string &optional;
};

type SecretsIdx: record {
	client_random: string;
};

type SecretsVal: record {
	secret: string;
};

const tls_decrypt_stream_name = "tls-keylog-file";

event zeek_init()
	{

	Broker::subscribe("/zeek/tls/decryption");

	if ( keylog_file != "" )
		{
		Input::add_table(Input::TableDescription($name=tls_decrypt_stream_name, $source=keylog_file, $destination=secrets, $idx=SecretsIdx, $val=SecretsVal, $want_record=F));
		Input::remove(tls_decrypt_stream_name);
		}
	}

event SSL::add_keys(client_random: string, val: string)
	{
	SSL::keys[client_random] = val;
	}

event SSL::add_secret(client_random: string, val: string)
	{
	SSL::secrets[client_random] = val;
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
	{
	c$ssl$client_random = client_random;

	if ( client_random in keys )
		set_keys(c, keys[client_random]);
	else if ( client_random in secrets )
		set_secret(c, secrets[client_random]);
	}

event ssl_change_cipher_spec(c: connection, is_client: bool)
	{
	if ( c$ssl?$client_random )
		{
		if ( c$ssl$client_random in keys )
			set_keys(c, keys[c$ssl$client_random]);
		else if ( c$ssl$client_random in secrets )
			set_secret(c, secrets[c$ssl$client_random]);
		}
	}
