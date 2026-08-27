

@load base/frameworks/storage/main

module Storage::Backend::Redis;

export {


	const default_connect_timeout: interval = 5 secs &redef;



	const default_operation_timeout: interval = 5 secs &redef;


	type Options: record {

		server_host: string &optional;


		server_port: port &default=6379/tcp;




		server_unix_socket: string &optional;




		key_prefix: string &default="";




		connect_timeout: interval &default=default_connect_timeout;



		operation_timeout: interval &default=default_operation_timeout;


		username: string &optional;



		password: string &optional;
	};
}

redef record Storage::BackendOptions += {
	redis: Storage::Backend::Redis::Options &optional;
};
