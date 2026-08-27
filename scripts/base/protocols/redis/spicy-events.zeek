

module Redis;

export {

	type SetCommand: record {

		key: string &log;

		value: string &log;

		nx: bool;

		xx: bool;

		get: bool;

		ex: count &optional;

		px: count &optional;


		exat: count &optional;


		pxat: count &optional;

		keep_ttl: bool;
	};


	type AuthCommand: record {

		username: string &optional;

		password: string;
	};


	type HelloCommand: record {

		requested_resp_version: string &optional;
	};


	type Command: record {

		raw: vector of string;


		name: string &log;

		key: string &log &optional;

		value: string &log &optional;

		known: RedisCommand &optional;
	};


	type ReplyData: record {

		attributes: string &optional;

		value: string &log;

		min_protocol_version: count;
	};
}






global set_command: event(c: connection, command: SetCommand);






global get_command: event(c: connection, key: string);






global auth_command: event(c: connection, command: AuthCommand);






global hello_command: event(c: connection, command: HelloCommand);






global command: event(c: connection, cmd: Command);











global reply: event(c: connection, data: ReplyData);







global error: event(c: connection, data: ReplyData);







global server_push: event(c: connection, data: ReplyData);
