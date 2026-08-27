




module Supervisor;

export {

	type ClusterRole: enum {
		NONE,
		LOGGER,
		MANAGER,
		PROXY,
		WORKER,
	};



	type ClusterEndpoint: record {

		role: ClusterRole;

		host: addr;

		p: port;


		interface: string &optional;


		pcap_file: string &optional;

		metrics_port: port &optional;
	};


	type NodeConfig: record {


		name: string;

		interface: string &optional;

		pcap_file: string &optional;

		directory: string &optional;

		stdout_file: string &optional;

		stderr_file: string &optional;


		bare_mode: bool &optional;


		addl_base_scripts: vector of string &default = vector();


		addl_user_scripts: vector of string &default = vector();

		env: table[string] of string &default=table();

		cpu_affinity: int &optional;







		cluster: table[string] of ClusterEndpoint &default=table();
	};


	type NodeStatus: record {

		node: NodeConfig;


		pid: int &optional;
	};


	type Status: record {

		nodes: table[string] of NodeStatus;
	};







	global create: function(node: NodeConfig): string;








	global status: function(node: string &default=""): Status;









	global restart: function(node: string &default=""): bool;








	global destroy: function(node: string &default=""): bool;


	global is_supervisor: function(): bool;


	global is_supervised: function(): bool;




	global node: function(): NodeConfig;













	global stdout_hook: hook(node: string, msg: string);













	global stderr_hook: hook(node: string, msg: string);










	global node_status: event(node: string, pid: count);
}
