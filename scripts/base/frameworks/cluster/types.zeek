
module Cluster;

export {


	type NodeType: enum {


		NONE,


		CONTROL,

		LOGGER,

		MANAGER,


		PROXY,

		WORKER,
	};


	type Node: record {

		node_type:    NodeType;

		ip:           addr;


		zone_id:      string      &default="";


		p:            port        &default=0/unknown;

		manager:      string      &optional;


		id: string                &optional;



		metrics_port: port        &optional;
	};


	type NamedNode: record {
		name: string;
		node: Node;
	};




	type Event: record {

		ev: any;

		args: vector of any;
	};









	const default_websocket_max_event_queue_size = 32 &redef;


	const default_websocket_ping_interval = 5 sec &redef;





	type WebSocketTLSOptions: record {

		cert_file: string &optional;

		key_file: string &optional;

		enable_peer_verification: bool &default=F;



		ca_file: string &default="";

		ciphers: string &default="";
	};


	type WebSocketServerOptions: record {

		listen_addr: addr &optional;

		listen_port: port;

		max_event_queue_size: count &default=default_websocket_max_event_queue_size;



		ping_interval: interval &default=default_websocket_ping_interval;


		tls_options: WebSocketTLSOptions &default=WebSocketTLSOptions();
	};


	type NetworkInfo: record {

		address: string;

		bound_port: port;
	};


	type EndpointInfo: record {
		id: string;
		network: NetworkInfo;

		application_name: string &optional;
	};
}
