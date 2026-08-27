




module NetControl;

export {

	option default_priority: int = +0;







	const whitelist_priority: int = +5 &redef;


	type EntityType: enum {
		ADDRESS,
		CONNECTION,
		FLOW,
		MAC,
	};





	type Flow: record {
		src_h: subnet &optional;
		src_p: port &optional;
		dst_h: subnet &optional;
		dst_p: port &optional;
		src_m: string &optional;
		dst_m: string &optional;
	};


	type Entity: record {
		ty: EntityType;
		conn: conn_id &optional;
		flow: Flow &optional;
		ip: subnet &optional;
		mac: string &optional;
	};







	type TargetType: enum {
		FORWARD,
		MONITOR,
	};





	type RuleType: enum {



		DROP,





		MODIFY,




		REDIRECT,





		WHITELIST,
	};


	type FlowMod: record {
		src_h: addr &optional;
		src_p: count &optional;
		dst_h: addr &optional;
		dst_p: count &optional;
		src_m: string &optional;
		dst_m: string &optional;
		redirect_port: count &optional;
	};




	type Rule: record {
		ty: RuleType;
		target: TargetType;
		entity: Entity;
		expire: interval &optional;
		priority: int &default=default_priority;
		location: string &optional;

		out_port: count &optional;
		mod: FlowMod &optional;

		id: string &default="";
		cid: count &default=0;
	};





	type FlowInfo: record {
		duration: interval &optional;
		packet_count: count &optional;
		byte_count: count &optional;
	};
}
