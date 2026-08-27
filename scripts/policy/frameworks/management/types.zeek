



module Management;

export {



	type Role: enum {
		NONE,
		AGENT,
		CONTROLLER,
		NODE,
	};


	type Option: record {
		name: string;
		value: string;
	};




	type Instance: record {

		name: string;

		host: addr;

		listen_port: port &optional;
	};

	type InstanceVec: vector of Instance;





	type State: enum {
		PENDING,
		RUNNING,
		STOPPED,
		FAILED,
		CRASHED,
		UNKNOWN,
	};


	type Node: record {
		name: string;
		instance: string;
		role: Supervisor::ClusterRole;
		state: State;
		p: port &optional;
		scripts: vector of string &optional;
		options: set[Option] &optional;
		interface: string &optional;
		cpu_affinity: int &optional;
		env: table[string] of string &default=table();
		metrics_port: port &optional;
	};


	type Configuration: record {
		id: string &default=unique_id("");

		instances: set[Instance] &default=set();


		nodes: set[Node] &default=set();
	};



	type NodeStatus: record {

		node: string;

		state: State;

		mgmt_role: Role &default=NONE;

		cluster_role: Supervisor::ClusterRole &default=Supervisor::NONE;


		pid: int &optional;

		p: port &optional;

		metrics_port: port &optional;
	};

	type NodeStatusVec: vector of NodeStatus;







	type Result: record {
		reqid: string;
		success: bool &default=T;
		instance: string &optional;
		data: any &optional;
		error: string &optional;
		node: string &optional;
	};

	type ResultVec: vector of Result;








	type NodeOutputs: record {
		stdout: string;
		stderr: string;
	};



	global result_to_string: function(res: Result): string;



	global result_vec_to_string: function(res: ResultVec): string;
}

function result_to_string(res: Result): string
	{
	local result = "";

	if ( res$success )
		result = "success";
	else if ( res?$error )
		result = fmt("error (%s)", res$error);
	else
		result = "error";

	local details: string_vec;

	if ( res$reqid != "" )
		details[|details|] = fmt("reqid %s", res$reqid);
	if ( res?$instance )
		details[|details|] = fmt("instance %s", res$instance);
	if ( res?$node && res$node != "" )
		details[|details|] = fmt("node %s", res$node);

	if ( |details| > 0 )
		result = fmt("%s (%s)", result, join_string_vec(details, ", "));

	return result;
	}

function result_vec_to_string(res: ResultVec): string
	{
	local ret: vector of string;

	for ( idx in res )
		ret += result_to_string(res[idx]);;

	return join_string_vec(ret, ", ");
	}
