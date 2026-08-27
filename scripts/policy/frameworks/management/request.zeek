



@load ./config
@load ./types

module Management::Request;

export {






	type Request: record {

		id: string;





		parent_id: string &optional;



		results: Management::ResultVec &default=vector();


		finished: bool &default=F;
	};



	redef record Request += {


		finish: function(req: Management::Request::Request) &optional;
	};










	const timeout_interval = 10sec &redef;


	global null_req = Request($id="", $finished=T);





	global create: function(reqid: string &default=unique_id("")): Request;






	global lookup: function(reqid: string): Request;







	global finish: function(reqid: string): bool;







	global request_expired: event(req: Request);








	global is_null: function(request: Request): bool;





	global to_string: function(request: Request): string;
}

function requests_expire_func(reqs: table[string] of Request, reqid: string): interval
	{


	if ( ! reqs[reqid]$finished )
		event Management::Request::request_expired(reqs[reqid]);

	return 0secs;
	}





global g_requests: table[string] of Request
    &create_expire=timeout_interval &expire_func=requests_expire_func;

function create(reqid: string): Request
	{
	local ret = Request($id=reqid);
	g_requests[reqid] = ret;
	return ret;
	}

function lookup(reqid: string): Request
	{
	if ( reqid in g_requests )
		return g_requests[reqid];

	return null_req;
	}

function finish(reqid: string): bool
	{
	if ( reqid !in g_requests )
		return F;

	local req = g_requests[reqid];
	delete g_requests[reqid];

	if ( req?$finish )
		req$finish(req);

	req$finished = T;

	return T;
	}

function is_null(request: Request): bool
	{
	if ( request$id == "" )
		return T;

	return F;
	}

function to_string(request: Request): string
	{
	local parent_id = "";

	if ( request?$parent_id )
		parent_id = fmt(" (via %s)", request$parent_id);

	return fmt("[request %s%s %s, results: %s]", request$id, parent_id,
	           request$finished ? "finished" : "pending",
		   Management::result_vec_to_string(request$results));
	}
