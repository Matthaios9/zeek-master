

module Queue;

export {

	type Settings: record {



		max_len: count &optional;
	};


	type Queue: record {};






	global init:       function(s: Settings &default=[]): Queue;






	global put:       function(q: Queue, val: any);






	global get:        function(q: Queue): any;






	global peek:      function(q: Queue): any;










	global merge:      function(q1: Queue, q2: Queue): Queue;






	global len:     function(q: Queue): count;







	global get_vector: function(q: Queue, ret: vector of any);

}

redef record Queue += {

	initialized: bool                   &default=F;

	vals:        table[count] of any &optional;

	settings:    Settings               &optional;

	top:         count                  &default=0;

	bottom:      count                  &default=0;

	size:        count                  &default=0;
};

function init(s: Settings): Queue
	{
	local q: Queue;
	q$vals=table();
	q$settings = copy(s);
	q$initialized=T;
	return q;
	}

function put(q: Queue, val: any)
	{
	if ( q$settings?$max_len && len(q) >= q$settings$max_len )
		get(q);
	q$vals[q$top] = val;
	++q$top;
	}

function get(q: Queue): any
	{
	local ret = q$vals[q$bottom];
	delete q$vals[q$bottom];
	++q$bottom;
	return ret;
	}

function peek(q: Queue): any
	{
	return q$vals[q$bottom];
	}

function merge(q1: Queue, q2: Queue): Queue
	{
	local ret = init(q1$settings);
	local i = q1$bottom;
	local j = q2$bottom;
	for ( ignored_val in q1$vals )
		{
		if ( i in q1$vals )
			put(ret, q1$vals[i]);
		if ( j in q2$vals )
			put(ret, q2$vals[j]);
		++i;
		++j;
		}
	return ret;
	}

function len(q: Queue): count
	{
	return |q$vals|;
	}

function get_vector(q: Queue, ret: vector of any)
	{
	local i = q$bottom;
	local j = 0;



	for ( ignored_val in q$vals )
		{
		if ( i >= q$top )
			break;

		ret[j] = q$vals[i];
		++j; ++i;
		}
	}
