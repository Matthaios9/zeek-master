

@load base/frameworks/sumstats
@load base/utils/queue

module SumStats;

export {
	redef enum Calculation += {

		LAST
	};

	redef record Reducer += {

		num_last_elements: count &default=0;
	};

	redef record ResultVal += {




		last_elements: Queue::Queue &optional;
	};


	global get_last: function(rv: ResultVal): vector of Observation;
}

function get_last(rv: ResultVal): vector of Observation
	{
	local s: vector of any = vector();

	if ( rv?$last_elements )
		Queue::get_vector(rv$last_elements, s);

	local rval: vector of Observation = vector();

	for ( i in s )




		rval += s[i] as Observation;

	return rval;
	}

hook register_observe_plugins()
	{
	register_observe_plugin(LAST, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		if ( r$num_last_elements > 0 )
			{
			if ( ! rv?$last_elements )
				rv$last_elements = Queue::init(Queue::Settings($max_len=r$num_last_elements));
			Queue::put(rv$last_elements, obs);
			}
		});
	}


hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{

	if ( rv1?$last_elements && rv2?$last_elements )
		result$last_elements = Queue::merge(rv1$last_elements, rv2$last_elements);
	else if ( rv1?$last_elements )
		result$last_elements = rv1$last_elements;
	else if ( rv2?$last_elements )
		result$last_elements = rv2$last_elements;
	}
