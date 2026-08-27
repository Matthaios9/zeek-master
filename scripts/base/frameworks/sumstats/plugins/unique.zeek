

@load ../main

module SumStats;

export {
	redef record Reducer += {

		unique_max: count &optional;
	};

	redef enum Calculation += {

		UNIQUE
	};

	redef record ResultVal += {


		unique: count &default=0;
	};
}

redef record ResultVal += {



	unique_max: count &optional;





	unique_vals: set[Observation] &optional;
};

hook register_observe_plugins()
	{
	register_observe_plugin(UNIQUE, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		if ( ! rv?$unique_vals )
			rv$unique_vals=set();
		if ( r?$unique_max )
			rv$unique_max=r$unique_max;

		if ( ! r?$unique_max || |rv$unique_vals| <= r$unique_max )
			add rv$unique_vals[obs];

		rv$unique = |rv$unique_vals|;
		});
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( rv1?$unique_vals || rv2?$unique_vals )
		{
		if ( rv1?$unique_max )
			result$unique_max = rv1$unique_max;
		else if ( rv2?$unique_max )
			result$unique_max = rv2$unique_max;

		if ( rv1?$unique_vals )
			result$unique_vals = copy(rv1$unique_vals);

		if ( rv2?$unique_vals )
			{
			if ( ! result?$unique_vals )
				{
				result$unique_vals = copy(rv2$unique_vals);
				}
			else
				{
				for ( val2 in rv2$unique_vals )
					{
					if ( result?$unique_max && |result$unique_vals| >= result$unique_max )
						break;

					add result$unique_vals[copy(val2)];
					}
				}
			}

		result$unique = |result$unique_vals|;
		}
	}
