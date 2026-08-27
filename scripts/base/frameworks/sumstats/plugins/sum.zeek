

@load ../main

module SumStats;

export {
	redef enum Calculation += {


		SUM
	};

	redef record ResultVal += {

		sum: double &default=0.0;
	};



}











hook init_resultval_hook(r: Reducer, rv: ResultVal)
	{
	if ( SUM in r$apply && ! rv?$sum )
		rv$sum = 0;
	}

hook register_observe_plugins()
	{
	register_observe_plugin(SUM, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		rv$sum += val;
		});
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( rv1?$sum || rv2?$sum )
		{
		result$sum = rv1?$sum ? rv1$sum : 0;
		if ( rv2?$sum )
			result$sum += rv2$sum;
		}
	}
