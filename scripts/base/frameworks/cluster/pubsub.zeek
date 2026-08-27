

@load ./types

module Cluster;

export {





	global subscribe: function(topic: string): bool;






	global unsubscribe: function(topic: string): bool;






	global on_subscribe: hook(topic: string);






	global on_unsubscribe: hook(topic: string);
}



@load base/bif/cluster.bif

function subscribe(topic: string): bool
	{
	return Cluster::__subscribe(topic);
	}

function unsubscribe(topic: string): bool
	{
	return Cluster::__unsubscribe(topic);
	}
