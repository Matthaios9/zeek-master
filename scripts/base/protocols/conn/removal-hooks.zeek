








module Conn;

export {




	type RemovalHook: hook(c: connection);










	global register_removal_hook: function(c: connection, hk: RemovalHook): bool;











	global unregister_removal_hook: function(c: connection, hk: RemovalHook): bool;
}

redef record connection += {
	removal_hooks: set[RemovalHook] &optional;
};

function register_removal_hook(c: connection, hk: RemovalHook): bool
	{
	if ( c?$removal_hooks )
		{
		if ( hk in c$removal_hooks )
			return F;

		add c$removal_hooks[hk];
		return T;
		}

	c$removal_hooks = set(hk);
	return T;
	}

function unregister_removal_hook(c: connection, hk: RemovalHook): bool
	{
	if ( ! c?$removal_hooks )
		return F;

	if ( hk !in c$removal_hooks )
		return F;

	delete c$removal_hooks[hk];
	return T;
	}

event connection_state_remove(c: connection) &priority=-3
	{
	if ( c?$removal_hooks )
		for ( removal_hook in c$removal_hooks )
			hook removal_hook(c);
	}
