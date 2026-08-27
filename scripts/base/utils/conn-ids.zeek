

module GLOBAL;

export {



	global id_string: function(id: conn_id): string;




	global reverse_id_string: function(id: conn_id): string;



	global directed_id_string: function(id: conn_id, is_orig: bool): string;
}





function id_string(id: conn_id): string
	{
	return fmt("%s:%d > %s:%d",
		id$orig_h, id$orig_p,
		id$resp_h, id$resp_p);
	}

function reverse_id_string(id: conn_id): string
	{
	return fmt("%s:%d < %s:%d",
		id$orig_h, id$orig_p,
		id$resp_h, id$resp_p);
	}

function directed_id_string(id: conn_id, is_orig: bool): string
	{
	return is_orig ? id_string(id) : reverse_id_string(id);
	}
