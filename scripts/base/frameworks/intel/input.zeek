


@load ./main

module Intel;

export {



	const read_files: set[string] = {} &redef;









	const path_prefix = "" &redef;











	global read_entry: event(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item);











	global read_error: event(desc: Input::EventDescription, message: string, level: Reporter::Level);
}

event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item)
	{
	Intel::insert(item);
	}

event zeek_init() &priority=5
	{
	if ( ! Cluster::is_enabled() ||
	     Cluster::local_node_type() == Cluster::MANAGER )
		{
		for ( a_file in read_files )
			{



			local source = a_file;



			if ( |path_prefix| > 0 && sub_bytes(a_file, 0, 1) != "/" )
				source = cat(rstrip(path_prefix, "/"), "/", a_file);

			Input::add_event(Input::EventDescription($source=source,
			                                         $reader=Input::READER_ASCII,
			                                         $mode=Input::REREAD,
			                                         $name=cat("intel-", a_file),
			                                         $fields=Intel::Item,
			                                         $ev=Intel::read_entry,
			                                         $error_ev=Intel::read_error));
			}
		}
	}
