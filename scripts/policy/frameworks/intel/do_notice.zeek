

@load base/frameworks/intel
@load base/frameworks/notice

module Intel;

export {
	redef enum Notice::Type += {


		Intel::Notice
	};

	redef record Intel::MetaData += {



		do_notice: bool &default=F;




		if_in: Intel::Where &default=IN_ANYWHERE;
	};
}

event Intel::match(s: Seen, items: set[Item])
	{
	for ( item in items )
		{
		if ( item$meta$do_notice &&
			(item$meta$if_in == IN_ANYWHERE || s$where == item$meta$if_in) )
			{
			local n = Notice::Info($note=Intel::Notice,
				$msg = fmt("Intel hit on %s at %s", s$indicator, s$where),
				$sub = s$indicator);
			local service_str = "";

			if ( s?$conn )
				{
				n$conn = s$conn;



				local intel_id = s$indicator;
				if( s$conn?$id )
					{
					if( s$conn$id$orig_h < s$conn$id$resp_h)
						intel_id = cat(intel_id, s$conn$id$orig_h, s$conn$id$resp_h);
					else
						intel_id = cat(intel_id, s$conn$id$resp_h, s$conn$id$orig_h);
					}
				n$identifier = intel_id;

				if ( s$conn?$service )
					{
					for ( service in s$conn$service )
						service_str = cat(service_str, service, " ");
					}
				}


			local mail_ext = vector(
				fmt("Service: %s\n", service_str),
				fmt("Intel source: %s\n", item$meta$source));
			n$email_body_sections = mail_ext;

			NOTICE(n);
			}
		}
	}
