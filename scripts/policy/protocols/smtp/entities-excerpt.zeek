


@load base/protocols/smtp/entities

module SMTP;

export {
	redef record SMTP::Entity+= {

		excerpt:    string &log &default="";
	};




	option default_entity_excerpt_len = 0;
}

event file_new(f: fa_file) &priority=5
	{
	if ( ! f?$source ) return;
	if ( f$source != "SMTP" ) return;
	if ( ! f?$bof_buffer ) return;
	if ( ! f?$conns ) return;

	for ( _, c in f$conns )
		{
		if ( ! c?$smtp ) next;

		if ( default_entity_excerpt_len > 0 )
			c$smtp$entity$excerpt = f$bof_buffer[0:default_entity_excerpt_len];
		}
	}
