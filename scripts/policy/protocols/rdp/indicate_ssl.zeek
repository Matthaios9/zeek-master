


@load base/protocols/rdp
@load base/protocols/ssl

module RDP;

export {
	redef record RDP::Info += {

		ssl: bool &log &default=F;
	};
}

event ssl_established(c: connection)
	{
	if ( c?$rdp )
		{
		c$rdp$ssl = T;
		}
	}