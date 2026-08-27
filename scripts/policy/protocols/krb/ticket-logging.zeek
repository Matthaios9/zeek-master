

@load base/protocols/krb

module KRB;

redef record Info += {

	auth_ticket_sha256: string &log &optional;

	new_ticket_sha256:  string &log &optional;
};

event krb_ap_request(c: connection, ticket: KRB::Ticket, opts: KRB::AP_Options)
	{

	c$krb$request_type = "AP";

	if ( ticket?$ciphertext )
		c$krb$auth_ticket_sha256 = sha256_hash(ticket$ciphertext);
	}

event krb_as_response(c: connection, msg: KDC_Response)
	{
	if ( msg$ticket?$ciphertext )
		c$krb$new_ticket_sha256 = sha256_hash(msg$ticket$ciphertext);
	}

event krb_tgs_response(c: connection, msg: KDC_Response)
	{
	if ( msg$ticket?$ciphertext )
		c$krb$new_ticket_sha256 = sha256_hash(msg$ticket$ciphertext);
	}
