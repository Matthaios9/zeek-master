



@load base/protocols/ssl
@load base/files/x509

redef record X509::Info += {

	cert: string &log &optional;
};


redef X509::default_max_field_string_bytes = 0;

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=1
	{
	if ( ! f$info?$x509 )
		return;

	f$info$x509$cert = encode_base64(x509_get_certificate_string(cert_ref));
	}
