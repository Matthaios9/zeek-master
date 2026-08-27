




@load ../main
@load base/utils/site

module Notice;

export {
	redef enum Action += {




		ACTION_EMAIL_ADMIN
	};
}

hook notice(n: Notice::Info)
	{
	if ( |Site::local_admins| > 0 &&
	     ACTION_EMAIL_ADMIN in n$actions )
		{
		if ( n?$src && |Site::get_emails(n$src)| > 0 )
			add n$email_dest[Site::get_emails(n$src)];
		if ( n?$dst && |Site::get_emails(n$dst)| > 0 )
			add n$email_dest[Site::get_emails(n$dst)];
		}
	}
