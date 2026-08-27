

@load ../main

module Notice;

export {
	redef enum Action += {



		ACTION_PAGE
	};



	option mail_page_dest = "";
}

hook notice(n: Notice::Info)
	{
	if ( ACTION_PAGE in n$actions )
		add n$email_dest[mail_page_dest];
	}
