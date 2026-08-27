

event zeek_init()
	{
	Files::register_for_mime_type(Files::ANALYZER_ZIP, "application/zip");
	}
