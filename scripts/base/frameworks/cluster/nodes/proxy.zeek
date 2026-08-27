




@prefixes += cluster-proxy


redef Log::enable_local_logging = F;


redef Log::enable_remote_logging = T;

redef Log::default_rotation_interval = 24hrs;

@if ( ! Supervisor::is_supervised() )

redef Log::default_rotation_postprocessor_cmd = "delete-log";
@endif
