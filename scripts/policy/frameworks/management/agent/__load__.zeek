








@if ( Supervisor::is_supervised() )
@load policy/frameworks/management/agent/config
@endif

@if ( Supervisor::is_supervisor() )
@load policy/frameworks/management/supervisor
@load ./boot
@endif
