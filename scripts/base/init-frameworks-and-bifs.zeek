



@load base/frameworks/logging
@load base/frameworks/broker
@load base/frameworks/supervisor
@load base/frameworks/input
@load base/frameworks/cluster
@load base/frameworks/config
@load base/frameworks/analyzer
@load base/frameworks/files
@load base/frameworks/telemetry/options


@load base/bif


@load base/bif/plugins

@if ( have_spicy() )
@load base/frameworks/spicy/init-framework
@endif








@if ( __init_secondary_bifs() )
@endif
