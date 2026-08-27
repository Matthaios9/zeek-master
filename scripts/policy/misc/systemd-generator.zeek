

@load base/frameworks/cluster







@if ( Cluster::local_node_type() == Cluster::LOGGER || ( Cluster::local_node_type() == Cluster::MANAGER && Cluster::manager_is_logger ) || ! Cluster::is_enabled() )
@load base/frameworks/cluster/nodes/logger
@load base/frameworks/logging
redef Log::default_rotation_dir = "../log-queue";
redef Log::rotation_format_func = archiver_rotation_format_func;
redef LogAscii::enable_leftover_log_rotation = T;
redef Log::default_rotation_postprocessor_cmd = "";
@endif
