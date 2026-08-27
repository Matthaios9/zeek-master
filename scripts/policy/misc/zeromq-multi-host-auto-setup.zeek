








@load frameworks/cluster/backend/zeromq

module Cluster::Backend::ZeroMQ;





const env_xpub_port = getenv("ZEEK_CLUSTER_BACKEND_ZEROMQ_XPUB_PORT");
@if ( |env_xpub_port| > 0)
const xpub_port = fmt("%s/tcp", split_string1(env_xpub_port, /\//)[0]) as port;
@else
const xpub_port = 5555/tcp;
@endif

const env_xsub_port = getenv("ZEEK_CLUSTER_BACKEND_ZEROMQ_XSUB_PORT");
@if ( |env_xsub_port| > 0)
const xsub_port = fmt("%s/tcp", split_string1(env_xsub_port, /\//)[0]) as port;
@else
const xsub_port = 5556/tcp;
@endif


@if ( "manager" in Cluster::nodes && Cluster::node in Cluster::nodes )
const my_addr = Cluster::nodes[Cluster::node]$ip;
const manager_addr = Cluster::nodes["manager"]$ip;
const manager_addr_uri = addr_to_uri(manager_addr);
@else
const my_addr = [::1];
const manager_addr = [::1];
const manager_addr_uri = addr_to_uri(manager_addr);
@endif


@if ( Cluster::local_node_type() == Cluster::MANAGER )
redef listen_xpub_endpoint = fmt("tcp://%s:%s", manager_addr_uri, xpub_port as count);
redef listen_xsub_endpoint = fmt("tcp://%s:%s", manager_addr_uri, xsub_port as count);
@else
redef listen_xpub_endpoint = "";
redef listen_xsub_endpoint = "";
@endif


redef connect_xpub_endpoint = fmt("tcp://%s:%s", manager_addr_uri, xsub_port as count);
redef connect_xsub_endpoint = fmt("tcp://%s:%s", manager_addr_uri, xpub_port as count);

redef ipv6 = is_v6_addr(manager_addr) || is_v6_addr(my_addr);
