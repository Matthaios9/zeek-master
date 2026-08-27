











event Broker::peer_removed(ep: Broker::EndpointInfo, msg: string)
	{
	if ( "caf::sec::backpressure_overflow" !in msg ) {
		return;
	}

	if ( ! ep?$network ) {
		Reporter::error(fmt("Missing network info to re-peer with %s", ep$id));
		return;
	}






	if ( Broker::is_outbound_peering(ep$network$address, ep$network$bound_port) )
		Broker::peer(ep$network$address, ep$network$bound_port);
}
