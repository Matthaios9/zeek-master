zeek_add_plugin(
    Zeek Pcap
    SOURCES Source.cc Dumper.cc Plugin.cc)


bif_target(pcap.bif)
