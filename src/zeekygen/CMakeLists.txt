zeek_add_subdir_library(
    zeekygen
    SOURCES
    Manager.cc
    Info.h
    PackageInfo.cc
    ScriptInfo.cc
    IdentifierInfo.cc
    Target.cc
    Configuration.cc
    ReStructuredTextTable.cc
    utils.cc)


bif_target(zeekygen.bif)
