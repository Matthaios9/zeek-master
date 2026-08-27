
module Spicy;

export {








    global enable_protocol_analyzer: function(tag: Analyzer::Tag) : bool;








    global disable_protocol_analyzer: function(tag: Analyzer::Tag) : bool;









    global enable_file_analyzer: function(tag: Files::Tag) : bool;








    global disable_file_analyzer: function(tag: Files::Tag) : bool;


    global resource_usage: function() : ResourceUsage;

}



event spicy_analyzer_for_mime_type(a: Files::Tag, mt: string) &is_used
    {
    Files::register_for_mime_type(a, mt);
    }



event spicy_analyzer_for_port(a: Analyzer::Tag, p: port) &is_used
    {
    Analyzer::register_for_port(a, p);
    }

function enable_protocol_analyzer(tag: Analyzer::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, T);
    }

function disable_protocol_analyzer(tag: Analyzer::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, F);
    }

function enable_file_analyzer(tag: Files::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, T);
    }

function disable_file_analyzer(tag: Files::Tag) : bool
    {
    return Spicy::__toggle_analyzer(tag, F);
    }

function resource_usage() : ResourceUsage
    {
    return Spicy::__resource_usage();
    }
