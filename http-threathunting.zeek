const EXCLUDE_KEYS: set[string] = {};

redef record HTTP::Info += {
    threathunting: bool &log &optional;
};

hook HTTP::log_policy(rec: HTTP::Info, id: Log::ID, filter: Log::Filter)
{
    if ( filter$name == "http_investigation" ) {
        if (! rec?$threathunting) {
            break;
        }
    }
}

event zeek_init()
{
    ## Define a new log filter tailored for HTTP investigations.
    local filter: Log::Filter = [
        $name="http_investigation", 
        $path="http-investigation", 
        $exclude=EXCLUDE_KEYS
    ];

    ## Incorporate the defined filter into the standard HTTP log stream.
    Log::add_filter(HTTP::LOG, filter);
}
