@load ../__load__
@load ./seen

# Loading necessary scripts for intelligence framework and expiration handling.
module ThreatHunting;

const EXCLUDE_KEYS: set[string] = {};

redef record HTTP::Info += {
    threathunting: bool &log &optional;
};

# Hook for filtering Intel log entries based on predefined criteria.
hook Intel::seen_policy(s: Intel::Seen, found: bool)
{
    # Check if the current log entry matches the set investigation criteria.
    if ( (found) && ("HTTP" in enable_module) && (s$conn?$http) )
        s$conn$http$threathunting = T;
}

hook HTTP::log_policy(rec: HTTP::Info, id: Log::ID, filter: Log::Filter)
{
    if ( filter$name == "http_investigation" ) {
        if (! rec?$threathunting) {
            return;
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
