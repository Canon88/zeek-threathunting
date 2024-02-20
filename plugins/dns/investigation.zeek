@load ../__load__

# Loading necessary scripts for intelligence framework and expiration handling.
module ThreatHunting;

redef record DNS::Info += {
    threathunting: bool &log &optional;
};

# Hook for filtering Intel log entries based on predefined criteria.
hook Intel::seen_policy(s: Intel::Seen, found: bool) &priority=10
{
    # Break if there is no match.
    if ( ! found )
        break;

    # Check if the current log entry matches the set investigation criteria.
    if ( ("DNS" in enable_module) && (s$conn?$dns) )
        s$conn$dns$threathunting = T;
}


hook DNS::log_policy(rec: DNS::Info, id: Log::ID, filter: Log::Filter)
{
    if ( filter$name == "dns_investigation" ) {
        if (! rec?$threathunting) {
            break;
        }
    }
}

event zeek_init()
{
    ## Define a new log filter tailored for DNS investigations.
    local filter: Log::Filter = [
        $name="dns_investigation",
        $path="dns-investigation"
    ];

    ## Incorporate the defined filter into the standard DNS log stream.
    Log::add_filter(DNS::LOG, filter);
}
