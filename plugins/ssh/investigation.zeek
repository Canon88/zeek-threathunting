@load ../__load__
@load ./seen

# Loading necessary scripts for intelligence framework and expiration handling.
module ThreatHunting;

redef record SSH::Info += {
    threathunting: bool &log &optional;
};

# Hook for filtering Intel log entries based on predefined criteria.
hook Intel::seen_policy(s: Intel::Seen, found: bool)
{
    # Check if the current log entry matches the set investigation criteria.
    if ( (found) && ("SSH" in enable_module) && (s$conn?$ssh) )
        s$conn$ssh$threathunting = T;
}

hook SSH::log_policy(rec: SSH::Info, id: Log::ID, filter: Log::Filter)
{
    if ( filter$name == "ssh_investigation" ) {
        if (! rec?$threathunting) {
            return;
        }
    }
}

event zeek_init()
{
    ## Define a new log filter tailored for SSH investigations.
    local filter: Log::Filter = [
        $name="ssh_investigation",
        $path="ssh-investigation"
    ];

    ## Incorporate the defined filter into the standard SSH log stream.
    Log::add_filter(SSH::LOG, filter);
}
