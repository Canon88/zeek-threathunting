@load ../__load__

# Loading necessary scripts for intelligence framework and expiration handling.
module ThreatHunting;

# Extend the Files::Info record to include a 'threathunting' field
redef record Files::Info += {
    threathunting: bool &log &optional;
};

# Hook for filtering Intel log entries based on predefined criteria
hook Intel::seen_policy(s: Intel::Seen, found: bool) &priority = 10 {
    # Update 2024-06-26 by Canon. Fix "field value missing (ThreatHunting::s$f)"
    if ((! s?$f) || (! s$f?$info))
        return;

    # If the entry is found and the "FILE" module is enabled, set the 'threathunting' flag
    if (found && ("FILE" in enable_module)) {
        s$f$info$threathunting = T;
    }
}

# Hook to modify the log policy for Files records
hook Files::log_policy(rec: Files::Info, id: Log::ID, filter: Log::Filter) &priority = 5 {
    # Apply the policy only if the filter name is "files_investigation"
    if (filter$name == "files_investigation") {
        # If 'threathunting' field is not set, exit the hook
        if (! rec?$threathunting) {
            return;
        }
    }
}

# Event to initialize the Zeek script
event zeek_init() {
    # Define a new log filter tailored for Files investigations
    local filter: Log::Filter = [
        $name = "files_investigation",
        $path = "files-investigation"
    ];

    # Incorporate the defined filter into the standard Files log stream
    Log::add_filter(Files::LOG, filter);
}