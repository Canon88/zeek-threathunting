# Loading necessary scripts for intelligence framework and expiration handling.
module ThreatHunting;

# Condition to check if the script should run based on the Zeek cluster status.
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )

    # Check for JavaScript support and load the related script if available.
    @ifdef ( JavaScript::main_script_source )
        @load ./threathunting.js

    # Log an error if JavaScript support is not available.
    @else
        event zeek_init() {
            Reporter::error("Missing JavaScript support");
        }
    @endif
@endif
