@load base/frameworks/intel
@load frameworks/intel/seen
@load packages/intel-expire/item-expire
@load packages/intel-expire/delete-expired

# Loading necessary scripts for intelligence framework and expiration handling.
module ThreatHunting;

export {
    # Option to enable or disable threat hunting features.
    option enable: bool = T;

    # Global settings for Kafka topic and server.
	global topic: string = "intelligence"; # Your Kafka topic name.
	global kafka: string = "192.168.199.98:9092"; # Your Kafka server IP address and port.
	
    # Mapping intelligence types to Zeek's internal representations.
	global intel_type: table[string] of string = { 
		["addr"] = "Intel::ADDR",  # An IP address.
		["subnet"] = "Intel::SUBNET",  # A subnet in CIDR notation.
		["url"] = "Intel::URL",  # A complete URL without the prefix "http://".
		["software"] = "Intel::SOFTWARE",  # Software name.
		["email"] = "Intel::EMAIL",  # Email address.
		["domain"] = "Intel::DOMAIN",  # DNS domain name.
		["user_name"] = "Intel::USER_NAME",  # A user name.
		["cert_hash"] = "Intel::CERT_HASH",  # Certificate SHA-1 hash.
		["pubkey_hash"] = "Intel::PUBKEY_HASH",  # Public key MD5 hash, formatted as hexadecimal digits delimited by colons. (SSH server host keys are a good example.)
		["file_hash"] = "Intel::FILE_HASH",  # File hash which is non-hash type specific. It’s up to the user to query for any relevant hash types.
		["file_name"] = "Intel::FILE_NAME",	# File name. Typically with protocols with definite indications of a file name.
	};

    # Including a custom configuration file for threat hunting.
    redef Config::config_files += { "/usr/local/zeek/share/zeek/site/threat-hunting/threathunting.dat" };
}

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

# Hook for filtering Intel log entries based on predefined criteria.
hook Intel::seen_policy(s: Intel::Seen, found: bool) &priority=10
{
    # Skip processing if threat hunting is disabled.
    if ( ! enable )
        break;

    # Break if there is no match.
    if ( ! found )
        break;

    # Default Hunting Conn::LOG.
    s$conn$threathunting = T; 
    
    # Check if the current log entry matches the set investigation criteria.
    if ("HTTP" in s$conn$service)
        s$conn$http$threathunting = T;
}
