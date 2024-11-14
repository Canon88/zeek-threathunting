# Loading necessary scripts for intelligence framework and expiration handling.
module ThreatHunting;

export {
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

    # Option to enable_module or disable threat hunting features.
    option enable_module: set[string] = {};

    # Including a custom configuration file for threat hunting.
    redef Config::config_files += { "/usr/local/zeek/share/zeek/site/threat-hunting/config.dat" };
}

@load ./utils/threat-level

@load ./plugins/conn
@load ./plugins/dns
@load ./plugins/http
@load ./plugins/ssh
@load ./plugins/file