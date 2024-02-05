# zeek-threathunting
 Custom log capture via Intel::LOG from ZeekJS + Intelligence Framework. If log capture is a compliance risk for you, then this may be a good solution, at least it is triggered by security Incident.

 I use Intel::LOG as a trigger for ThreatHunting when a security event occurs. Once the IoC (Indicator of Compromise) is triggered, I automatically log all HTTP logs via Zeek.



# Zeek Threat Hunting Integration

This project aims to implement threat hunting in network traffic using Zeek scripts and configurations, with intelligence sharing via Kafka.

## Environment

- version: zeek version 6.2.0-dev.500
- 

## File List

- `threathunting.zeek`: The main Zeek script that loads necessary frameworks and configurations, setting global variables for threat hunting.
- `http-threathunting.zeek`: A Zeek script for threat hunting in HTTP traffic, extending HTTP logs to include fields specific to threat hunting.
- `threathunting.js`: A JavaScript script for consuming messages from Kafka and inserting intelligence items into Zeek's intelligence framework.
- `threathunting.dat`: A configuration file to enable the threat hunting feature.

## Configuration Steps

1. Ensure the Zeek environment is installed and the Kafka plugin is configured.
2. Place all script files in the Zeek script directory.
3. Include the `threathunting.zeek` script in the Zeek configuration.
4. Modify the Kafka server address and port in `threathunting.zeek`, along with other related configurations, according to your environment.
5. Start Zeek and confirm that the threat hunting functionality is activated.

## Feature Description

- **Threat Intelligence Sharing**: Uses Kafka as middleware for real-time sharing of threat intelligence.
- **HTTP Traffic Monitoring**: Specific logging for HTTP traffic to facilitate subsequent threat analysis.
- **Dynamic Intelligence Handling**: Consumes intelligence data from Kafka using a JavaScript script and dynamically inserts it into Zeek's intelligence framework for real-time threat identification.

## Notes

- Ensure the Zeek version is compatible with the project scripts.
- The Kafka server should be pre-configured and ensure smooth network communication.
- Adjust the configuration items in the scripts according to the actual situation.

## Workflow

![Workflow](Workflow.png)

## Demo

![threathunting](threathunting.gif)

