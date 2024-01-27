// Importing Kafka from the 'kafkajs' library
const { Kafka } = require('kafkajs');

// Read some redefs from the Zeek side into globals
let threathunting_topic = zeek.global_vars['ThreatHunting::topic'];
let kafka_server = zeek.global_vars['ThreatHunting::kafka'];
let intel_type = zeek.global_vars['ThreatHunting::intel_type'];


// Defining the KafkaConsumer class
class KafkaConsumer {
  // Constructor for the KafkaConsumer class
  constructor(clientId, brokers, groupId) {
    this.kafka = new Kafka({
      clientId: clientId, // Client identifier for the Kafka connection
      brokers: brokers,   // List of broker addresses
    });
    this.consumer = this.kafka.consumer({ groupId: groupId }); // Creating a consumer with a specific group ID
    this.topic = '';     // Initial empty topic to be set later
  }

  // Method to set the topic that this consumer will subscribe to
  setTopic(topic) {
    this.topic = topic;  // Setting the topic
    return this;
  }

  // Method to provide a callback function for message processing
  onMessage(callback) {
    this.messageCallback = callback; // Storing the callback function
  }

  // Method to connect to Kafka, subscribe to the topic, and start listening for messages
  async connectAndConsume() {
    try {
      await this.consumer.connect(); // Connecting the consumer to Kafka
      await this.consumer.subscribe({ topic: this.topic, fromBeginning: false }); // Subscribing to the specified topic

      await this.consumer.run({
        // Asynchronous function to handle each received message
        eachMessage: async ({ topic, partition, message }) => {
          const messageData = {
            partition, // Partition from which the message was received
            offset: message.offset, // Offset of the message in the partition
            value: message.value.toString(), // Converting the message value to string
          };
          // Invoking the callback function with the message data
          this.messageCallback(messageData);
        },
      });
    } catch (error) {
      console.error('Error in KafkaConsumer: ', error); // Logging any errors
      await this.disconnect(); // Disconnecting in case of error
    }
  }

  // Method to disconnect the consumer
  async disconnect() {
    await this.consumer.disconnect(); // Disconnecting the consumer from Kafka
  }
}

// Creating an instance of KafkaConsumer
const kafkaConsumer = new KafkaConsumer('my-app', [kafka_server], 'my-group');
kafkaConsumer.setTopic(threathunting_topic); // Setting the topic to 'zeek-http'

// Defining a callback function to handle received messages
function handleMessage(message) {
  // Logging received messages (currently commented out)
  // console.log('Received message:', message);

  // Attempting to parse the JSON string in the 'value' field of the message
  try {
    const valueObject = JSON.parse(message.value);

    // Validate message format and content
    if (!valueObject.ioc || !valueObject.type || !valueObject.meta) {
      throw new Error('Invalid message format');
    }

    const indicator = valueObject.ioc; // Extracting the indicator
    if (!indicator) {
      throw new Error('Invalid indicator');
    }

    const _indicator_type = valueObject.type; // Extracting the indicator_type
    const indicator_type = intel_type.hasOwnProperty(_indicator_type) ? intel_type[_indicator_type] : 'unknown'; // Setting the indicator type e.g. Intel::ADDR, Intel::DOMAIN, etc.
    if (indicator_type == 'unknown') {
      throw new Error('Unknown indicator type encountered');
    }

    const source = valueObject.meta.source; // Extracting the meta_source
    const desc = valueObject.meta.desc; // Extracting the meta_desc
    const expire = valueObject.meta.expire; // Extracting the meta_expire

    let intel_item = {
      indicator: indicator,                 // Using the source IP as the indicator
      indicator_type: indicator_type,     // Setting the indicator type e.g. Intel::ADDR, Intel::DOMAIN, etc.
      meta: { 
        source: source,
        desc: desc,
        expire: expire,
      },     // Adding metadata to the intelligence item
    };

    // Invoking a function (presumably from the Zeek framework) to insert the intelligence item
    zeek.invoke('Intel::insert', [intel_item]);

  } catch (error) {
    // Logging an error if there's a problem parsing the message value
    console.error('Error parsing message value:', error);
  }
}

// Setting the message handling callback function and connecting to Kafka to start consuming messages
kafkaConsumer.onMessage(handleMessage);
kafkaConsumer.connectAndConsume();