from confluent_kafka import Producer
import json

# Kafka configuration
conf = {
    'bootstrap.servers': '192.168.199.98:9092',  # Replace with your Kafka server address
    'client.id': 'SOAR_Client'
}

# Create a Producer instance
producer = Producer(conf)

# Data to be sent
data = {
    "ioc": "httpbin.org",
    "type": "domain",
    "meta": {
        "expire": 300,
        "source": "SOAR",
        "desc": "bad domain"
    }
}

# Convert the data to a JSON string
data_string = json.dumps(data)

# Callback function to check if message delivery was successful
def delivery_report(err, msg):
    if err is not None:
        print(f'Message delivery failed: {err}')
    else:
        print(f'Message delivered to {msg.topic()} [{msg.partition()}]')

# Produce and send the message
topic = 'intelligence'
producer.produce(topic, data_string, callback=delivery_report)

# Wait for any outstanding messages to be delivered
producer.flush()
