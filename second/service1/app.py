from flask import Flask
from confluent_kafka import Producer

app = Flask(__name__)

@app.route('/ping')
def ping():
    producer = Producer({'bootstrap.servers': 'kafka:9092'})
    producer.produce('ping-topic', key='key', value='ping')
    producer.flush()
    return 'Ping sent to Kafka'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)