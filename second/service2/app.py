import threading
from confluent_kafka import Consumer, KafkaError
from flask import Flask

def pong():
    conf = {
        'bootstrap.servers': 'kafka:9092',
        'group.id': 'mygroup',
        'auto.offset.reset': 'earliest'
    }

    consumer = Consumer(conf)
    consumer.subscribe(['ping-topic'])

    msg = consumer.poll(1.0)

    if msg is None:
        return 'No ping received'

    if msg.error():
        if msg.error().code() == KafkaError._PARTITION_EOF:
            return 'No more messages'
        else:
            return 'Error: ' + msg.error()
    
    print('Pong')

app = Flask(__name__)

if __name__ == '__main__':
    t = threading.Thread(target=pong)
    t.start()
    app.run(host='0.0.0.0', port=5001)