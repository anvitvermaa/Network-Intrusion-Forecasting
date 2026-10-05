#!/usr/bin/env python3
"""Phase 2 - Kafka Consumer (verification).

Reads messages off the network-flow-data topic and prints them, proving the
producer->Kafka->consumer pipe works end to end. Also used for the data-loss
resilience test.

USAGE:
  python consumer.py                 # consume from current position, print 10
  python consumer.py --count 20      # print 20 messages
  python consumer.py --from-start    # read from the very beginning of the topic
"""
import argparse, json
from confluent_kafka import Consumer, KafkaError

TOPIC = "network-flow-data"
BOOTSTRAP = "localhost:9092"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=10, help="messages to print")
    ap.add_argument("--from-start", action="store_true",
                    help="read from beginning of topic")
    ap.add_argument("--group", default="nif-verify",
                    help="consumer group id")
    args = ap.parse_args()

    consumer = Consumer({
        "bootstrap.servers": BOOTSTRAP,
        "group.id": args.group,
        "auto.offset.reset": "earliest" if args.from_start else "latest",
        "enable.auto.commit": True,
    })
    consumer.subscribe([TOPIC])
    print(f"[consumer] group='{args.group}' reading up to {args.count} messages "
          f"from '{TOPIC}' ({'earliest' if args.from_start else 'latest'})...")

    seen = 0
    try:
        while seen < args.count:
            msg = consumer.poll(timeout=5.0)
            if msg is None:
                print("   (waiting for messages... run the producer in another terminal)")
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                print(f"[error] {msg.error()}")
                continue
            rec = json.loads(msg.value().decode("utf-8"))
            seen += 1
            # print a compact view: label + a few features
            label = rec.get("label", "?")
            stage = rec.get("kill_chain_stage", "?")
            dur = rec.get("duration", "?")
            print(f"   #{seen} offset={msg.offset()} label={label} "
                  f"stage={stage} duration={dur}")
    finally:
        consumer.close()
    print(f"[done] consumed {seen} messages successfully.")


if __name__ == "__main__":
    main()
