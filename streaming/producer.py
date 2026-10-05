#!/usr/bin/env python3
"""Phase 2 - Kafka Replay Producer.

Reads labeled flow records from Parquet and streams them into Kafka as JSON,
row by row, simulating a live network telemetry feed (Zeek-equivalent flows).

This is the standard streaming-ML pattern: a replay producer over a fixed
dataset gives reproducible, rate-controllable throughput -- exactly what's
needed to evaluate streaming latency in Phase 5.

USAGE:
  python producer.py                      # stream test.parquet at 1000 msg/s
  python producer.py --rate 100           # throttle to 100 msg/s
  python producer.py --rate 0             # max speed (no throttle)
  python producer.py --limit 5000         # only send first 5000 rows
  python producer.py --split train        # stream a different split
"""
import argparse, json, os, time
import pandas as pd
from confluent_kafka import Producer

HERE = os.path.dirname(os.path.abspath(__file__))
PROC = os.path.join(HERE, "..", "data", "processed")
TOPIC = "network-flow-data"
BOOTSTRAP = "localhost:9092"


def make_producer():
    return Producer({
        "bootstrap.servers": BOOTSTRAP,
        "client.id": "nif-replay-producer",
        "acks": "all",            # wait for broker ack (no data loss)
        "linger.ms": 5,           # small batching for throughput
        "compression.type": "lz4",
    })


def delivery_report(err, msg):
    # called async for each message; only print failures to avoid spam
    if err is not None:
        print(f"[DELIVERY FAILED] {err}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test", choices=["train", "val", "test"])
    ap.add_argument("--rate", type=float, default=1000.0,
                    help="messages/sec (0 = max speed)")
    ap.add_argument("--limit", type=int, default=0, help="max rows (0 = all)")
    args = ap.parse_args()

    path = os.path.join(PROC, f"{args.split}.parquet")
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found (run Phase 0 first)")

    print(f"[load] reading {args.split}.parquet ...")
    df = pd.read_parquet(path)
    if args.limit > 0:
        df = df.sample(n=min(args.limit, len(df)), random_state=42).reset_index(drop=True)
    n = len(df)
    print(f"[producer] streaming {n:,} flows to topic '{TOPIC}' "
          f"at {'MAX' if args.rate==0 else args.rate} msg/s")

    producer = make_producer()
    # convert to records once (fast); keep label + kill_chain_stage in the msg
    # so downstream (Phase 3) can compare predictions to ground truth.
    records = df.to_dict(orient="records")

    interval = 1.0 / args.rate if args.rate > 0 else 0.0
    sent = 0
    t0 = time.time()
    for rec in records:
        # JSON-serialize the flow; convert non-serializable types to str
        rec["_produced_at"] = time.time() * 1000.0  # for latency measurement
        payload = json.dumps(rec, default=str)
        producer.produce(TOPIC, value=payload.encode("utf-8"),
                         callback=delivery_report)
        sent += 1
        # poll to trigger delivery callbacks
        producer.poll(0)
        if sent % 10000 == 0:
            elapsed = time.time() - t0
            print(f"   sent {sent:,}/{n:,} ({sent/elapsed:.0f} msg/s actual)")
        if interval:
            time.sleep(interval)

    print("[producer] flushing remaining messages...")
    producer.flush(timeout=30)
    elapsed = time.time() - t0
    print(f"[done] sent {sent:,} flows in {elapsed:.1f}s "
          f"({sent/elapsed:.0f} msg/s average)")


if __name__ == "__main__":
    main()
