#!/usr/bin/env python3
"""Derive bounded server settings for the exact-delivery MQTT benchmark."""

from __future__ import annotations

import argparse


MOSQUITTO_MAX_QUEUED_MESSAGES = (1 << 31) - 1
DEFAULT_QUEUE_CAPACITY = 1_024


def queue_capacity(
    warmup_messages: int,
    measured_messages: int,
    configured_capacity: int | None = None,
) -> int:
    """Return a queue bound that cannot drop a complete benchmark phase."""
    if warmup_messages < 0 or measured_messages <= 0:
        raise ValueError("warmup must be non-negative and messages positive")
    required = max(
        DEFAULT_QUEUE_CAPACITY, warmup_messages, measured_messages
    )
    if required > MOSQUITTO_MAX_QUEUED_MESSAGES:
        raise ValueError("benchmark phase exceeds Mosquitto's queue limit")
    capacity = required if configured_capacity is None else configured_capacity
    if capacity <= 0 or capacity > MOSQUITTO_MAX_QUEUED_MESSAGES:
        raise ValueError("queue capacity must be between 1 and 2147483647")
    if capacity < required:
        raise ValueError(
            f"queue capacity {capacity} cannot preserve exact delivery for "
            f"the required {required}-message bound"
        )
    return capacity


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--messages", type=int, required=True)
    parser.add_argument("--capacity", type=int)
    args = parser.parse_args()
    try:
        capacity = queue_capacity(args.warmup, args.messages, args.capacity)
    except ValueError as error:
        parser.error(str(error))
    print(capacity)


if __name__ == "__main__":
    main()
