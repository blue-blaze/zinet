#!/usr/bin/env python3
"""Cross-implementation check for Zinet's protobuf codec.

Encodes messages with Google's Python `protobuf`, pipes them through
`zig-out/bin/protobuf_relay`, and parses what comes back with Python again. The
relay decodes each message and re-encodes it from the decoded value, so a field
the Zig side drops, widens or mis-tags comes back wrong rather than coming back
untouched.

`FileDescriptorProto` is used because Python's protobuf ships it pre-generated:
no `protoc`, no `.proto` file, and a message with nesting, repeated submessages,
strings and integers in it. The relay's schema deliberately declares only a
subset of its fields, so every run also checks that unknown fields are skipped
rather than refused.

Usage: python3 scripts/protobuf-interop.py [path-to-relay]
"""

import subprocess
import sys

from google.protobuf import descriptor_pb2


def varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def read_varint(data: bytes, pos: int):
    value = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated length prefix")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, pos
        shift += 7
        if shift > 63:
            raise ValueError("length prefix overflow")


def cases():
    """Messages worth sending, each for a stated reason."""
    # The empty message: proto3 leaves every default off the wire, so this is
    # zero bytes of body and must survive being zero bytes.
    yield "empty", descriptor_pb2.FileDescriptorProto()

    simple = descriptor_pb2.FileDescriptorProto(name="a.proto", package="pkg")
    yield "strings only", simple

    # Nesting: a file with a message with fields, which is three levels.
    nested = descriptor_pb2.FileDescriptorProto(name="nested.proto", package="deep.pkg")
    message = nested.message_type.add()
    message.name = "Outer"
    for index in range(1, 4):
        field = message.field.add()
        field.name = f"field_{index}"
        field.number = index
        field.json_name = f"field{index}"
        field.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32
    yield "nested with repeated fields", nested

    # Several submessages, so the repeated-message path is not exercised only at
    # length one — the count is what the decoder has to get right.
    many = descriptor_pb2.FileDescriptorProto(name="many.proto")
    for index in range(5):
        submessage = many.message_type.add()
        submessage.name = f"M{index}"
        field = submessage.field.add()
        field.name = "x"
        field.number = 1000 + index
    yield "five submessages", many

    # A field number near protobuf's maximum, which is where tag arithmetic goes
    # wrong if the shift is done in 32 bits.
    high = descriptor_pb2.FileDescriptorProto(name="high.proto")
    message = high.message_type.add()
    message.name = "High"
    field = message.field.add()
    field.name = "way_up_there"
    field.number = 536870911
    yield "field number at the maximum", high

    # Non-ASCII, because the length is in bytes and a codec that counted
    # characters would pass every ASCII test.
    unicode_case = descriptor_pb2.FileDescriptorProto(name="héllo-wörld.proto", package="ü")
    yield "non-ascii strings", unicode_case

    # Long enough that its length prefix needs two varint bytes, and long enough
    # to cross a 4 KiB pipe buffer.
    big = descriptor_pb2.FileDescriptorProto(name="big.proto")
    message = big.message_type.add()
    message.name = "Big"
    for index in range(200):
        field = message.field.add()
        field.name = f"f{index}" * 8
        field.number = index + 1
    yield "multi-kilobyte message", big


def compare(name, sent, got):
    """Only the fields the relay's schema declares survive the round trip."""
    problems = []
    if sent.name != got.name:
        problems.append(f"name: sent {sent.name!r}, got {got.name!r}")
    if sent.package != got.package:
        problems.append(f"package: sent {sent.package!r}, got {got.package!r}")
    if len(sent.message_type) != len(got.message_type):
        problems.append(
            f"message_type count: sent {len(sent.message_type)}, got {len(got.message_type)}"
        )
    else:
        for index, (a, b) in enumerate(zip(sent.message_type, got.message_type)):
            if a.name != b.name:
                problems.append(f"message_type[{index}].name: {a.name!r} vs {b.name!r}")
            if len(a.field) != len(b.field):
                problems.append(
                    f"message_type[{index}].field count: {len(a.field)} vs {len(b.field)}"
                )
                continue
            for field_index, (x, y) in enumerate(zip(a.field, b.field)):
                where = f"message_type[{index}].field[{field_index}]"
                if x.name != y.name:
                    problems.append(f"{where}.name: {x.name!r} vs {y.name!r}")
                if x.number != y.number:
                    problems.append(f"{where}.number: {x.number} vs {y.number}")
                if x.json_name != y.json_name:
                    problems.append(f"{where}.json_name: {x.json_name!r} vs {y.json_name!r}")
    return problems


def main():
    relay = sys.argv[1] if len(sys.argv) > 1 else "./zig-out/bin/protobuf_relay"

    names = []
    sent = []
    payload = bytearray()
    for name, message in cases():
        body = message.SerializeToString()
        payload += varint(len(body)) + body
        names.append(name)
        sent.append(message)

    result = subprocess.run(
        [relay], input=bytes(payload), capture_output=True, timeout=60
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode(errors="replace"))
        sys.exit(f"relay exited with {result.returncode}")

    data = result.stdout
    failures = 0
    pos = 0
    for index, (name, message) in enumerate(zip(names, sent)):
        try:
            length, pos = read_varint(data, pos)
        except ValueError as err:
            sys.exit(f"[{name}] reading the reply: {err}")
        if pos + length > len(data):
            sys.exit(f"[{name}] reply is truncated: wanted {length} bytes")
        body = data[pos : pos + length]
        pos += length

        got = descriptor_pb2.FileDescriptorProto()
        try:
            got.ParseFromString(body)
        except Exception as err:  # noqa: BLE001 - any parse failure is the result
            print(f"FAIL [{name}]: Python could not parse the reply: {err}")
            failures += 1
            continue

        problems = compare(name, message, got)
        if problems:
            failures += 1
            print(f"FAIL [{name}]:")
            for problem in problems:
                print(f"  {problem}")
        else:
            print(f"ok   [{name}] {length} bytes back")

    if pos != len(data):
        print(f"FAIL: {len(data) - pos} unread bytes after the last reply")
        failures += 1

    if failures:
        sys.exit(f"{failures} of {len(names)} cases failed")
    print(f"all {len(names)} cases round-tripped through Python's protobuf")


if __name__ == "__main__":
    main()
