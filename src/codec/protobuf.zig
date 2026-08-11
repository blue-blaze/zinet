//! Protocol Buffers: the wire format, a `comptime` mapping onto Zig structs, and
//! the varint-length framing that carries messages over a stream.
//!
//! Three layers, and the boundary between them is the point:
//!
//! 1. **The wire format** (this section) is pure functions over bytes: varints,
//!    tags, zigzag, and a field iterator. No allocation, no schema, nothing to
//!    configure but limits. It is the layer that can be checked byte for byte
//!    against another implementation.
//! 2. **The schema mapping** turns a Zig struct into encode/decode routines at
//!    compile time. Zig has no run-time reflection, so where Java asks a code
//!    generator for a class, this asks `@typeInfo` for the fields — which means
//!    no generator, no build step, and mistakes that are compile errors rather
//!    than silently unserialized fields.
//! 3. **The framing** is `Varint32FrameDecoder` and `Varint32Prepender`, the
//!    length-delimited stream convention Netty spells
//!    `ProtobufVarint32FrameDecoder`. A protobuf message is not self-delimiting,
//!    so something has to say how long it is.
//!
//! **Field numbers are declared, never inferred.** A struct opts in with a
//! `proto` declaration mapping each field to its number, and every field must
//! appear in it. Deriving numbers from declaration order would be shorter and
//! would also make reordering two fields a silent wire-format break, which is
//! the one thing protobuf exists to prevent.
//!
//! What is deliberately absent, each with its reason rather than left to be
//! discovered:
//!
//! | Not here | Why |
//! |---|---|
//! | Groups (wire types 3 and 4) | Deprecated in proto2 and never in proto3. Refused rather than skipped: a group's end tag is the only thing that bounds it, so "skip it" means implementing it. |
//! | `map<K, V>` | It is `repeated` of a two-field message on the wire (§ maps are not a wire type), so a `[]const struct { key: K, value: V }` already expresses it. A dedicated form would add API without adding capability. |
//! | `oneof` | Presence is `?T`, and which-of-many is the application's invariant. A tagged union would encode fine but decode into an ambiguity: two members present is legal on the wire. |
//! | Unknown-field retention | Unknown fields are skipped, and counted so the caller can see it happened. Retaining the original bytes for re-emission is a feature of a full runtime, not of a codec, and it needs an owner for those bytes. |
//! | `.proto` parsing and code generation | A compiler, not a network framework. The `comptime` mapping is what replaces it here. |
//! | proto2 `required`, explicit defaults | proto3 field presence is what this models. |

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const pipeline_mod = @import("../pipeline.zig");
const Pipeline = pipeline_mod.Pipeline;
const HandlerContext = pipeline_mod.HandlerContext;
const Message = @import("../message.zig").Message;
const Buffer = @import("../buffer.zig").Buffer;
const codec = @import("codec.zig");
const ByteToMessageDecoder = codec.ByteToMessageDecoder;

pub const Error = error{
    /// The bytes end mid-value. For a whole message this is corruption; for a
    /// stream decoder it means "ask me again with more".
    Truncated,
    /// More than ten bytes, or a tenth byte with bits above the 64th.
    VarintOverflow,
    /// Wire type 3 or 4 (groups), or 6 or 7 (never assigned).
    UnsupportedWireType,
    /// Field number zero, above 2^29-1, or in the 19000-19999 range the
    /// implementation reserves for itself.
    InvalidFieldNumber,
    /// A field's wire type cannot carry the declared Zig type.
    WireTypeMismatch,
    /// A length-delimited field, or the whole message, exceeds the stated limit.
    MessageTooLong,
    /// Nested messages deeper than the stated limit.
    NestingTooDeep,
    /// A repeated field has more elements than the stated limit.
    TooManyElements,
    /// A `bool`, `enum` or `packed` field held a value the Zig type cannot
    /// represent.
    InvalidValue,
};

/// Ten bytes: 64 bits at 7 bits each needs ten, and the tenth carries one bit.
pub const max_varint_len = 10;

/// A field number fits in 29 bits, because the tag that carries it is a varint
/// whose low three bits are the wire type.
pub const max_field_number: u32 = (1 << 29) - 1;

/// Numbers protobuf reserves for its own implementation details.
pub const reserved_field_numbers = struct {
    pub const first: u32 = 19000;
    pub const last: u32 = 19999;
};

/// Caps on what a peer can make a decoder do. Every one of these is a security
/// limit rather than a tuning knob: a length-delimited format lets a peer
/// announce any size it likes, and nesting lets it announce any depth.
pub const Limits = struct {
    /// Longest message, and longest length-delimited field inside one.
    max_message_len: usize = 4 * 1024 * 1024,
    /// How deeply nested messages may go. Decoding is iterative rather than
    /// recursive per field, but a nested struct is a nested call, so this bounds
    /// the stack as well as the work.
    max_nesting_depth: u8 = 32,
    /// Elements in one repeated field.
    max_elements: usize = 65536,

    pub fn assertValid(self: Limits) void {
        assert(self.max_message_len > 0);
        assert(self.max_nesting_depth > 0);
        assert(self.max_elements > 0);
    }
};

pub const WireType = enum(u3) {
    varint = 0,
    i64 = 1,
    len = 2,
    /// Deprecated group start. Present in the enum because it appears on the
    /// wire and has to be named to be refused.
    sgroup = 3,
    /// Deprecated group end.
    egroup = 4,
    i32 = 5,

    /// Whether this codec will carry a field of this type. Groups and the two
    /// unassigned values are not.
    pub fn isSupported(self: WireType) bool {
        return switch (self) {
            .varint, .i64, .len, .i32 => true,
            .sgroup, .egroup => false,
        };
    }
};

/// A decoded value and how many bytes it took, which is what lets a caller walk
/// a buffer without the decoder holding a cursor.
pub fn Decoded(comptime T: type) type {
    return struct { value: T, len: usize };
}

/// The number of bytes `encodeVarint` will write.
pub fn varintLen(value: u64) usize {
    var remaining = value;
    var len: usize = 1;
    while (remaining >= 0x80) : (len += 1) remaining >>= 7;
    return len;
}

/// Writes `value` as a base-128 varint. Asserts the room rather than returning
/// an error: every caller here computes the length first, and a short buffer is
/// a bug in this file rather than something a peer can cause.
pub fn encodeVarint(dest: []u8, value: u64) usize {
    assert(dest.len >= varintLen(value));
    var remaining = value;
    var len: usize = 0;
    while (remaining >= 0x80) {
        dest[len] = @intCast((remaining & 0x7f) | 0x80);
        remaining >>= 7;
        len += 1;
    }
    dest[len] = @intCast(remaining);
    return len + 1;
}

pub fn decodeVarint(bytes: []const u8) Error!Decoded(u64) {
    var value: u64 = 0;
    var index: usize = 0;
    while (index < bytes.len) {
        const byte = bytes[index];
        if (index == max_varint_len - 1) {
            // The tenth byte carries bit 63 and nothing else, so anything above
            // 1 is a value that does not fit — and the continuation bit here
            // would mean an eleventh byte, which does not exist.
            if (byte > 1) return error.VarintOverflow;
            value |= @as(u64, byte) << (7 * (max_varint_len - 1));
            return .{ .value = value, .len = index + 1 };
        }
        value |= @as(u64, byte & 0x7f) << @intCast(7 * index);
        index += 1;
        if (byte & 0x80 == 0) return .{ .value = value, .len = index };
    }
    return error.Truncated;
}

/// §Signed integers: zigzag maps small negatives onto small unsigned values, so
/// -1 costs one byte instead of ten.
pub fn zigzagEncode(comptime T: type, value: T) u64 {
    const bits = @typeInfo(T).int.bits;
    const wide: i64 = value;
    return @bitCast((wide << 1) ^ (wide >> (bits - 1)));
}

pub fn zigzagDecode(comptime T: type, value: u64) Error!T {
    const shifted: i64 = @bitCast(value >> 1);
    const sign: i64 = -@as(i64, @intCast(value & 1));
    const wide = shifted ^ sign;
    return std.math.cast(T, wide) orelse error.InvalidValue;
}

pub const Tag = struct {
    number: u32,
    wire: WireType,

    pub fn encodedLen(self: Tag) usize {
        return varintLen(self.raw());
    }

    pub fn raw(self: Tag) u64 {
        return (@as(u64, self.number) << 3) | @backingInt(self.wire);
    }
};

pub fn encodeTag(dest: []u8, tag: Tag) usize {
    return encodeVarint(dest, tag.raw());
}

pub fn decodeTag(bytes: []const u8) Error!Decoded(Tag) {
    const decoded = try decodeVarint(bytes);
    const raw = decoded.value;
    const number_wide = raw >> 3;
    if (number_wide == 0 or number_wide > max_field_number) return error.InvalidFieldNumber;
    const number: u32 = @intCast(number_wide);
    if (number >= reserved_field_numbers.first and number <= reserved_field_numbers.last) {
        return error.InvalidFieldNumber;
    }
    // 6 and 7 were never assigned, so they are refused by value rather than
    // being given names in `WireType`: `@enumFromInt` on an undefined value is a
    // panic, and a peer's three bits must not be able to cause one.
    const wire_raw: u3 = @truncate(raw);
    if (wire_raw > @backingInt(WireType.i32)) return error.UnsupportedWireType;
    const wire: WireType = @fromBackingInt(@intCast(wire_raw));
    if (!wire.isSupported()) return error.UnsupportedWireType;
    return .{ .value = .{ .number = number, .wire = wire }, .len = decoded.len };
}

/// One field as it appeared, with its payload borrowed from the input. Borrowed
/// rather than copied because the schema layer decides what needs to outlive the
/// buffer — the same split the rest of this framework draws between inbound
/// messages, which own an arena, and the parsing that fills it.
pub const Field = struct {
    number: u32,
    value: Value,

    pub const Value = union(enum) {
        varint: u64,
        i64: u64,
        i32: u32,
        len: []const u8,
    };

    pub fn wire(self: Field) WireType {
        return switch (self.value) {
            .varint => .varint,
            .i64 => .i64,
            .i32 => .i32,
            .len => .len,
        };
    }

    pub fn asU64(self: Field) Error!u64 {
        return switch (self.value) {
            .varint => |v| v,
            .i64 => |v| v,
            .i32 => |v| v,
            .len => error.WireTypeMismatch,
        };
    }

    pub fn asBool(self: Field) Error!bool {
        const raw = try self.asU64();
        // §Booleans are varints, and anything non-zero is true — but only a
        // varint field can hold one at all.
        if (self.value != .varint) return error.WireTypeMismatch;
        return raw != 0;
    }

    pub fn asBytes(self: Field) Error![]const u8 {
        return switch (self.value) {
            .len => |bytes| bytes,
            else => error.WireTypeMismatch,
        };
    }

    pub fn asF32(self: Field) Error!f32 {
        return switch (self.value) {
            .i32 => |v| @bitCast(v),
            else => error.WireTypeMismatch,
        };
    }

    pub fn asF64(self: Field) Error!f64 {
        return switch (self.value) {
            .i64 => |v| @bitCast(v),
            else => error.WireTypeMismatch,
        };
    }
};

/// Walks the fields of one message. Holds no allocation and no schema, so it is
/// also the tool for skipping a message whose shape is not known.
pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,
    limits: Limits = .{},

    pub fn init(bytes: []const u8, limits: Limits) Reader {
        limits.assertValid();
        return .{ .bytes = bytes, .limits = limits };
    }

    pub fn atEnd(self: *const Reader) bool {
        return self.pos >= self.bytes.len;
    }

    pub fn next(self: *Reader) Error!?Field {
        if (self.atEnd()) return null;
        const rest = self.bytes[self.pos..];
        const tag = try decodeTag(rest);
        var offset = tag.len;
        const value: Field.Value = switch (tag.value.wire) {
            .varint => blk: {
                const decoded = try decodeVarint(rest[offset..]);
                offset += decoded.len;
                break :blk .{ .varint = decoded.value };
            },
            .i64 => blk: {
                if (rest.len - offset < 8) return error.Truncated;
                const value = std.mem.readInt(u64, rest[offset..][0..8], .little);
                offset += 8;
                break :blk .{ .i64 = value };
            },
            .i32 => blk: {
                if (rest.len - offset < 4) return error.Truncated;
                const value = std.mem.readInt(u32, rest[offset..][0..4], .little);
                offset += 4;
                break :blk .{ .i32 = value };
            },
            .len => blk: {
                const decoded = try decodeVarint(rest[offset..]);
                offset += decoded.len;
                if (decoded.value > self.limits.max_message_len) return error.MessageTooLong;
                const length: usize = @intCast(decoded.value);
                if (rest.len - offset < length) return error.Truncated;
                const payload = rest[offset..][0..length];
                offset += length;
                break :blk .{ .len = payload };
            },
            // `decodeTag` refuses these, so reaching here would mean it stopped.
            .sgroup, .egroup => unreachable,
        };
        self.pos += offset;
        return .{ .number = tag.value.number, .value = value };
    }
};

// ── The schema mapping ───────────────────────────────────────────────────────

/// How a Zig type is carried on the wire. Zig cannot distinguish protobuf's
/// three encodings of a 32-bit signed integer — `int32`, `sint32` and
/// `sfixed32` are all `i32` — so where the choice matters it is declared.
///
/// `default` picks the encoding an unadorned Zig type implies, which is the
/// varint form for integers and bools, the fixed form for floats, and
/// length-delimited for slices of bytes and for nested structs.
pub const Kind = enum {
    default,
    /// Varint, two's complement. A negative `int32` costs ten bytes on the wire;
    /// that is protobuf's rule, not an oversight, and `sint32` is the fix.
    int,
    /// Varint, zigzag. What a field holding negatives should almost always use.
    sint,
    /// Fixed width, little endian: `fixed32`/`fixed64` for unsigned,
    /// `sfixed32`/`sfixed64` for signed.
    fixed,
};

/// A field's declared number, and its encoding when the Zig type leaves that
/// open.
pub const FieldSpec = struct {
    number: u32,
    kind: Kind = .default,
    /// Whether a `repeated` scalar goes out as one length-delimited run.
    ///
    /// Orthogonal to `kind` on purpose: a repeated zigzag field has to be able to
    /// say both things, and folding "packed" into the same enum made that
    /// inexpressible. Defaults to proto3's default. Decoding accepts both forms
    /// whatever this says, because the wire allows either.
    packed_scalars: bool = true,
};

/// Normalizes the two ways a `proto` declaration may name a field: a bare
/// number, or a struct with the number and a kind.
fn specOf(comptime declared: anytype) FieldSpec {
    const T = @TypeOf(declared);
    if (T == FieldSpec) return declared;
    return switch (@typeInfo(T)) {
        .int, .comptime_int => .{ .number = declared },
        .@"struct" => .{
            .number = declared.number,
            .kind = if (@hasField(T, "kind")) declared.kind else .default,
            .packed_scalars = if (@hasField(T, "packed_scalars")) declared.packed_scalars else true,
        },
        else => @compileError(
            "a `proto` entry must be a field number or `.{ .number = N, .kind = ... }`",
        ),
    };
}

/// The compile-time description of one struct field: where it lives in Zig and
/// how it goes on the wire.
const Plan = struct {
    name: []const u8,
    spec: FieldSpec,
    Type: type,
};

/// Reads a struct's `proto` declaration and checks it against the struct's own
/// fields, at compile time.
///
/// Every field must be declared. A struct that gains a field and forgets the
/// declaration is a compile error rather than a message that silently stops
/// carrying it — which is the failure mode that makes a hand-written codec worse
/// than a generated one, so it is the one worth making impossible.
fn planOf(comptime T: type) []const Plan {
    comptime {
        const info = switch (@typeInfo(T)) {
            .@"struct" => |s| s,
            else => @compileError(@typeName(T) ++ " is not a struct, so it has no fields to map"),
        };
        if (!@hasDecl(T, "proto")) @compileError(
            @typeName(T) ++ " needs a `pub const proto = .{ .field = number, ... }` declaration; " ++
                "field numbers are declared rather than inferred so that reordering fields " ++
                "cannot silently change the wire format",
        );
        const declared = T.proto;
        const declared_count = @typeInfo(@TypeOf(declared)).@"struct".field_names.len;

        var plans: [info.field_names.len]Plan = undefined;
        for (info.field_names, info.field_types, 0..) |name, FieldType, index| {
            if (!@hasField(@TypeOf(declared), name)) @compileError(
                @typeName(T) ++ "." ++ name ++ " has no entry in `proto`",
            );
            const spec = specOf(@field(declared, name));
            if (spec.number == 0 or spec.number > max_field_number) @compileError(
                @typeName(T) ++ "." ++ name ++ " has a field number outside 1..2^29-1",
            );
            if (spec.number >= reserved_field_numbers.first and
                spec.number <= reserved_field_numbers.last) @compileError(
                @typeName(T) ++ "." ++ name ++ " uses a number reserved by protobuf " ++
                    "(19000-19999)",
            );
            for (plans[0..index]) |earlier| {
                if (earlier.spec.number == spec.number) @compileError(
                    @typeName(T) ++ "." ++ name ++ " reuses field number " ++
                        std.fmt.comptimePrint("{d}", .{spec.number}) ++ " from " ++ earlier.name,
                );
            }
            plans[index] = .{ .name = name, .spec = spec, .Type = FieldType };
        }
        if (declared_count != info.field_names.len) @compileError(
            @typeName(T) ++ "'s `proto` declares entries that are not fields of it",
        );
        const frozen = plans;
        return &frozen;
    }
}

/// What a single (non-optional, non-repeated) Zig type becomes on the wire.
fn wireFor(comptime T: type, comptime kind: Kind) WireType {
    return switch (@typeInfo(T)) {
        .bool => .varint,
        .int => switch (kind) {
            .default, .int, .sint => .varint,
            .fixed => if (@typeInfo(T).int.bits == 64) .i64 else .i32,
        },
        .float => switch (@typeInfo(T).float.bits) {
            32 => .i32,
            64 => .i64,
            else => @compileError("protobuf has f32 and f64 and nothing else"),
        },
        .@"enum" => .varint,
        .@"struct" => .len,
        .pointer => .len,
        else => @compileError("no protobuf encoding for " ++ @typeName(T)),
    };
}

fn isScalarSlice(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => |p| p.size == .slice and p.child != u8 and switch (@typeInfo(p.child)) {
            .bool, .int, .float, .@"enum" => true,
            else => false,
        },
        else => false,
    };
}

fn isByteSlice(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => |p| p.size == .slice and p.child == u8,
        else => false,
    };
}

/// A `*const Message` field: one nested message, and the only way a message can
/// contain itself in Zig, since a struct cannot hold one by value.
fn isMessagePointer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => |p| p.size == .one and @typeInfo(p.child) == .@"struct",
        else => false,
    };
}

fn isMessageSlice(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => |p| p.size == .slice and switch (@typeInfo(p.child)) {
            .@"struct" => true,
            .pointer => isByteSlice(p.child),
            else => false,
        },
        else => false,
    };
}

// ── Encoding ─────────────────────────────────────────────────────────────────

/// Bytes `encode` will write for `value`. Computed rather than guessed because a
/// nested message's length precedes it, so the inner size has to be known before
/// the outer bytes can be laid down.
pub fn encodedLen(comptime T: type, value: *const T) usize {
    const plans = comptime planOf(T);
    var total: usize = 0;
    inline for (plans) |plan| {
        total += fieldLen(plan, @field(value, plan.name));
    }
    return total;
}

fn fieldLen(comptime plan: Plan, value: anytype) usize {
    const F = @TypeOf(value);
    if (comptime @typeInfo(F) == .optional) {
        // §Presence: an absent optional writes nothing at all, which is what
        // makes `?T` the way to say "explicitly unset" rather than "zero".
        const inner = value orelse return 0;
        return scalarOrMessageLen(plan, inner);
    }
    if (comptime isScalarSlice(F)) return repeatedScalarLen(plan, value);
    if (comptime isMessageSlice(F)) {
        var total: usize = 0;
        for (value) |element| total += scalarOrMessageLen(plan, element);
        return total;
    }
    if (comptime isByteSlice(F)) {
        // proto3 omits a scalar equal to its default, which for bytes is empty.
        if (value.len == 0) return 0;
        return scalarOrMessageLen(plan, value);
    }
    if (isDefaultValued(F, value)) return 0;
    return scalarOrMessageLen(plan, value);
}

/// proto3 leaves a scalar at its default value off the wire entirely; a decoder
/// reading no field and a decoder reading zero must reach the same result. That
/// is why the round-trip tests can compare structs rather than bytes.
fn isDefaultValued(comptime F: type, value: F) bool {
    return switch (@typeInfo(F)) {
        .bool => value == false,
        .int => value == 0,
        .float => value == 0.0,
        .@"enum" => @backingInt(value) == 0,
        // A nested message is present or absent, never "default": use `?T` to
        // say absent. Writing an empty one is meaningful (proto3 distinguishes
        // an empty submessage from a missing one).
        .@"struct" => false,
        else => false,
    };
}

fn scalarOrMessageLen(comptime plan: Plan, value: anytype) usize {
    const F = @TypeOf(value);
    const tag: Tag = .{ .number = plan.spec.number, .wire = wireFor(F, plan.spec.kind) };
    const header = tag.encodedLen();
    return switch (@typeInfo(F)) {
        .bool => header + 1,
        .int => header + switch (plan.spec.kind) {
            .fixed => @divExact(@typeInfo(F).int.bits, 8),
            .sint => varintLen(zigzagEncode(F, value)),
            else => varintLen(twosComplement(value)),
        },
        .float => header + @divExact(@typeInfo(F).float.bits, 8),
        .@"enum" => header + varintLen(twosComplement(@backingInt(value))),
        .@"struct" => blk: {
            const inner = encodedLen(F, &value);
            break :blk header + varintLen(inner) + inner;
        },
        .pointer => blk: {
            if (comptime isMessagePointer(F)) {
                const inner = encodedLen(@typeInfo(F).pointer.child, value);
                break :blk header + varintLen(inner) + inner;
            }
            break :blk header + varintLen(value.len) + value.len;
        },
        else => @compileError("no protobuf encoding for " ++ @typeName(F)),
    };
}

/// A signed varint is its 64-bit two's complement, which is why a negative
/// `int32` costs ten bytes.
fn twosComplement(value: anytype) u64 {
    const F = @TypeOf(value);
    if (@typeInfo(F).int.signedness == .unsigned) return value;
    const wide: i64 = value;
    return @bitCast(wide);
}

fn repeatedScalarLen(comptime plan: Plan, value: anytype) usize {
    if (value.len == 0) return 0;
    const Child = @typeInfo(@TypeOf(value)).pointer.child;
    var payload: usize = 0;
    for (value) |element| payload += scalarPayloadLen(plan, Child, element);
    if (!plan.spec.packed_scalars) {
        const tag: Tag = .{ .number = plan.spec.number, .wire = wireFor(Child, plan.spec.kind) };
        return (tag.encodedLen() * value.len) + payload;
    }
    const tag: Tag = .{ .number = plan.spec.number, .wire = .len };
    return tag.encodedLen() + varintLen(payload) + payload;
}

fn scalarPayloadLen(comptime plan: Plan, comptime Child: type, element: Child) usize {
    return switch (@typeInfo(Child)) {
        .bool => 1,
        .int => switch (plan.spec.kind) {
            .fixed => @divExact(@typeInfo(Child).int.bits, 8),
            .sint => varintLen(zigzagEncode(Child, element)),
            else => varintLen(twosComplement(element)),
        },
        .float => @divExact(@typeInfo(Child).float.bits, 8),
        .@"enum" => varintLen(twosComplement(@backingInt(element))),
        else => @compileError("no packed encoding for " ++ @typeName(Child)),
    };
}

/// Writes `value` into `dest`, which must be at least `encodedLen` long.
///
/// Fields go out in declaration order. The wire format permits any order, and
/// nothing here depends on it, but a stable order is what makes an encoder's
/// output comparable byte for byte against another implementation's.
pub fn encode(comptime T: type, dest: []u8, value: *const T) usize {
    assert(dest.len >= encodedLen(T, value));
    const plans = comptime planOf(T);
    var len: usize = 0;
    inline for (plans) |plan| {
        len += writeField(plan, dest[len..], @field(value, plan.name));
    }
    return len;
}

fn writeField(comptime plan: Plan, dest: []u8, value: anytype) usize {
    const F = @TypeOf(value);
    if (comptime @typeInfo(F) == .optional) {
        const inner = value orelse return 0;
        return writeOne(plan, dest, inner);
    }
    if (comptime isScalarSlice(F)) return writeRepeatedScalar(plan, dest, value);
    if (comptime isMessageSlice(F)) {
        var len: usize = 0;
        for (value) |element| len += writeOne(plan, dest[len..], element);
        return len;
    }
    if (comptime isByteSlice(F)) {
        if (value.len == 0) return 0;
        return writeOne(plan, dest, value);
    }
    if (comptime isRepeated(F) or isByteSlice(F)) unreachable;
    if (isDefaultValued(F, value)) return 0;
    return writeOne(plan, dest, value);
}

fn writeOne(comptime plan: Plan, dest: []u8, value: anytype) usize {
    const F = @TypeOf(value);
    const tag: Tag = .{ .number = plan.spec.number, .wire = wireFor(F, plan.spec.kind) };
    var len = encodeTag(dest, tag);
    switch (@typeInfo(F)) {
        .bool => {
            dest[len] = @intFromBool(value);
            len += 1;
        },
        .int => len += writeScalar(plan, F, dest[len..], value),
        .float => len += writeScalar(plan, F, dest[len..], value),
        .@"enum" => len += encodeVarint(dest[len..], twosComplement(@backingInt(value))),
        .@"struct" => {
            const inner = encodedLen(F, &value);
            len += encodeVarint(dest[len..], inner);
            len += encode(F, dest[len..], &value);
        },
        .pointer => {
            if (comptime isMessagePointer(F)) {
                const Child = @typeInfo(F).pointer.child;
                const inner = encodedLen(Child, value);
                len += encodeVarint(dest[len..], inner);
                len += encode(Child, dest[len..], value);
            } else {
                len += encodeVarint(dest[len..], value.len);
                @memcpy(dest[len..][0..value.len], value);
                len += value.len;
            }
        },
        else => @compileError("no protobuf encoding for " ++ @typeName(F)),
    }
    return len;
}

fn writeScalar(comptime plan: Plan, comptime F: type, dest: []u8, value: F) usize {
    switch (@typeInfo(F)) {
        .int => {
            if (plan.spec.kind == .fixed) {
                // protobuf has exactly two fixed widths, so the two cases are
                // written out rather than derived: `fixed32`/`sfixed32` and
                // `fixed64`/`sfixed64`.
                return switch (@typeInfo(F).int.bits) {
                    32 => blk: {
                        std.mem.writeInt(u32, dest[0..4], @bitCast(value), .little);
                        break :blk 4;
                    },
                    64 => blk: {
                        std.mem.writeInt(u64, dest[0..8], @bitCast(value), .little);
                        break :blk 8;
                    },
                    else => @compileError("a fixed field must be 32 or 64 bits wide"),
                };
            }
            if (plan.spec.kind == .sint) return encodeVarint(dest, zigzagEncode(F, value));
            return encodeVarint(dest, twosComplement(value));
        },
        .float => return switch (@typeInfo(F).float.bits) {
            32 => blk: {
                std.mem.writeInt(u32, dest[0..4], @bitCast(value), .little);
                break :blk 4;
            },
            64 => blk: {
                std.mem.writeInt(u64, dest[0..8], @bitCast(value), .little);
                break :blk 8;
            },
            else => @compileError("protobuf has f32 and f64 and nothing else"),
        },
        .bool => {
            dest[0] = @intFromBool(value);
            return 1;
        },
        .@"enum" => return encodeVarint(dest, twosComplement(@backingInt(value))),
        else => @compileError("no scalar encoding for " ++ @typeName(F)),
    }
}

fn writeRepeatedScalar(comptime plan: Plan, dest: []u8, value: anytype) usize {
    if (value.len == 0) return 0;
    const Child = @typeInfo(@TypeOf(value)).pointer.child;
    if (!plan.spec.packed_scalars) {
        var len: usize = 0;
        for (value) |element| {
            const tag: Tag = .{ .number = plan.spec.number, .wire = wireFor(Child, plan.spec.kind) };
            len += encodeTag(dest[len..], tag);
            len += writeScalar(plan, Child, dest[len..], element);
        }
        return len;
    }
    var payload: usize = 0;
    for (value) |element| payload += scalarPayloadLen(plan, Child, element);
    const tag: Tag = .{ .number = plan.spec.number, .wire = .len };
    var len = encodeTag(dest, tag);
    len += encodeVarint(dest[len..], payload);
    for (value) |element| len += writeScalar(plan, Child, dest[len..], element);
    return len;
}

// ── Decoding ─────────────────────────────────────────────────────────────────

/// A decoded message and the arena its strings and slices live in.
///
/// Inbound messages own an arena here for the same reason `http.Request` does:
/// nothing else is around to keep their contents alive. The alternative — slices
/// borrowed from the input buffer — would make the lifetime of a decoded message
/// the lifetime of the bytes it came from, which no handler can rely on.
pub fn Owned(comptime T: type) type {
    return struct {
        value: T,
        arena: std.heap.ArenaAllocator,

        /// Takes the allocator every `Message` payload is destroyed with and
        /// ignores it: the arena already holds the one it was created from. The
        /// signature is what `Message` requires, and taking it is what makes a
        /// dropped message release the arena instead of leaking it.
        pub fn deinit(self: *@This(), _: Allocator) void {
            self.arena.deinit();
        }
    };
}

/// Decodes a whole message, allocating its contents in a fresh arena.
pub fn decode(comptime T: type, gpa: Allocator, bytes: []const u8, limits: Limits) !Owned(T) {
    limits.assertValid();
    if (bytes.len > limits.max_message_len) return error.MessageTooLong;
    var owned: Owned(T) = .{ .value = undefined, .arena = .init(gpa) };
    errdefer owned.arena.deinit();
    owned.value = try decodeInto(T, owned.arena.allocator(), bytes, limits, 0);
    return owned;
}

/// Decodes into an arena the caller owns, which is what nested messages and the
/// pipeline handler both need.
///
/// Two passes over the bytes, which is the interesting decision here. A repeated
/// field's elements are scattered through the message and may arrive in either
/// the packed or the unpacked form, so the count is not known until the whole
/// message has been walked. Counting first and allocating once beats growing a
/// list per field: one allocation of the exact size, no reallocation a peer can
/// provoke, and the element limit is checked before any memory is taken rather
/// than after each append.
pub fn decodeInto(
    comptime T: type,
    arena: Allocator,
    bytes: []const u8,
    limits: Limits,
    depth: u8,
) !T {
    if (depth >= limits.max_nesting_depth) return error.NestingTooDeep;
    const plans = comptime planOf(T);

    // Start from the struct's own defaults, which is how a field absent from the
    // wire reaches proto3's default value without a second table saying what
    // those values are.
    var result: T = .{};

    inline for (plans) |plan| {
        if (comptime isRepeated(plan.Type)) {
            const count = try countElements(plan, bytes, limits);
            if (count > limits.max_elements) return error.TooManyElements;
            const Child = @typeInfo(plan.Type).pointer.child;
            if (count > 0) @field(result, plan.name) = try arena.alloc(Child, count);
        }
    }

    var filled: [plans.len]usize = @splat(0);
    var reader: Reader = .init(bytes, limits);
    while (try reader.next()) |field| {
        // Unknown fields are skipped, which is what makes a decoder built from an
        // older schema keep working. `Reader` has already measured the field, so
        // skipping is not a special case here — it is simply not matching.
        inline for (plans, 0..) |plan, index| {
            if (field.number == plan.spec.number) {
                try readField(plan, T, &result, &filled[index], field, arena, limits, depth);
            }
        }
    }
    return result;
}

fn isRepeated(comptime T: type) bool {
    return isScalarSlice(T) or isMessageSlice(T);
}

/// How many elements a repeated field will hold, counting both wire forms and
/// without allocating anything.
fn countElements(comptime plan: Plan, bytes: []const u8, limits: Limits) Error!usize {
    const Child = @typeInfo(plan.Type).pointer.child;
    var count: usize = 0;
    var reader: Reader = .init(bytes, limits);
    while (try reader.next()) |field| {
        if (field.number != plan.spec.number) continue;
        if (comptime isScalarSlice(plan.Type)) {
            switch (field.value) {
                // A length-delimited run of a scalar field is the packed form,
                // whatever the schema asked for: §the two encodings are
                // interchangeable on the wire, and a decoder that refused one
                // could not talk to a proto2 encoder.
                .len => |payload| {
                    var pos: usize = 0;
                    while (pos < payload.len) {
                        const read = try readPackedElement(plan, Child, payload[pos..]);
                        pos += read.len;
                        count += 1;
                        if (count > limits.max_elements) return error.TooManyElements;
                    }
                },
                else => count += 1,
            }
        } else {
            count += 1;
        }
        if (count > limits.max_elements) return error.TooManyElements;
    }
    return count;
}

fn readField(
    comptime plan: Plan,
    comptime T: type,
    result: *T,
    filled: *usize,
    field: Field,
    arena: Allocator,
    limits: Limits,
    depth: u8,
) !void {
    const F = plan.Type;
    if (comptime isScalarSlice(F)) {
        const Child = @typeInfo(F).pointer.child;
        const slot = @field(result, plan.name);
        switch (field.value) {
            .len => |payload| {
                var pos: usize = 0;
                while (pos < payload.len) {
                    const read = try readPackedElement(plan, Child, payload[pos..]);
                    // The counting pass sized this, so an overrun would mean the
                    // two passes disagreed about the same bytes.
                    assert(filled.* < slot.len);
                    @constCast(slot)[filled.*] = read.value;
                    filled.* += 1;
                    pos += read.len;
                }
            },
            else => {
                assert(filled.* < slot.len);
                @constCast(slot)[filled.*] = try scalarFromField(plan, Child, field);
                filled.* += 1;
            },
        }
        return;
    }
    if (comptime isMessageSlice(F)) {
        const Child = @typeInfo(F).pointer.child;
        const slot = @field(result, plan.name);
        assert(filled.* < slot.len);
        const payload = try field.asBytes();
        @constCast(slot)[filled.*] = if (comptime isByteSlice(Child))
            try arena.dupe(u8, payload)
        else
            try decodeInto(Child, arena, payload, limits, depth + 1);
        filled.* += 1;
        return;
    }
    if (comptime @typeInfo(F) == .optional) {
        const Child = @typeInfo(F).optional.child;
        @field(result, plan.name) = try readSingle(plan, Child, field, arena, limits, depth);
        return;
    }
    // §The last one wins: a message with the same non-repeated field twice takes
    // the later value, which is what makes concatenating two messages a merge.
    @field(result, plan.name) = try readSingle(plan, F, field, arena, limits, depth);
}

fn readSingle(
    comptime plan: Plan,
    comptime F: type,
    field: Field,
    arena: Allocator,
    limits: Limits,
    depth: u8,
) !F {
    return switch (@typeInfo(F)) {
        .bool, .int, .float, .@"enum" => try scalarFromField(plan, F, field),
        .@"struct" => try decodeInto(F, arena, try field.asBytes(), limits, depth + 1),
        .pointer => blk: {
            if (comptime isMessagePointer(F)) {
                const Child = @typeInfo(F).pointer.child;
                const created = try arena.create(Child);
                created.* = try decodeInto(Child, arena, try field.asBytes(), limits, depth + 1);
                break :blk created;
            }
            if (comptime !isByteSlice(F)) @compileError(
                "no protobuf decoding for " ++ @typeName(F),
            );
            break :blk try arena.dupe(u8, try field.asBytes());
        },
        else => @compileError("no protobuf decoding for " ++ @typeName(F)),
    };
}

fn scalarFromField(comptime plan: Plan, comptime F: type, field: Field) Error!F {
    // The wire type has to be able to carry the declared type. A `fixed32` field
    // arriving as a varint is a schema disagreement, not something to coerce:
    // guessing would turn a mismatch into a wrong value.
    const expected = wireFor(F, plan.spec.kind);
    if (field.wire() != expected) return error.WireTypeMismatch;
    return switch (@typeInfo(F)) {
        .bool => try field.asBool(),
        .int => switch (plan.spec.kind) {
            .sint => try zigzagDecode(F, try field.asU64()),
            else => fromTwosComplement(F, try field.asU64()),
        },
        .float => switch (@typeInfo(F).float.bits) {
            32 => try field.asF32(),
            64 => try field.asF64(),
            else => @compileError("protobuf has f32 and f64 and nothing else"),
        },
        .@"enum" => blk: {
            const raw = fromTwosComplement(i64, try field.asU64()) catch return error.InvalidValue;
            const Int = @typeInfo(F).@"enum".tag_type;
            const narrowed = std.math.cast(Int, raw) orelse return error.InvalidValue;
            // An unrecognized enum value is a real protobuf case — a peer built
            // from a newer schema — but a Zig enum cannot hold one, so it is
            // reported rather than coerced. A field that must survive unknown
            // values should be declared as its integer type.
            break :blk std.enums.fromInt(F, narrowed) orelse error.InvalidValue;
        },
        else => @compileError("no scalar decoding for " ++ @typeName(F)),
    };
}

fn fromTwosComplement(comptime F: type, raw: u64) Error!F {
    if (@typeInfo(F).int.signedness == .unsigned) {
        return std.math.cast(F, raw) orelse error.InvalidValue;
    }
    const wide: i64 = @bitCast(raw);
    return std.math.cast(F, wide) orelse error.InvalidValue;
}

fn readPackedElement(
    comptime plan: Plan,
    comptime Child: type,
    bytes: []const u8,
) Error!Decoded(Child) {
    return switch (@typeInfo(Child)) {
        .bool => blk: {
            const decoded = try decodeVarint(bytes);
            break :blk .{ .value = decoded.value != 0, .len = decoded.len };
        },
        .int => switch (plan.spec.kind) {
            .fixed => switch (@typeInfo(Child).int.bits) {
                32 => blk: {
                    if (bytes.len < 4) return error.Truncated;
                    break :blk .{
                        .value = @bitCast(std.mem.readInt(u32, bytes[0..4], .little)),
                        .len = 4,
                    };
                },
                64 => blk: {
                    if (bytes.len < 8) return error.Truncated;
                    break :blk .{
                        .value = @bitCast(std.mem.readInt(u64, bytes[0..8], .little)),
                        .len = 8,
                    };
                },
                else => @compileError("a fixed field must be 32 or 64 bits wide"),
            },
            .sint => blk: {
                const decoded = try decodeVarint(bytes);
                break :blk .{ .value = try zigzagDecode(Child, decoded.value), .len = decoded.len };
            },
            else => blk: {
                const decoded = try decodeVarint(bytes);
                break :blk .{
                    .value = try fromTwosComplement(Child, decoded.value),
                    .len = decoded.len,
                };
            },
        },
        .float => switch (@typeInfo(Child).float.bits) {
            32 => blk: {
                if (bytes.len < 4) return error.Truncated;
                break :blk .{
                    .value = @bitCast(std.mem.readInt(u32, bytes[0..4], .little)),
                    .len = 4,
                };
            },
            64 => blk: {
                if (bytes.len < 8) return error.Truncated;
                break :blk .{
                    .value = @bitCast(std.mem.readInt(u64, bytes[0..8], .little)),
                    .len = 8,
                };
            },
            else => @compileError("protobuf has f32 and f64 and nothing else"),
        },
        .@"enum" => blk: {
            const decoded = try decodeVarint(bytes);
            const raw = try fromTwosComplement(i64, decoded.value);
            const Int = @typeInfo(Child).@"enum".tag_type;
            const narrowed = std.math.cast(Int, raw) orelse return error.InvalidValue;
            break :blk .{
                .value = std.enums.fromInt(Child, narrowed) orelse return error.InvalidValue,
                .len = decoded.len,
            };
        },
        else => @compileError("no packed decoding for " ++ @typeName(Child)),
    };
}

// ── Framing and handlers ─────────────────────────────────────────────────────

/// The most bytes a length prefix takes: a 32-bit length is five varint bytes.
pub const max_length_prefix_len = 5;

/// Splits a stream into messages by the varint length that precedes each one.
///
/// A protobuf message is not self-delimiting — it ends where its bytes end — so
/// a stream needs a convention, and this is the one everybody uses. Netty spells
/// it `ProtobufVarint32FrameDecoder`.
///
/// The prefix itself can be split across reads, which is the case worth stating:
/// a decoder that assumed the length arrived whole would work in every test
/// written by hand and fail against a peer that flushed mid-prefix. Returning
/// null until the whole prefix *and* its payload are present is what makes the
/// chunk-independence property hold, and that property is asserted by the fuzz
/// target rather than only reasoned about.
pub const Varint32FrameDecoder = struct {
    decoder: ByteToMessageDecoder(Varint32FrameDecoder),
    options: Options,

    pub const handler_name = "protobuf-varint32-frame-decoder";

    pub const Options = struct {
        /// Longest message that will be delivered, prefix excluded. A larger one
        /// is `error.FrameTooLong`: with a length-delimited stream there is no
        /// way to find the next boundary after refusing one, so the connection
        /// cannot continue and the error says so rather than resynchronizing on a
        /// guess.
        max_frame_length: usize = 4 * 1024 * 1024,
    };

    pub fn init(options: Options) Varint32FrameDecoder {
        assert(options.max_frame_length > 0);
        return .{
            // The prefix has to fit alongside the largest frame, or a legal
            // message could never accumulate.
            .decoder = .{ .options = .{
                .max_cumulation = options.max_frame_length + max_length_prefix_len,
            } },
            .options = options,
        };
    }

    pub fn addTo(pipeline: *Pipeline, options: Options) !*Varint32FrameDecoder {
        const decoder = try pipeline.gpa.create(Varint32FrameDecoder);
        decoder.* = .init(options);
        errdefer pipeline.gpa.destroy(decoder);
        _ = try pipeline.addLast(handler_name, .initOwned(decoder));
        return decoder;
    }

    pub fn deinit(self: *Varint32FrameDecoder, gpa: Allocator) void {
        self.decoder.deinit(gpa);
    }

    pub fn onRead(self: *Varint32FrameDecoder, ctx: *HandlerContext, msg: Message) codec.Error!void {
        return self.decoder.onRead(self, ctx, msg);
    }

    pub fn onInactive(self: *Varint32FrameDecoder, ctx: *HandlerContext) codec.Error!void {
        return self.decoder.onInactive(self, ctx);
    }

    pub fn decode(
        self: *Varint32FrameDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) codec.Error!?Message {
        const readable = cumulation.readableSlice();
        const prefix = decodeVarint(readable) catch |err| switch (err) {
            // Not all of the prefix is here yet. Consuming nothing and asking for
            // more is the whole contract of this method.
            error.Truncated => return null,
            error.VarintOverflow => return error.FrameTooLong,
            else => return error.ProtocolViolation,
        };
        if (prefix.value > self.options.max_frame_length) return error.FrameTooLong;
        const length: usize = @intCast(prefix.value);
        if (readable.len - prefix.len < length) return null;

        cumulation.skip(prefix.len) catch return error.ProtocolViolation;
        const payload = cumulation.readBytes(length) catch return error.ProtocolViolation;
        // Copied, because an inbound message must outlive the read that produced
        // it and `cumulation` is reused by the next one.
        return try Message.initBytes(ctx.gpa(), payload);
    }
};

/// Writes each outbound message's length as a varint in front of it, the encoder
/// half of `Varint32FrameDecoder`. Netty calls it
/// `ProtobufVarint32LengthFieldPrepender`.
pub const Varint32Prepender = struct {
    pub const handler_name = "protobuf-varint32-prepender";

    pub fn addTo(pipeline: *Pipeline) !void {
        _ = try pipeline.addLast(handler_name, .init(&singleton));
    }

    var singleton: Varint32Prepender = .{};

    pub fn onWrite(_: *Varint32Prepender, ctx: *HandlerContext, msg: Message) codec.Error!void {
        var owned = msg;
        const bytes = owned.bytes() orelse {
            // Some other message type reached here, which means the pipeline is
            // missing the encoder that would have turned it into bytes.
            owned.deinit(ctx.gpa());
            return error.UnsupportedMessage;
        };
        var prefix: [max_length_prefix_len]u8 = undefined;
        const prefix_len = encodeVarint(&prefix, bytes.len);

        var framed: Buffer = try .init(ctx.gpa(), .{ .capacity = prefix_len + bytes.len });
        errdefer framed.deinit(ctx.gpa());
        const dest = try framed.reserve(ctx.gpa(), prefix_len + bytes.len);
        @memcpy(dest[0..prefix_len], prefix[0..prefix_len]);
        @memcpy(dest[prefix_len..][0..bytes.len], bytes);
        owned.deinit(ctx.gpa());
        return ctx.write(.initBuffer(&framed));
    }
};

/// Decodes each framed message into a `T`, for a pipeline that already has
/// framing in front of it.
///
/// One handler per message type, because the type is what says how to decode —
/// this is where Zig's `comptime` stands in for Java's generated class. A
/// pipeline carrying more than one message type needs a dispatch of its own,
/// which is the application's business rather than the codec's.
pub fn Decoder(comptime T: type) type {
    return struct {
        const Self = @This();

        limits: Limits = .{},

        pub const handler_name = "protobuf-decoder";
        pub const Decoded = Owned(T);

        pub fn addTo(pipeline: *Pipeline, limits: Limits) !*Self {
            limits.assertValid();
            const decoder = try pipeline.gpa.create(Self);
            decoder.* = .{ .limits = limits };
            errdefer pipeline.gpa.destroy(decoder);
            _ = try pipeline.addLast(handler_name, .initOwned(decoder));
            return decoder;
        }

        pub fn onRead(self: *Self, ctx: *HandlerContext, msg: Message) codec.Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            const bytes = owned.bytes() orelse return error.UnsupportedMessage;

            const decoded = decode(T, ctx.gpa(), bytes, self.limits) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // Everything else is the peer's bytes being wrong, which is a
                // protocol violation rather than a failure of this handler.
                else => return error.ProtocolViolation,
            };
            var holder = decoded;
            errdefer holder.deinit(ctx.gpa());
            // The arena travels with the message, which is what makes the decoded
            // strings outlive this callback: whoever consumes the message owns the
            // arena and releases it with `deinit`.
            ctx.fireRead(try Message.initAny(ctx.gpa(), Owned(T), holder));
        }
    };
}

/// Encodes each outbound `T` into bytes. Pair it with `Varint32Prepender` when
/// the stream needs framing, which it does unless something else delimits.
pub fn Encoder(comptime T: type) type {
    return struct {
        const Self = @This();

        pub const handler_name = "protobuf-encoder";

        pub fn addTo(pipeline: *Pipeline) !void {
            const encoder = try pipeline.gpa.create(Self);
            encoder.* = .{};
            errdefer pipeline.gpa.destroy(encoder);
            _ = try pipeline.addLast(handler_name, .initOwned(encoder));
        }

        pub fn onWrite(_: *Self, ctx: *HandlerContext, msg: Message) codec.Error!void {
            var owned = msg;
            const value = owned.get(T) orelse {
                owned.deinit(ctx.gpa());
                return error.UnsupportedMessage;
            };
            const len = encodedLen(T, value);
            var buffer: Buffer = try .init(ctx.gpa(), .{ .capacity = len });
            errdefer buffer.deinit(ctx.gpa());
            const dest = try buffer.reserve(ctx.gpa(), len);
            const written = encode(T, dest, value);
            assert(written == len);
            owned.deinit(ctx.gpa());
            return ctx.write(.initBuffer(&buffer));
        }
    };
}

// ── Tests: against another implementation ────────────────────────────────────
//
// Every byte string below was produced by Google's own Python `protobuf`, either
// through a message type it ships pre-generated — `Timestamp`,
// `FileDescriptorProto`, the `wrappers` — or through its low-level encoder for
// the encodings no shipped message happens to use. Checking against them is the
// same standard the rest of this repository holds itself to: HPACK against RFC
// 7541's appendix, the TLS key schedule against RFC 8448, QUIC's packet
// protection against RFC 9001. A codec verified only against its own encoder has
// tested that it is self-consistent, which is not the claim anybody needs.
//
// The generating commands are in the comments so the vectors can be regenerated
// rather than trusted.

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var expected: [256]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqualSlices(u8, decoded, actual);
}

/// `google.protobuf.Int32Value`, whose single field is an `int32`.
const Int32Value = struct {
    value: i32 = 0,
    pub const proto = .{ .value = 1 };
};

/// `google.protobuf.StringValue`.
const StringValue = struct {
    value: []const u8 = "",
    pub const proto = .{ .value = 1 };
};

/// `google.protobuf.DoubleValue`.
const DoubleValue = struct {
    value: f64 = 0,
    pub const proto = .{ .value = 1 };
};

test "protobuf interop: Python's wrappers, both directions" {
    // python3 -c "from google.protobuf import wrappers_pb2; \
    //   print(wrappers_pb2.Int32Value(value=-1).SerializeToString().hex())"
    const gpa = testing.allocator;

    // A negative int32 is ten bytes of two's complement. This is the vector worth
    // having most: it is the rule a hand-written encoder gets wrong by treating
    // the field as 32 bits wide.
    const negative_one = "08ffffffffffffffffff01";
    var buf: [64]u8 = undefined;
    const value: Int32Value = .{ .value = -1 };
    try expectHex(negative_one, buf[0..encode(Int32Value, &buf, &value)]);

    var expected: [64]u8 = undefined;
    var decoded = try decode(
        Int32Value,
        gpa,
        try std.fmt.hexToBytes(&expected, negative_one),
        .{},
    );
    defer decoded.deinit(gpa);
    try testing.expectEqual(@as(i32, -1), decoded.value.value);

    // StringValue(value="héllo"): UTF-8, and length in bytes rather than
    // characters.
    const string_hex = "0a0668c3a96c6c6f";
    const string_value: StringValue = .{ .value = "héllo" };
    try expectHex(string_hex, buf[0..encode(StringValue, &buf, &string_value)]);

    // DoubleValue(value=-2.25): fixed64, little endian.
    const double_hex = "0900000000000002c0";
    const double_value: DoubleValue = .{ .value = -2.25 };
    try expectHex(double_hex, buf[0..encode(DoubleValue, &buf, &double_value)]);

    var double_bytes: [64]u8 = undefined;
    var double_decoded = try decode(
        DoubleValue,
        gpa,
        try std.fmt.hexToBytes(&double_bytes, double_hex),
        .{},
    );
    defer double_decoded.deinit(gpa);
    try testing.expectEqual(@as(f64, -2.25), double_decoded.value.value);
}

/// `google.protobuf.Timestamp`, a message every gRPC deployment carries.
const Timestamp = struct {
    seconds: i64 = 0,
    nanos: i32 = 0,
    pub const proto = .{ .seconds = 1, .nanos = 2 };
};

test "protobuf interop: Python's Timestamp, both directions" {
    // python3 -c "from google.protobuf import timestamp_pb2; \
    //   print(timestamp_pb2.Timestamp(seconds=1700000000, nanos=123456789) \
    //     .SerializeToString().hex())"
    const gpa = testing.allocator;
    const hex = "0880e2cfaa0610959aef3a";
    const value: Timestamp = .{ .seconds = 1700000000, .nanos = 123456789 };

    var buf: [64]u8 = undefined;
    try expectHex(hex, buf[0..encode(Timestamp, &buf, &value)]);

    var bytes: [64]u8 = undefined;
    var decoded = try decode(Timestamp, gpa, try std.fmt.hexToBytes(&bytes, hex), .{});
    defer decoded.deinit(gpa);
    try testing.expectEqual(value.seconds, decoded.value.seconds);
    try testing.expectEqual(value.nanos, decoded.value.nanos);
}

const Sints = struct {
    thirty_two: i32 = 0,
    sixty_four: i64 = 0,
    pub const proto = .{
        .thirty_two = .{ .number = 1, .kind = .sint },
        .sixty_four = .{ .number = 2, .kind = .sint },
    };
};

const Packed = struct {
    numbers: []const i32 = &.{},
    pub const proto = .{ .numbers = 1 };
};

const Unpacked = struct {
    numbers: []const i32 = &.{},
    pub const proto = .{ .numbers = .{ .number = 1, .packed_scalars = false } };
};

const Fixeds = struct {
    thirty_two: u32 = 0,
    sixty_four: u64 = 0,
    signed: i32 = 0,
    pub const proto = .{
        .thirty_two = .{ .number = 1, .kind = .fixed },
        .sixty_four = .{ .number = 2, .kind = .fixed },
        .signed = .{ .number = 3, .kind = .fixed },
    };
};

const BoolFloat = struct {
    flag: bool = false,
    single: f32 = 0,
    pub const proto = .{ .flag = 1, .single = 2 };
};

test "protobuf interop: Python's encoder for the encodings its wrappers do not use" {
    // Generated with google.protobuf.internal.encoder, which is the same encoder
    // the generated classes call:
    //   SInt32Encoder(1, False, False)(w, -12345, False)
    //   SInt64Encoder(2, False, False)(w, -1, False)
    const gpa = testing.allocator;
    var buf: [64]u8 = undefined;

    const sint_hex = "08f1c0011001";
    const sints: Sints = .{ .thirty_two = -12345, .sixty_four = -1 };
    try expectHex(sint_hex, buf[0..encode(Sints, &buf, &sints)]);

    // Int32Encoder(1, True, True) — repeated, packed.
    const packed_hex = "0a0601ac02f0a204";
    const packed_value: Packed = .{ .numbers = &.{ 1, 300, 70000 } };
    try expectHex(packed_hex, buf[0..encode(Packed, &buf, &packed_value)]);

    // Int32Encoder(1, True, False) — repeated, one tag per element. A decoder has
    // to accept this for the same field, which is what the next assertion checks.
    const unpacked_hex = "080108ac0208f0a204";
    const unpacked_value: Unpacked = .{ .numbers = &.{ 1, 300, 70000 } };
    try expectHex(unpacked_hex, buf[0..encode(Unpacked, &buf, &unpacked_value)]);

    var bytes: [64]u8 = undefined;
    var from_unpacked = try decode(
        Packed,
        gpa,
        try std.fmt.hexToBytes(&bytes, unpacked_hex),
        .{},
    );
    defer from_unpacked.deinit(gpa);
    try testing.expectEqualSlices(i32, &.{ 1, 300, 70000 }, from_unpacked.value.numbers);

    var from_packed = try decode(
        Unpacked,
        gpa,
        try std.fmt.hexToBytes(&bytes, packed_hex),
        .{},
    );
    defer from_packed.deinit(gpa);
    try testing.expectEqualSlices(i32, &.{ 1, 300, 70000 }, from_packed.value.numbers);

    // Fixed32Encoder / Fixed64Encoder / SFixed32Encoder.
    const fixed_hex = "0d040302011108070605040302011dfeffffff";
    const fixeds: Fixeds = .{
        .thirty_two = 0x01020304,
        .sixty_four = 0x0102030405060708,
        .signed = -2,
    };
    try expectHex(fixed_hex, buf[0..encode(Fixeds, &buf, &fixeds)]);

    // BoolEncoder / FloatEncoder.
    const bool_float_hex = "08011500006040";
    const bool_float: BoolFloat = .{ .flag = true, .single = 3.5 };
    try expectHex(bool_float_hex, buf[0..encode(BoolFloat, &buf, &bool_float)]);
}

/// A subset of `google.protobuf.FileDescriptorProto`: enough fields to walk the
/// nesting, and deliberately not all of them, so that decoding a real message
/// also exercises skipping the fields this schema does not know about.
const FileDescriptorProto = struct {
    name: []const u8 = "",
    package: []const u8 = "",
    message_type: []const DescriptorProto = &.{},
    pub const proto = .{ .name = 1, .package = 2, .message_type = 4 };
};

const DescriptorProto = struct {
    name: []const u8 = "",
    field: []const FieldDescriptorProto = &.{},
    pub const proto = .{ .name = 1, .field = 2 };
};

const FieldDescriptorProto = struct {
    name: []const u8 = "",
    number: i32 = 0,
    pub const proto = .{ .name = 1, .number = 3 };
};

test "protobuf interop: a real nested message from Python, with fields we ignore" {
    // python3 - <<'EOF'
    // from google.protobuf import descriptor_pb2
    // f = descriptor_pb2.FileDescriptorProto(name="a.proto", package="pkg")
    // m = f.message_type.add(); m.name = "M"
    // fld = m.field.add(); fld.name = "x"; fld.number = 1
    // fld.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT32
    // print(f.SerializeToString().hex())
    // EOF
    //
    // The message carries `label` and `type` on the field, which the schema above
    // does not declare. Decoding it anyway is protobuf's forward compatibility,
    // and it is the property that makes an incomplete schema useful rather than
    // wrong.
    const gpa = testing.allocator;
    const hex = "0a07612e70726f746f1203706b67220c0a014d12070a017818012805";
    var bytes: [64]u8 = undefined;

    var decoded = try decode(
        FileDescriptorProto,
        gpa,
        try std.fmt.hexToBytes(&bytes, hex),
        .{},
    );
    defer decoded.deinit(gpa);

    try testing.expectEqualStrings("a.proto", decoded.value.name);
    try testing.expectEqualStrings("pkg", decoded.value.package);
    try testing.expectEqual(@as(usize, 1), decoded.value.message_type.len);
    try testing.expectEqualStrings("M", decoded.value.message_type[0].name);
    try testing.expectEqual(@as(usize, 1), decoded.value.message_type[0].field.len);
    try testing.expectEqualStrings("x", decoded.value.message_type[0].field[0].name);
    try testing.expectEqual(@as(i32, 1), decoded.value.message_type[0].field[0].number);
}

// ── Tests: framing and handlers ──────────────────────────────────────────────

const test_support = @import("test_support.zig");

/// Collects the messages a decoder emits, keeping the `Owned(T)` holders so their
/// arenas can be released after the assertions.
fn HolderCollector(comptime T: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        items: std.ArrayList(Owned(T)) = .empty,
        errors: std.ArrayList(anyerror) = .empty,

        pub const handler_name = "holder-collector";

        pub fn onRead(self: *Self, ctx: *HandlerContext, msg: Message) codec.Error!void {
            var owned = msg;
            // Taken rather than borrowed: the arena has to outlive this callback
            // for the assertions to read the strings in it.
            var holder = owned.take(ctx.gpa(), Owned(T)) orelse {
                owned.deinit(ctx.gpa());
                return error.UnsupportedMessage;
            };
            errdefer holder.deinit(ctx.gpa());
            try self.items.append(self.gpa, holder);
        }

        pub fn onError(self: *Self, _: *HandlerContext, err: anyerror) void {
            self.errors.append(self.gpa, err) catch {};
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.items.items) |*holder| holder.deinit(gpa);
            self.items.deinit(gpa);
            self.errors.deinit(gpa);
        }
    };
}

const FrameFixture = struct {
    fixture: test_support.Fixture,
    collected: *HolderCollector(Person),

    fn init(gpa: Allocator, options: Varint32FrameDecoder.Options) !FrameFixture {
        var fixture = try test_support.Fixture.init(gpa);
        errdefer fixture.deinit();

        _ = try Varint32FrameDecoder.addTo(fixture.pipeline, options);
        _ = try Decoder(Person).addTo(fixture.pipeline, .{});

        const collected = try gpa.create(HolderCollector(Person));
        collected.* = .{ .gpa = gpa };
        errdefer gpa.destroy(collected);
        _ = try fixture.pipeline.addLast(HolderCollector(Person).handler_name, .init(collected));

        return .{ .fixture = fixture, .collected = collected };
    }

    fn deinit(self: *FrameFixture) void {
        const gpa = self.fixture.gpa;
        self.fixture.deinit();
        self.collected.deinit(gpa);
        gpa.destroy(self.collected);
    }

    fn feed(self: *FrameFixture, bytes: []const u8) !void {
        self.fixture.pipeline.fireRead(try Message.initBytes(self.fixture.gpa, bytes));
    }

    fn people(self: *const FrameFixture) []const Owned(Person) {
        return self.collected.items.items;
    }
};

/// Frames one message the way `Varint32Prepender` does, for feeding a decoder.
fn frameOne(gpa: Allocator, person: Person) ![]u8 {
    const body_len = encodedLen(Person, &person);
    var prefix: [max_length_prefix_len]u8 = undefined;
    const prefix_len = encodeVarint(&prefix, body_len);
    const out = try gpa.alloc(u8, prefix_len + body_len);
    @memcpy(out[0..prefix_len], prefix[0..prefix_len]);
    _ = encode(Person, out[prefix_len..], &person);
    return out;
}

test "protobuf framing: two messages in one read, and one across two" {
    const gpa = testing.allocator;
    var rig = try FrameFixture.init(gpa, .{});
    defer rig.deinit();

    const first = try frameOne(gpa, .{ .name = "Alice", .id = 1 });
    defer gpa.free(first);
    const second = try frameOne(gpa, .{ .name = "Bob", .id = 2 });
    defer gpa.free(second);

    const both = try std.mem.concat(gpa, u8, &.{ first, second });
    defer gpa.free(both);
    try rig.feed(both);
    try testing.expectEqual(@as(usize, 2), rig.people().len);
    try testing.expectEqualStrings("Alice", rig.people()[0].value.name);
    try testing.expectEqualStrings("Bob", rig.people()[1].value.name);

    // Split anywhere: the decoder must hold what it has and wait.
    var split: usize = 1;
    while (split < first.len) : (split += 1) {
        var one = try FrameFixture.init(gpa, .{});
        defer one.deinit();
        try one.feed(first[0..split]);
        try testing.expectEqual(@as(usize, 0), one.people().len);
        try one.feed(first[split..]);
        try testing.expectEqual(@as(usize, 1), one.people().len);
        try testing.expectEqualStrings("Alice", one.people()[0].value.name);
    }
}

test "protobuf framing: a length prefix split across reads is not a special case" {
    // The case a hand-written test would miss: a message long enough that its
    // length takes two varint bytes, delivered one byte at a time. A decoder that
    // assumed the prefix arrived whole would read a length of 0x80 and then look
    // for a boundary that is not there.
    const gpa = testing.allocator;
    var long_name: [200]u8 = @splat('x');
    const person: Person = .{ .name = &long_name, .id = 9 };

    const bytes = try frameOne(gpa, person);
    defer gpa.free(bytes);
    // 200 bytes of name plus its own header pushes the message past 127, so the
    // prefix is two bytes — which is the whole point of this test.
    try testing.expect(bytes[0] & 0x80 != 0);

    var rig = try FrameFixture.init(gpa, .{});
    defer rig.deinit();
    for (bytes) |byte| {
        try rig.feed(&.{byte});
    }
    try testing.expectEqual(@as(usize, 1), rig.people().len);
    try testing.expectEqualStrings(&long_name, rig.people()[0].value.name);
}

test "protobuf framing: a frame longer than the limit is refused rather than buffered" {
    const gpa = testing.allocator;
    var rig = try FrameFixture.init(gpa, .{ .max_frame_length = 16 });
    defer rig.deinit();

    // A prefix announcing 1 MiB. Nothing after it is needed: the limit is checked
    // against what the peer claims, before anything is accumulated.
    var prefix: [max_length_prefix_len]u8 = undefined;
    const prefix_len = encodeVarint(&prefix, 1 << 20);
    try rig.feed(prefix[0..prefix_len]);

    try testing.expectEqual(@as(usize, 0), rig.people().len);
    try testing.expectEqual(@as(usize, 1), rig.collected.errors.items.len);
    try testing.expectEqual(error.FrameTooLong, rig.collected.errors.items[0]);
}

test "protobuf framing: the prepender and the decoder are each other's inverse" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    try Varint32Prepender.addTo(fixture.pipeline);
    try Encoder(Person).addTo(fixture.pipeline);

    const person: Person = .{ .name = "Carol", .id = 3, .email = "c@example.com" };
    try fixture.pipeline.write(try Message.initAny(gpa, Person, person));

    // What went out is exactly what the decoder side accepts, which is the only
    // claim worth making about an encoder-decoder pair.
    var rig = try FrameFixture.init(gpa, .{});
    defer rig.deinit();
    try rig.feed(fixture.written());
    try testing.expectEqual(@as(usize, 1), rig.people().len);
    try testing.expectEqualStrings("Carol", rig.people()[0].value.name);
    try testing.expectEqualStrings("c@example.com", rig.people()[0].value.email);
    try testing.expectEqual(@as(i32, 3), rig.people()[0].value.id);
}

// ── Tests: the schema mapping ────────────────────────────────────────────────

/// The example message from protobuf's own tutorial, which makes the encoded
/// bytes checkable against anybody's documentation.
const Person = struct {
    name: []const u8 = "",
    id: i32 = 0,
    email: []const u8 = "",

    pub const proto = .{ .name = 1, .id = 2, .email = 3 };
};

const Scalars = struct {
    flag: bool = false,
    small: u32 = 0,
    big: u64 = 0,
    negative: i32 = 0,
    zigzagged: i32 = 0,
    fixed_wide: u64 = 0,
    single: f32 = 0,
    double: f64 = 0,
    bytes: []const u8 = "",

    pub const proto = .{
        .flag = 1,
        .small = 2,
        .big = 3,
        .negative = 4,
        .zigzagged = .{ .number = 5, .kind = .sint },
        .fixed_wide = .{ .number = 6, .kind = .fixed },
        .single = 7,
        .double = 8,
        .bytes = 9,
    };
};

fn roundTrip(comptime T: type, value: T) !Owned(T) {
    const gpa = testing.allocator;
    const len = encodedLen(T, &value);
    const buf = try gpa.alloc(u8, len);
    defer gpa.free(buf);
    const written = encode(T, buf, &value);
    try testing.expectEqual(len, written);
    return decode(T, gpa, buf[0..written], .{});
}

test "protobuf schema: the tutorial's own message, byte for byte" {
    const person: Person = .{ .name = "Alice", .id = 42, .email = "a@example.com" };
    var buf: [64]u8 = undefined;
    const len = encode(Person, &buf, &person);

    // Field 1 (0x0a) length 5 "Alice", field 2 (0x10) varint 42, field 3 (0x1a)
    // length 13. Hand-derived from the encoding rules, so this test fails if the
    // tag arithmetic drifts rather than only if a round trip breaks.
    try testing.expectEqualSlices(u8, &.{
        0x0a, 0x05, 'A',  'l',  'i', 'c', 'e',
        0x10, 0x2a, 0x1a, 0x0d, 'a', '@', 'e',
        'x',  'a',  'm',  'p',  'l', 'e', '.',
        'c',  'o',  'm',
    }, buf[0..len]);

    var decoded = try roundTrip(Person, person);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqualStrings("Alice", decoded.value.name);
    try testing.expectEqual(@as(i32, 42), decoded.value.id);
    try testing.expectEqualStrings("a@example.com", decoded.value.email);
}

test "protobuf schema: every scalar encoding survives a round trip" {
    const value: Scalars = .{
        .flag = true,
        .small = 4000000000,
        .big = std.math.maxInt(u64),
        .negative = -1,
        .zigzagged = -1,
        .fixed_wide = 0x0102030405060708,
        .single = 3.5,
        .double = -2.25,
        .bytes = "\x00\xff binary",
    };
    var decoded = try roundTrip(Scalars, value);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(value.flag, decoded.value.flag);
    try testing.expectEqual(value.small, decoded.value.small);
    try testing.expectEqual(value.big, decoded.value.big);
    try testing.expectEqual(value.negative, decoded.value.negative);
    try testing.expectEqual(value.zigzagged, decoded.value.zigzagged);
    try testing.expectEqual(value.fixed_wide, decoded.value.fixed_wide);
    try testing.expectEqual(value.single, decoded.value.single);
    try testing.expectEqual(value.double, decoded.value.double);
    try testing.expectEqualStrings(value.bytes, decoded.value.bytes);
}

test "protobuf schema: a negative int costs ten bytes and sint costs one" {
    // This is the difference the `kind` declaration exists for, and it is worth
    // asserting rather than describing: `int32` is a 64-bit two's complement
    // varint, so -1 is ten bytes of 0xff.
    const value: Scalars = .{ .negative = -1, .zigzagged = -1 };
    var buf: [64]u8 = undefined;
    const len = encode(Scalars, &buf, &value);
    // Field 4 tag + ten bytes, then field 5 tag + one byte.
    try testing.expectEqualSlices(u8, &.{
        0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        0x28, 0x01,
    }, buf[0..len]);
}

test "protobuf schema: proto3 leaves defaults off the wire" {
    // An all-default message is zero bytes, and decoding zero bytes returns the
    // defaults. That equivalence is what lets two peers with the same schema and
    // different versions agree.
    const empty: Scalars = .{};
    try testing.expectEqual(@as(usize, 0), encodedLen(Scalars, &empty));

    var decoded = try decode(Scalars, testing.allocator, &.{}, .{});
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(false, decoded.value.flag);
    try testing.expectEqual(@as(u32, 0), decoded.value.small);
    try testing.expectEqualStrings("", decoded.value.bytes);
}

const Presence = struct {
    maybe: ?u32 = null,
    plain: u32 = 0,

    pub const proto = .{ .maybe = 1, .plain = 2 };
};

test "protobuf schema: an optional distinguishes unset from zero" {
    // The whole reason `?T` is in the mapping: proto3 cannot tell a zero from an
    // absent scalar unless presence is explicit, and a struct that needs the
    // difference says so in its type.
    const unset: Presence = .{ .maybe = null, .plain = 0 };
    try testing.expectEqual(@as(usize, 0), encodedLen(Presence, &unset));

    const zero: Presence = .{ .maybe = 0, .plain = 0 };
    try testing.expect(encodedLen(Presence, &zero) > 0);

    var decoded = try roundTrip(Presence, zero);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqual(@as(?u32, 0), decoded.value.maybe);

    var absent = try roundTrip(Presence, unset);
    defer absent.deinit(testing.allocator);
    try testing.expectEqual(@as(?u32, null), absent.value.maybe);
}

const Repeated = struct {
    numbers: []const u32 = &.{},
    unpacked: []const u32 = &.{},
    names: []const []const u8 = &.{},
    people: []const Person = &.{},

    pub const proto = .{
        .numbers = 1,
        .unpacked = .{ .number = 2, .packed_scalars = false },
        .names = 3,
        .people = 4,
    };
};

test "protobuf schema: repeated fields, packed and not, and nested messages" {
    const value: Repeated = .{
        .numbers = &.{ 1, 300, 70000 },
        .unpacked = &.{ 7, 8 },
        .names = &.{ "a", "bb" },
        .people = &.{
            .{ .name = "Alice", .id = 1 },
            .{ .name = "Bob", .id = 2, .email = "b@example.com" },
        },
    };
    var decoded = try roundTrip(Repeated, value);
    defer decoded.deinit(testing.allocator);
    try testing.expectEqualSlices(u32, value.numbers, decoded.value.numbers);
    try testing.expectEqualSlices(u32, value.unpacked, decoded.value.unpacked);
    try testing.expectEqual(@as(usize, 2), decoded.value.names.len);
    try testing.expectEqualStrings("bb", decoded.value.names[1]);
    try testing.expectEqual(@as(usize, 2), decoded.value.people.len);
    try testing.expectEqualStrings("Bob", decoded.value.people[1].name);
    try testing.expectEqualStrings("b@example.com", decoded.value.people[1].email);
    try testing.expectEqual(@as(i32, 1), decoded.value.people[0].id);
}

test "protobuf schema: a packed field is accepted in the unpacked form and vice versa" {
    // §The two encodings are interchangeable, and a decoder must accept both
    // whatever its own schema prefers — a proto2 encoder sends one tag per
    // element. Encoding `unpacked` and decoding it as `numbers` is the test,
    // done by rewriting the field number rather than by having two schemas.
    const gpa = testing.allocator;
    const unpacked: Repeated = .{ .unpacked = &.{ 1, 300, 70000 } };
    const len = encodedLen(Repeated, &unpacked);
    const buf = try gpa.alloc(u8, len);
    defer gpa.free(buf);
    _ = encode(Repeated, buf, &unpacked);

    // Field 2 varint becomes field 1 varint: tag 0x10 -> 0x08.
    for (buf) |*byte| {
        if (byte.* == 0x10) byte.* = 0x08;
    }
    var decoded = try decode(Repeated, gpa, buf, .{});
    defer decoded.deinit(gpa);
    try testing.expectEqualSlices(u32, &.{ 1, 300, 70000 }, decoded.value.numbers);
    try testing.expectEqual(@as(usize, 0), decoded.value.unpacked.len);
}

test "protobuf schema: an unknown field is skipped rather than refused" {
    // Forward compatibility is the point of the format, so a message from a newer
    // schema has to decode. Field 15 is not in `Person`.
    const gpa = testing.allocator;
    var buf: [64]u8 = undefined;
    var len = encodeTag(&buf, .{ .number = 1, .wire = .len });
    len += encodeVarint(buf[len..], 3);
    @memcpy(buf[len..][0..3], "Eve");
    len += 3;
    len += encodeTag(buf[len..], .{ .number = 15, .wire = .varint });
    len += encodeVarint(buf[len..], 99);
    len += encodeTag(buf[len..], .{ .number = 2, .wire = .varint });
    len += encodeVarint(buf[len..], 7);

    var decoded = try decode(Person, gpa, buf[0..len], .{});
    defer decoded.deinit(gpa);
    try testing.expectEqualStrings("Eve", decoded.value.name);
    try testing.expectEqual(@as(i32, 7), decoded.value.id);
}

const Level4 = struct {
    leaf: u32 = 0,
    pub const proto = .{ .leaf = 1 };
};
const Level3 = struct {
    inner: ?*const Level4 = null,
    pub const proto = .{ .inner = 1 };
};
const Level2 = struct {
    inner: ?*const Level3 = null,
    pub const proto = .{ .inner = 1 };
};
const Nested = struct {
    inner: ?*const Level2 = null,
    pub const proto = .{ .inner = 1 };
};

test "protobuf schema: nesting deeper than the limit is refused, not recursed" {
    // A length-delimited field can hold another message, so a peer can announce
    // any depth it likes in a handful of bytes. Without the limit that is a stack
    // overflow rather than an error, which is why the bound is a decoder input
    // and not a constant.
    //
    // Three levels of wrapping around `leaf = 42`, hand-assembled so the test
    // does not depend on the encoder to check the decoder.
    const gpa = testing.allocator;
    const bytes = [_]u8{
        0x0a, 0x06, // Nested.inner, 6 bytes
        0x0a, 0x04, // Level2.inner, 4 bytes
        0x0a, 0x02, // Level3.inner, 2 bytes
        0x08, 0x2a, // Level4.leaf = 42
    };

    // Four `decodeInto` calls happen at depths 0, 1, 2 and 3.
    try testing.expectError(
        error.NestingTooDeep,
        decode(Nested, gpa, &bytes, .{ .max_nesting_depth = 3 }),
    );

    var ok = try decode(Nested, gpa, &bytes, .{ .max_nesting_depth = 8 });
    defer ok.deinit(gpa);
    try testing.expectEqual(@as(u32, 42), ok.value.inner.?.inner.?.inner.?.leaf);
}

test "protobuf schema: a nested message behind a pointer round trips" {
    // `*const Message` is how a message holds another by reference, which is what
    // an optional submessage needs when the child is large or absent.
    const leaf: Level4 = .{ .leaf = 7 };
    const third: Level3 = .{ .inner = &leaf };
    const second: Level2 = .{ .inner = &third };
    var round = try roundTrip(Nested, .{ .inner = &second });
    defer round.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 7), round.value.inner.?.inner.?.inner.?.leaf);

    // An absent submessage writes nothing, which is the difference between a
    // missing message and an empty one.
    const empty: Nested = .{};
    try testing.expectEqual(@as(usize, 0), encodedLen(Nested, &empty));
}

test "protobuf schema: the element limit is checked before memory is taken" {
    const gpa = testing.allocator;
    const value: Repeated = .{ .numbers = &.{ 1, 2, 3, 4, 5 } };
    const len = encodedLen(Repeated, &value);
    const buf = try gpa.alloc(u8, len);
    defer gpa.free(buf);
    _ = encode(Repeated, buf, &value);

    try testing.expectError(
        error.TooManyElements,
        decode(Repeated, gpa, buf, .{ .max_elements = 4 }),
    );
    var ok = try decode(Repeated, gpa, buf, .{ .max_elements = 5 });
    defer ok.deinit(gpa);
    try testing.expectEqual(@as(usize, 5), ok.value.numbers.len);
}

test "protobuf schema: a wire type the field cannot hold is a mismatch, not a coercion" {
    // Field 2 of `Person` is a varint. Sending it length-delimited is a schema
    // disagreement, and guessing would turn that into a wrong number.
    const gpa = testing.allocator;
    var buf: [32]u8 = undefined;
    var len = encodeTag(&buf, .{ .number = 2, .wire = .len });
    len += encodeVarint(buf[len..], 1);
    buf[len] = 0x2a;
    len += 1;
    try testing.expectError(error.WireTypeMismatch, decode(Person, gpa, buf[0..len], .{}));
}

test "protobuf schema: the last value of a repeated-once field wins" {
    // §Concatenating two messages merges them, and for a non-repeated field that
    // means the later value replaces the earlier one.
    const gpa = testing.allocator;
    var buf: [32]u8 = undefined;
    var len = encodeTag(&buf, .{ .number = 2, .wire = .varint });
    len += encodeVarint(buf[len..], 1);
    len += encodeTag(buf[len..], .{ .number = 2, .wire = .varint });
    len += encodeVarint(buf[len..], 2);

    var decoded = try decode(Person, gpa, buf[0..len], .{});
    defer decoded.deinit(gpa);
    try testing.expectEqual(@as(i32, 2), decoded.value.id);
}

const Colour = enum(i32) { unspecified = 0, red = 1, green = 2 };

const WithEnum = struct {
    colour: Colour = .unspecified,

    pub const proto = .{ .colour = 1 };
};

test "protobuf schema: an enum value the type cannot hold is reported" {
    const gpa = testing.allocator;
    var round = try roundTrip(WithEnum, .{ .colour = .green });
    defer round.deinit(testing.allocator);
    try testing.expectEqual(Colour.green, round.value.colour);

    // A peer built from a newer schema sends 7. A Zig enum cannot hold it, so it
    // is an error rather than a value nobody declared — and the note in the code
    // says to declare the field as its integer type when that matters.
    var buf: [16]u8 = undefined;
    var len = encodeTag(&buf, .{ .number = 1, .wire = .varint });
    len += encodeVarint(buf[len..], 7);
    try testing.expectError(error.InvalidValue, decode(WithEnum, gpa, buf[0..len], .{}));
}

// ── Tests: the wire format ───────────────────────────────────────────────────

const testing = std.testing;

test "protobuf varint: round trips, and the length is predicted before writing" {
    const cases = [_]u64{
        0,     1,                    127,     128,     300,
        16383, 16384,                1 << 31, 1 << 63, std.math.maxInt(u64),
        150,   std.math.maxInt(u32),
    };
    for (cases) |value| {
        var buf: [max_varint_len]u8 = undefined;
        const written = encodeVarint(&buf, value);
        try testing.expectEqual(varintLen(value), written);
        const decoded = try decodeVarint(buf[0..written]);
        try testing.expectEqual(value, decoded.value);
        try testing.expectEqual(written, decoded.len);
    }
}

test "protobuf varint: the encoding in the specification's own example" {
    // The protobuf encoding document uses 150 as its worked example: 0x96 0x01.
    var buf: [max_varint_len]u8 = undefined;
    const written = encodeVarint(&buf, 150);
    try testing.expectEqualSlices(u8, &.{ 0x96, 0x01 }, buf[0..written]);
}

test "protobuf varint: truncation and overflow are different answers" {
    // Continuation bit set with nothing after it: ask again with more bytes.
    try testing.expectError(error.Truncated, decodeVarint(&.{0x80}));
    try testing.expectError(error.Truncated, decodeVarint(&.{}));
    try testing.expectError(error.Truncated, decodeVarint(&.{ 0x80, 0x80 }));

    // Ten bytes is the most a 64-bit value can take, and the tenth carries one
    // bit. A tenth byte of 2 is a 65-bit value.
    const ten_ok = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 };
    const decoded = try decodeVarint(&ten_ok);
    try testing.expectEqual(std.math.maxInt(u64), decoded.value);
    try testing.expectEqual(@as(usize, 10), decoded.len);

    const ten_overflow = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02 };
    try testing.expectError(error.VarintOverflow, decodeVarint(&ten_overflow));

    // A tenth byte with the continuation bit would mean an eleventh.
    const eleven = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x81, 0x01 };
    try testing.expectError(error.VarintOverflow, decodeVarint(&eleven));
}

test "protobuf zigzag: the mapping in the specification's table" {
    // From the encoding document: 0 -> 0, -1 -> 1, 1 -> 2, -2 -> 3, and the
    // extremes of the 32-bit range.
    try testing.expectEqual(@as(u64, 0), zigzagEncode(i32, 0));
    try testing.expectEqual(@as(u64, 1), zigzagEncode(i32, -1));
    try testing.expectEqual(@as(u64, 2), zigzagEncode(i32, 1));
    try testing.expectEqual(@as(u64, 3), zigzagEncode(i32, -2));
    try testing.expectEqual(@as(u64, 4294967294), zigzagEncode(i32, std.math.maxInt(i32)));
    try testing.expectEqual(@as(u64, 4294967295), zigzagEncode(i32, std.math.minInt(i32)));

    for ([_]i32{ 0, -1, 1, -2, 2, 12345, -12345, std.math.maxInt(i32), std.math.minInt(i32) }) |v| {
        try testing.expectEqual(v, try zigzagDecode(i32, zigzagEncode(i32, v)));
    }
    for ([_]i64{ 0, -1, 1, std.math.maxInt(i64), std.math.minInt(i64) }) |v| {
        try testing.expectEqual(v, try zigzagDecode(i64, zigzagEncode(i64, v)));
    }

    // A 64-bit zigzag value does not fit an i32, and saying so beats truncating.
    try testing.expectError(
        error.InvalidValue,
        zigzagDecode(i32, zigzagEncode(i64, std.math.maxInt(i64))),
    );
}

test "protobuf tags: field number and wire type share the varint" {
    var buf: [max_varint_len]u8 = undefined;
    const written = encodeTag(&buf, .{ .number = 1, .wire = .len });
    // Field 1, wire type 2: the first byte of every length-delimited field 1.
    try testing.expectEqualSlices(u8, &.{0x0a}, buf[0..written]);

    const decoded = try decodeTag(buf[0..written]);
    try testing.expectEqual(@as(u32, 1), decoded.value.number);
    try testing.expectEqual(WireType.len, decoded.value.wire);

    const high = encodeTag(&buf, .{ .number = max_field_number, .wire = .varint });
    const high_decoded = try decodeTag(buf[0..high]);
    try testing.expectEqual(max_field_number, high_decoded.value.number);
}

test "protobuf tags: what is refused and why" {
    // Field number zero: no field has it, and accepting it would mean carrying a
    // number no encoder can produce.
    try testing.expectError(error.InvalidFieldNumber, decodeTag(&.{0x00}));

    // Groups are named in the enum so they can be refused rather than skipped:
    // a group is bounded only by its own end tag, so skipping one is
    // implementing one.
    var buf: [max_varint_len]u8 = undefined;
    const sgroup = encodeVarint(&buf, (1 << 3) | 3);
    try testing.expectError(error.UnsupportedWireType, decodeTag(buf[0..sgroup]));
    const egroup = encodeVarint(&buf, (1 << 3) | 4);
    try testing.expectError(error.UnsupportedWireType, decodeTag(buf[0..egroup]));

    // Wire types 6 and 7 were never assigned.
    const six = encodeVarint(&buf, (1 << 3) | 6);
    try testing.expectError(error.UnsupportedWireType, decodeTag(buf[0..six]));

    // 19000-19999 are reserved for the implementation.
    const reserved = encodeTag(&buf, .{ .number = 19000, .wire = .varint });
    try testing.expectError(error.InvalidFieldNumber, decodeTag(buf[0..reserved]));

    // Above 2^29-1 the number does not fit the tag's own definition.
    const too_high = encodeVarint(&buf, (@as(u64, max_field_number) + 1) << 3);
    try testing.expectError(error.InvalidFieldNumber, decodeTag(buf[0..too_high]));
}

test "protobuf reader: walks every wire type, and bounds what it is told" {
    // Hand-assembled: field 1 varint 150, field 2 string "hi", field 3 fixed32,
    // field 4 fixed64.
    const bytes = [_]u8{
        0x08, 0x96, 0x01, // 1: varint 150
        0x12, 0x02, 'h', 'i', // 2: len "hi"
        0x1d, 0x04, 0x03, 0x02, 0x01, // 3: i32
        0x21, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // 4: i64
    };
    var reader: Reader = .init(&bytes, .{});

    const first = (try reader.next()).?;
    try testing.expectEqual(@as(u32, 1), first.number);
    try testing.expectEqual(@as(u64, 150), try first.asU64());

    const second = (try reader.next()).?;
    try testing.expectEqual(@as(u32, 2), second.number);
    try testing.expectEqualStrings("hi", try second.asBytes());

    const third = (try reader.next()).?;
    try testing.expectEqual(@as(u32, 0x01020304), try third.asU64());

    const fourth = (try reader.next()).?;
    try testing.expectEqual(@as(u64, 0x0102030405060708), try fourth.asU64());

    try testing.expectEqual(@as(?Field, null), try reader.next());
    try testing.expect(reader.atEnd());
}

test "protobuf reader: a length a peer announced is checked against the limit" {
    // Field 1, length-delimited, announcing 1 MiB inside a 4-byte buffer. The
    // limit is what turns this from an allocation into an error.
    var bytes: [8]u8 = undefined;
    var len: usize = encodeTag(&bytes, .{ .number = 1, .wire = .len });
    len += encodeVarint(bytes[len..], 1 << 20);

    var strict: Reader = .init(bytes[0..len], .{ .max_message_len = 1024 });
    try testing.expectError(error.MessageTooLong, strict.next());

    // Within the limit but not actually present is a different answer, because a
    // stream decoder has to be able to ask for more.
    var permissive: Reader = .init(bytes[0..len], .{ .max_message_len = 1 << 21 });
    try testing.expectError(error.Truncated, permissive.next());
}

test "protobuf reader: a field cut in half asks for more rather than guessing" {
    const whole = [_]u8{ 0x08, 0x96, 0x01, 0x12, 0x02, 'h', 'i' };
    // Every proper prefix must be either a clean stop or `Truncated` — never a
    // value invented out of missing bytes. This is the same property the fuzz
    // targets assert for stream decoders, checked here where it is cheap.
    var cut: usize = 1;
    while (cut < whole.len) : (cut += 1) {
        var reader: Reader = .init(whole[0..cut], .{});
        while (true) {
            const field = reader.next() catch |err| {
                try testing.expectEqual(error.Truncated, err);
                break;
            };
            if (field == null) break;
        }
    }
}
