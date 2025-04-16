const std = @import("std");
const net = std.net;
const mem = std.mem;
const Thread = std.Thread;
const Allocator = mem.Allocator;

const MAX_USER_ID_LEN = 64;
const UserId = std.BoundedArray(u8, MAX_USER_ID_LEN);
const PublicKey = std.ArrayList(u8);
const Message = struct { data: []u8 };

pub fn Queue(comptime Child: type) type {
    return struct {
        const Self = @This();
        list: std.ArrayList(Child),
        allocator: Allocator,

        pub fn init(allocator: Allocator) Self {
            return Self{
                .list = std.ArrayList(Child).init(allocator),
                .allocator = allocator,
            };
        }

        pub fn enqueue(self: *Self, value: Child) !void {
            try self.list.append(value);
        }

        pub fn dequeue(self: *Self) ?Child {
            if (self.list.items.len == 0) return null;
            return self.list.orderedRemove(0);
        }

        pub fn len(self: *Self) usize {
            return self.list.items.len;
        }

        pub fn deinit(self: *Self) void {
            self.list.deinit();
        }
    };
}

const ServerContext = struct {
    allocator: Allocator,
    pubkey_store: std.AutoHashMap(UserId, PublicKey),
    message_queues: std.AutoHashMap(UserId, Queue(Message)),
    pubkey_mutex: Thread.Mutex = .{},
    msg_mutex: Thread.Mutex = .{},
};

const Command = enum(u8) {
    register = 1,
    get_pubkey = 2,
    send_msg = 3,
    get_msgs = 4,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const address = try net.Address.parseIp("0.0.0.0", 3000);
    var server = try address.listen(.{
        .reuse_address = true,
        .kernel_backlog = 128,
    });
    defer server.deinit();

    var context = ServerContext{
        .allocator = allocator,
        .pubkey_store = std.AutoHashMap(UserId, PublicKey).init(allocator),
        .message_queues = std.AutoHashMap(UserId, Queue(Message)).init(allocator),
    };

    // Main server loop
    while (true) {
        const conn = try server.accept();
        _ = try Thread.spawn(.{}, handleClient, .{ &context, conn });
    }
}

fn handleClient(context: *ServerContext, conn: net.Server.Connection) !void {
    defer conn.stream.close();
    const reader = conn.stream.reader();
    const writer = conn.stream.writer();

    while (true) {
        const cmd_byte = reader.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };

        switch (cmd_byte) {
            @intFromEnum(Command.register) => try handleRegister(context, reader, writer),
            @intFromEnum(Command.get_pubkey) => try handleGetPubkey(context, reader, writer),
            @intFromEnum(Command.send_msg) => try handleSendMsg(context, reader, writer),
            @intFromEnum(Command.get_msgs) => try handleGetMsgs(context, reader, writer),
            else => return error.InvalidCommand,
        }
    }
}

fn handleRegister(context: *ServerContext, reader: anytype, writer: anytype) !void {
    const user_id = try readBoundedArray(reader);
    const pubkey = try readArrayList(context.allocator, reader);

    context.pubkey_mutex.lock();
    defer context.pubkey_mutex.unlock();

    if (context.pubkey_store.contains(user_id)) {
        try writer.writeByte(1);
        return;
    }

    try context.pubkey_store.put(user_id, pubkey);
    try writer.writeByte(0);
}

fn handleGetPubkey(context: *ServerContext, reader: anytype, writer: anytype) !void {
    const user_id = try readBoundedArray(reader);

    context.pubkey_mutex.lock();
    defer context.pubkey_mutex.unlock();

    if (context.pubkey_store.get(user_id)) |pubkey| {
        try writer.writeByte(0);
        try writeArrayList(writer, pubkey);
    } else {
        try writer.writeByte(1);
    }
}

fn handleSendMsg(context: *ServerContext, reader: anytype, writer: anytype) !void {
    const recipient_id = try readBoundedArray(reader);
    const msg_data = try readArrayList(context.allocator, reader);

    context.pubkey_mutex.lock();
    const exists = context.pubkey_store.contains(recipient_id);
    context.pubkey_mutex.unlock();

    if (!exists) {
        try writer.writeByte(1);
        return;
    }

    const data_copy = try context.allocator.dupe(u8, msg_data.items);
    errdefer context.allocator.free(data_copy);

    context.msg_mutex.lock();
    defer context.msg_mutex.unlock();

    var queue_entry = try context.message_queues.getOrPut(recipient_id);
    if (!queue_entry.found_existing) {
        queue_entry.value_ptr.* = Queue(Message).init(context.allocator);
    }

    try queue_entry.value_ptr.enqueue(.{ .data = data_copy });
    try writer.writeByte(0);
}

fn handleGetMsgs(context: *ServerContext, reader: anytype, writer: anytype) !void {
    const user_id = try readBoundedArray(reader);

    context.msg_mutex.lock();
    defer context.msg_mutex.unlock();

    const queue = context.message_queues.getPtr(user_id) orelse {
        try writer.writeByte(0);
        return;
    };

    const count = queue.len();
    try writer.writeByte(0);
    try writer.writeInt(u32, @intCast(count), .big);

    while (queue.dequeue()) |msg| {
        defer context.allocator.free(msg.data);
        try writer.writeInt(u32, @intCast(msg.data.len), .big);
        try writer.writeAll(msg.data);
    }
}

fn readBoundedArray(reader: anytype) !UserId {
    const len = try reader.readInt(u16, .big);
    var data = try UserId.init(len);
    try reader.readNoEof(data.slice());
    return data;
}

fn readArrayList(allocator: Allocator, reader: anytype) !PublicKey {
    const len = try reader.readInt(u32, .big);
    var list = try PublicKey.initCapacity(allocator, len);
    try list.resize(len);
    try reader.readNoEof(list.items);
    return list;
}

fn writeArrayList(writer: anytype, list: PublicKey) !void {
    try writer.writeInt(u32, @intCast(list.items.len), .big);
    try writer.writeAll(list.items);
}
