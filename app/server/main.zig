const std = @import("std");
const net = std.net;
const mem = std.mem;
const Thread = std.Thread;
const Allocator = mem.Allocator;

const MAX_USER_ID_LEN = 64;
const UserId = std.BoundedArray(u8, MAX_USER_ID_LEN);
const PublicKey = std.ArrayList(u8);
const Message = struct { data: []u8 };

const ServerContext = struct {
    allocator: Allocator,
    pubkey_store: std.AutoHashMap(UserId, PublicKey),
    message_queues: std.AutoHashMap(UserId, std.Queue(Message)),
    pubkey_mutex: Thread.Mutex = .{},
    msg_mutex: Thread.Mutex = .{},
};

const Command = enum(u8) {
    register = 1,
    get_pubkey = 2,
    send_msg = 3,
    get_msgs = 4,
};

fn handleClient(context: *ServerContext, conn: net.Server.Connection) !void {
    const stream = conn.stream;
    defer stream.close();

    while (true) {
        const cmd_byte = stream.readByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };

        switch (cmd_byte) {
            @intFromEnum(Command.register) => try handleRegister(context, stream),
            @intFromEnum(Command.get_pubkey) => try handleGetPubkey(context, stream),
            @intFromEnum(Command.send_msg) => try handleSendMsg(context, stream),
            @intFromEnum(Command.get_msgs) => try handleGetMsgs(context, stream),
            else => return error.InvalidCommand,
        }
    }
}

fn handleRegister(context: *ServerContext, stream: net.Stream) !void {
    const user_id = try readBoundedArray(stream);

    const pubkey = try readArrayList(context.allocator, stream);

    context.pubkey_mutex.lock();
    defer context.pubkey_mutex.unlock();

    if (context.pubkey_store.contains(user_id)) {
        try stream.writeAll(&.{1});
        return;
    }

    try context.pubkey_store.put(user_id, pubkey);
    try stream.writeAll(&.{0});
}

fn handleGetPubkey(context: *ServerContext, stream: net.Stream) !void {
    const user_id = try readBoundedArray(stream);

    context.pubkey_mutex.lock();
    defer context.pubkey_mutex.unlock();

    if (context.pubkey_store.get(user_id)) |pubkey| {
        try stream.writeAll(&.{0});
        try writeArrayList(stream, pubkey);
    } else {
        try stream.writeAll(&.{1});
    }
}

fn handleSendMsg(context: *ServerContext, stream: net.Stream) !void {
    const recipient_id = try readBoundedArray(stream);
    const msg_data = try readArrayList(context.allocator, stream);

    context.pubkey_mutex.lock();
    const exists = context.pubkey_store.contains(recipient_id);
    context.pubkey_mutex.unlock();

    if (!exists) {
        try stream.writeAll(&.{1});
        return;
    }

    const data_copy = try context.allocator.dupe(u8, msg_data.items);
    context.msg_mutex.lock();
    defer context.msg_mutex.unlock();

    var queue_entry = try context.message_queues.getOrPut(recipient_id);
    if (!queue_entry.found_existing) {
        queue_entry.value_ptr.* = std.Queue(Message).init(context.allocator);
    }
    try queue_entry.value_ptr.enqueue(.{ .data = data_copy });

    try stream.writeAll(&.{0});
}

fn handleGetMsgs(context: *ServerContext, stream: net.Stream) !void {
    const user_id = try readBoundedArray(stream);

    context.msg_mutex.lock();
    defer context.msg_mutex.unlock();

    const queue = context.message_queues.getPtr(user_id) orelse {
        try stream.writeAll(&.{0});
        return;
    };

    const count = queue.len;
    try stream.writeAll(&.{0});
    try stream.writeInt(u32, count, .big);

    while (queue.dequeue()) |msg| {
        try stream.writeInt(u32, msg.data.len, .big);
        try stream.writeAll(msg.data);
        context.allocator.free(msg.data);
    }
}

fn readBoundedArray(stream: net.Stream) !UserId {
    const len = try stream.readInt(u16, .big);
    var data = try UserId.init(len);
    try stream.readAll(data.slice());
    return data;
}

fn readArrayList(allocator: Allocator, stream: net.Stream) !PublicKey {
    const len = try stream.readInt(u32, .big);
    var list = try PublicKey.initCapacity(allocator, len);
    list.items.len = len;
    try stream.readAll(list.items);
    return list;
}

fn writeArrayList(stream: net.Stream, list: PublicKey) !void {
    try stream.writeInt(u32, list.items.len, .big);
    try stream.writeAll(list.items);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var server = net.Server.init(allocator, .{ .reuse_addr = true });
    defer server.deinit();

    try server.listen(try net.Address.parseIp("0.0.0.0", 3000));

    var context = ServerContext{
        .allocator = allocator,
        .pubkey_store = std.AutoHashMap(UserId, PublicKey).init(allocator),
        .message_queues = std.AutoHashMap(UserId, std.Queue(Message)).init(allocator),
    };

    while (true) {
        const conn = try server.accept();
        try Thread.spawn(.{}, handleClient, .{ &context, conn });
    }
}
