const std = @import("std");
const net = std.net;
const mem = std.mem;
const Allocator = mem.Allocator;

const MAX_USER_ID_LEN = 64;
const UserId = std.BoundedArray(u8, MAX_USER_ID_LEN);
const PublicKey = std.ArrayList(u8);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const address = try net.Address.parseIp("192.168.0.24", 56625);
    const conn = try net.tcpConnectToAddress(address);
    defer conn.close();

    try testRegister(conn, "user1", "pubkey1");
    try testGetPubkey(allocator, conn, "user1");
    try testSendMessage(conn, "user1", "Hello World!");
    try testGetMessages(allocator, conn, "user1");

    try testDuplicateRegistration(conn, "user1");
    try testNonExistentUser(conn, "invalid_user");
}

fn testRegister(stream: net.Stream, user_id: []const u8, pubkey: []const u8) !void {
    const writer = stream.writer();
    const reader = stream.reader();

    try writer.writeByte(1);

    const bounded_id = try UserId.fromSlice(user_id);
    try writer.writeInt(u16, @intCast(bounded_id.len), .big);
    try writer.writeAll(bounded_id.constSlice());

    try writer.writeInt(u32, @intCast(pubkey.len), .big);
    try writer.writeAll(pubkey);

    const response = try reader.readByte();
    std.debug.print("Register {s}: {s}\n", .{ user_id, if (response == 0) "Success" else "Failed" });
}

fn testGetPubkey(allocator: Allocator, stream: net.Stream, user_id: []const u8) !void {
    const writer = stream.writer();
    const reader = stream.reader();

    try writer.writeByte(2);

    const bounded_id = try UserId.fromSlice(user_id);
    try writer.writeInt(u16, @intCast(bounded_id.len), .big);
    try writer.writeAll(bounded_id.constSlice());

    const status = try reader.readByte();
    if (status == 0) {
        const key_len = try reader.readInt(u32, .big);
        var key = try PublicKey.initCapacity(allocator, key_len);
        key.resize(key_len) catch unreachable;
        try reader.readNoEof(key.items);
        std.debug.print("Pubkey for {s}: {s}\n", .{ user_id, key.items });
    } else {
        std.debug.print("Pubkey for {s}: Not found\n", .{user_id});
    }
}

fn testSendMessage(stream: net.Stream, recipient: []const u8, message: []const u8) !void {
    const writer = stream.writer();
    const reader = stream.reader();

    try writer.writeByte(3);

    var bounded_id = try UserId.fromSlice(recipient);
    try writer.writeInt(u16, @intCast(bounded_id.len), .big);
    try writer.writeAll(bounded_id.constSlice());

    try writer.writeInt(u32, @intCast(message.len), .big);
    try writer.writeAll(message);

    const response = try reader.readByte();
    std.debug.print("Message to {s}: {s}\n", .{ recipient, if (response == 0) "Delivered" else "Failed" });
}

fn testGetMessages(allocator: Allocator, stream: net.Stream, user_id: []const u8) !void {
    const writer = stream.writer();
    const reader = stream.reader();

    try writer.writeByte(4);

    const bounded_id = try UserId.fromSlice(user_id);
    try writer.writeInt(u16, @intCast(bounded_id.len), .big);
    try writer.writeAll(bounded_id.constSlice());

    const status = try reader.readByte();
    if (status == 0) {
        const count = try reader.readInt(u32, .big);
        std.debug.print("Messages for {s} ({}):\n", .{ user_id, count });

        for (0..count) |_| {
            const msg_len = try reader.readInt(u32, .big);
            const msg = try allocator.alloc(u8, msg_len);
            defer allocator.free(msg);
            try reader.readNoEof(msg);
            std.debug.print(" - {s}\n", .{msg});
        }
    } else {
        std.debug.print("No messages for {s}\n", .{user_id});
    }
}

fn testDuplicateRegistration(stream: net.Stream, user_id: []const u8) !void {
    const writer = stream.writer();
    const reader = stream.reader();

    try writer.writeByte(1);
    const bounded_id = try UserId.fromSlice(user_id);
    try writer.writeInt(u16, @intCast(bounded_id.len), .big);
    try writer.writeAll(bounded_id.constSlice());
    try writer.writeInt(u32, 4, .big);
    try writer.writeAll("dupe");

    const response = try reader.readByte();
    std.debug.print("Duplicate register {s}: {s}\n", .{ user_id, if (response == 1) "Properly rejected" else "Unexpected success" });
}

fn testNonExistentUser(stream: net.Stream, user_id: []const u8) !void {
    const writer = stream.writer();
    const reader = stream.reader();

    try writer.writeByte(2);
    const bounded_id = try UserId.fromSlice(user_id);
    try writer.writeInt(u16, @intCast(bounded_id.len), .big);
    try writer.writeAll(bounded_id.constSlice());

    const status = try reader.readByte();
    std.debug.print("Invalid user check: {s}\n", .{if (status == 1) "Properly handled" else "Unexpected result"});
}
