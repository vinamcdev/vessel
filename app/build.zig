const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const server = b.addExecutable(.{
        .name = "server",
        .root_source_file = .{ .cwd_relative = "server/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(server);

    const client = b.addExecutable(.{
        .name = "client",
        .root_source_file = .{ .cwd_relative = "client/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(client);
}
