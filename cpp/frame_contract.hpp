#pragma once
#include <cstddef>
#include <cstdint>
// Test-only, self-written facts about a pinned 64-bit wire ABI.
// This is NOT the private project's C++ code or a packet cryptosystem.
namespace protocol_lab {
constexpr std::size_t gc_time_bytes = 1 + sizeof(std::int64_t);
constexpr std::size_t gc_effect_bytes = 1 + 1 + sizeof(std::uint32_t);
constexpr std::size_t gc_point_change_bytes = 4 + 4 + 1 + 4 + 4;
constexpr std::size_t gc_npc_header_bytes = 5;
constexpr std::size_t gc_npc_record_bytes = 78;
constexpr std::size_t gc_land_header_bytes = 3;
constexpr std::size_t gc_land_record_bytes = 24;
constexpr bool valid_npc_length(std::uint32_t size, std::uint32_t count) {
  return size == gc_npc_header_bytes + count * gc_npc_record_bytes && size <= 65535;
}
constexpr bool valid_land_length(std::uint32_t size) {
  return size >= 3 && size <= 65535 && (size - 3) % gc_land_record_bytes == 0;
}
static_assert(gc_time_bytes == 9, "GC106 must be 9B on ARM64 time_t ABI");
static_assert(gc_effect_bytes == 6, "GC114 must be six bytes");
static_assert(gc_point_change_bytes == 17, "GC17 is a four-byte header");
static_assert(valid_npc_length(5 + 78 * 47, 47));
static_assert(!valid_npc_length(5 + 78 * 47, 46));
static_assert(valid_land_length(3 + 24 * 18));
}
