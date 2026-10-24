#include "frame_contract.hpp"
#include <cassert>
int main() {
  using namespace protocol_lab;
  assert(gc_time_bytes == 9);
  assert(gc_effect_bytes == 6);
  assert(valid_npc_length(39005, 500));
  assert(!valid_npc_length(39005, 499));
  assert(valid_land_length(435));
  assert(!valid_land_length(436));
}
