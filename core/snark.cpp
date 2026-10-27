#include "snark.hpp"

#include <libff/common/profiling.hpp>

namespace zk {

void init_snark() {
    static const bool done = [] {
        // libff's enter_block/leave_block write to global tables and stdout;
        // inhibiting them makes the prover/verifier quiet and avoids races
        // on those globals when the server verifies on several threads.
        libff::inhibit_profiling_info = true;
        libff::inhibit_profiling_counters = true;
        ppT::init_public_params();
        return true;
    }();
    (void)done;
}

} // namespace zk
