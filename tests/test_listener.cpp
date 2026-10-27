// Initialises the curve parameters once, before any test runs.
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include "core/snark.hpp"

class InitSnark : public Catch::EventListenerBase {
public:
    using Catch::EventListenerBase::EventListenerBase;
    void testRunStarting(Catch::TestRunInfo const&) override { zk::init_snark(); }
};
CATCH_REGISTER_LISTENER(InitSnark)
