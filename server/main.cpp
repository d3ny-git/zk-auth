// zkauth-server: the Crow HTTP front end of AuthService (routes.cpp).
//
//   zkauth-server [--port 8081] [--bind 0.0.0.0] [--threads 0]
//                 [--domain localhost:8080] [--uri http://localhost:8080] [--chain-id 1]
//                 [--vk keys/vk.bin] [--roots data/issuer/roots.json]
//                 [--session-key data/server/session_ed25519.pem]
//                 [--mode production|development]
//
// --threads 0 means Crow's .multithreaded() (one worker per hardware thread).
#include <crow.h>

#include <chrono>
#include <cstdio>
#include <thread>

#include "server/routes.hpp"
#include "tools/cli.hpp"

using namespace zk;
using namespace zk::server;

namespace {

crow::response to_crow(const HttpResult& r) {
    crow::response res(r.status, r.body);
    res.set_header("Content-Type", "application/json");
    for (const auto& [k, v] : r.headers) res.set_header(k, v);
    return res;
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto a = cli::Args::parse(argc, argv);
        Config cfg;
        cfg.domain = a.get("domain", cfg.domain);
        cfg.uri = a.get("uri", cfg.uri);
        cfg.chain_id = std::stoull(a.get("chain-id", std::to_string(cfg.chain_id)));
        cfg.vk_path = a.get("vk", cfg.vk_path);
        cfg.roots_path = a.get("roots", cfg.roots_path);
        cfg.session_key_path = a.get("session-key", cfg.session_key_path);
        const std::string mode = a.get("mode", "production");
        if (mode != "production" && mode != "development") throw std::runtime_error("--mode must be production or development");
        cfg.debug_reject_header = mode == "development";
        const auto port = static_cast<std::uint16_t>(std::stoi(a.get("port", "8081")));
        const unsigned threads = static_cast<unsigned>(std::stoul(a.get("threads", "0")));

        init_snark(); // before any thread exists: libff keeps curve parameters in globals
        AuthService svc(cfg);

        crow::SimpleApp app;
        app.loglevel(crow::LogLevel::Warning);
        app.server_name("zk-auth");

        CROW_ROUTE(app, "/health").methods(crow::HTTPMethod::Get)([&svc] { return to_crow(svc.health()); });
        CROW_ROUTE(app, "/nonce").methods(crow::HTTPMethod::Get)([&svc] { return to_crow(svc.nonce()); });
        CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::Post)(
            [&svc](const crow::request& req) { return to_crow(svc.login(req.body)); });
        CROW_ROUTE(app, "/verify-proof").methods(crow::HTTPMethod::Post)(
            [&svc](const crow::request& req) { return to_crow(svc.verify_proof(req.body)); });
        CROW_ROUTE(app, "/verify-sig").methods(crow::HTTPMethod::Post)(
            [&svc](const crow::request& req) { return to_crow(svc.verify_sig(req.body)); });
        CROW_ROUTE(app, "/me").methods(crow::HTTPMethod::Get)(
            [&svc](const crow::request& req) { return to_crow(svc.me(req.get_header_value("Authorization"))); });

        // Lazy expiry happens on use; this sweep bounds memory and picks up
        // newly published issuer roots.
        std::jthread sweeper([&svc](std::stop_token st) {
            while (!st.stop_requested()) {
                for (int i = 0; i < 50 && !st.stop_requested(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
                svc.maintain();
            }
        });

        std::fprintf(stderr, "zkauth-server: %s mode, domain %s, chain %llu, site_id %s, port %u, %s\n", mode.c_str(),
                     cfg.domain.c_str(), static_cast<unsigned long long>(cfg.chain_id), to_hex(svc.site_id()).c_str(),
                     port, threads == 0 ? "multithreaded" : (std::to_string(threads) + " thread(s)").c_str());
        app.bindaddr(a.get("bind", "0.0.0.0")).port(port);
        if (threads == 0) app.multithreaded();
        else app.concurrency(threads);
        app.run();
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zkauth-server: %s\n", e.what());
        return 1;
    }
}
