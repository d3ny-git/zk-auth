// Minimal "--key value" argument parsing for the command-line tools.
#pragma once

#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace zk::cli {

struct Args {
    std::vector<std::string> positional;
    std::map<std::string, std::string> opts;

    static Args parse(int argc, char** argv, int first = 1) {
        Args a;
        for (int i = first; i < argc; ++i) {
            std::string s = argv[i];
            if (s.starts_with("--")) {
                s = s.substr(2);
                const bool has_value = i + 1 < argc && !std::string(argv[i + 1]).starts_with("--");
                a.opts[s] = has_value ? argv[++i] : "";
            } else {
                a.positional.push_back(s);
            }
        }
        return a;
    }
    bool has(const std::string& k) const { return opts.count(k) != 0; }
    std::string get(const std::string& k, const std::string& def) const {
        auto it = opts.find(k);
        return it == opts.end() ? def : it->second;
    }
    std::string require(const std::string& k) const {
        auto it = opts.find(k);
        if (it == opts.end() || it->second.empty()) throw std::runtime_error("missing --" + k);
        return it->second;
    }
};

} // namespace zk::cli
