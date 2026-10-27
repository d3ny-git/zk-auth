#include "siwe.hpp"

#include <algorithm>
#include <chrono>

namespace zk::siwe {

namespace {

constexpr std::string_view kHeader = " wants you to sign in with your Ethereum account:";

[[noreturn]] void bad(const std::string& why) { throw FormatError("siwe: " + why); }

bool is_alnum(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

// Printable ASCII without control characters; the wallet must display exactly
// what we parse, so nothing invisible is allowed anywhere.
bool printable(std::string_view s) {
    return std::all_of(s.begin(), s.end(), [](char c) { return c >= 0x20 && c <= 0x7e; });
}

// RFC 3986 authority: host (reg-name, IPv4 or [IPv6]) with optional port.
bool valid_authority(std::string_view s) {
    if (s.empty() || s.size() > 255) return false;
    return std::all_of(s.begin(), s.end(), [](char c) {
        return is_alnum(c) || c == '.' || c == '-' || c == ':' || c == '[' || c == ']' || c == '_' || c == '~';
    });
}

// A URI: scheme ":" then printable characters without spaces.
bool valid_uri(std::string_view s) {
    const auto colon = s.find(':');
    if (colon == std::string_view::npos || colon == 0 || !is_alnum(s[0])) return false;
    for (std::size_t i = 0; i < colon; ++i)
        if (!is_alnum(s[i]) && s[i] != '+' && s[i] != '-' && s[i] != '.') return false;
    return s.size() < 2048 && printable(s) && s.find(' ') == std::string_view::npos;
}

std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> lines;
    std::size_t start = 0;
    for (;;) {
        const auto nl = text.find('\n', start);
        if (nl == std::string_view::npos) {
            lines.push_back(text.substr(start));
            return lines;
        }
        lines.push_back(text.substr(start, nl - start));
        start = nl + 1;
    }
}

std::string_view field(std::string_view line, std::string_view name) {
    if (!line.starts_with(name)) bad("expected \"" + std::string(name) + "\"");
    return line.substr(name.size());
}

int digits(std::string_view s, std::size_t pos, std::size_t n) {
    int v = 0;
    for (std::size_t i = pos; i < pos + n; ++i) {
        if (i >= s.size() || s[i] < '0' || s[i] > '9') bad("bad date-time");
        v = v * 10 + (s[i] - '0');
    }
    return v;
}

} // namespace

std::int64_t parse_rfc3339_ms(std::string_view s) {
    using namespace std::chrono;
    // YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)
    if (s.size() < 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':')
        bad("bad date-time");
    const year_month_day ymd{year{digits(s, 0, 4)}, month{unsigned(digits(s, 5, 2))}, day{unsigned(digits(s, 8, 2))}};
    const int hh = digits(s, 11, 2), mm = digits(s, 14, 2), ss = digits(s, 17, 2);
    if (!ymd.ok() || hh > 23 || mm > 59 || ss > 60) bad("bad date-time");
    std::size_t pos = 19;
    std::int64_t ms = 0;
    if (pos < s.size() && s[pos] == '.') {
        std::size_t n = 0;
        for (++pos; pos < s.size() && s[pos] >= '0' && s[pos] <= '9'; ++pos, ++n)
            if (n < 3) ms = ms * 10 + (s[pos] - '0');
        if (n == 0 || n > 9) bad("bad date-time fraction");
        for (; n < 3; ++n) ms *= 10;
    }
    std::int64_t offset_min = 0;
    if (pos < s.size() && s[pos] == 'Z') {
        ++pos;
    } else if (pos < s.size() && (s[pos] == '+' || s[pos] == '-')) {
        if (s.size() != pos + 6 || s[pos + 3] != ':') bad("bad date-time offset");
        const int oh = digits(s, pos + 1, 2), om = digits(s, pos + 4, 2);
        if (oh > 23 || om > 59) bad("bad date-time offset");
        offset_min = (s[pos] == '+' ? 1 : -1) * (oh * 60 + om);
        pos += 6;
    } else {
        bad("date-time needs Z or an offset");
    }
    if (pos != s.size()) bad("trailing characters after date-time");
    const std::int64_t days = sys_days(ymd).time_since_epoch().count();
    return ((days * 86400 + hh * 3600 + mm * 60 + std::min(ss, 59)) - offset_min * 60) * 1000 + ms;
}

Message parse(std::string_view text) {
    if (text.size() > kMaxMessageBytes) bad("message too long");
    if (text.find('\r') != std::string_view::npos) bad("CR characters are not allowed");
    const auto lines = split_lines(text);
    std::size_t i = 0;
    auto next = [&]() -> std::string_view {
        if (i >= lines.size()) bad("message ends early");
        return lines[i++];
    };
    Message m;

    // Line 1: [scheme "://"] domain " wants you to sign in with your Ethereum account:"
    std::string_view head = next();
    if (!head.ends_with(kHeader)) bad("bad first line");
    head.remove_suffix(kHeader.size());
    if (const auto sep = head.find("://"); sep != std::string_view::npos) {
        m.scheme = std::string(head.substr(0, sep));
        head.remove_prefix(sep + 3);
        if (m.scheme.empty() || !std::all_of(m.scheme.begin(), m.scheme.end(), is_alnum)) bad("bad scheme");
    }
    if (!valid_authority(head)) bad("bad domain");
    m.domain = std::string(head);

    // Line 2: the address, which EIP-4361 requires in EIP-55 checksum form.
    const std::string_view addr = next();
    auto a = eth::parse_address(addr);
    if (!a || eth::to_checksum_address(*a) != addr) bad("address must be EIP-55 checksummed");
    m.address = *a;
    m.address_text = std::string(addr);

    if (!next().empty()) bad("expected empty line after address");
    // Optional statement, framed by empty lines.
    std::string_view line = next();
    if (!line.empty()) {
        if (!printable(line)) bad("statement has non-printable characters");
        m.statement = std::string(line);
        if (!next().empty()) bad("expected empty line after statement");
    }

    m.uri = std::string(field(next(), "URI: "));
    if (!valid_uri(m.uri)) bad("bad URI");
    m.version = std::string(field(next(), "Version: "));
    if (m.version != "1") bad("unsupported version");
    const std::string_view chain = field(next(), "Chain ID: ");
    if (chain.empty() || chain.size() > 18 || !std::all_of(chain.begin(), chain.end(), [](char c) { return c >= '0' && c <= '9'; }))
        bad("bad chain id");
    // "01" and "1" would be two signed texts for one chain (found by fuzz_siwe).
    if (chain.size() > 1 && chain[0] == '0') bad("chain id has leading zeros");
    m.chain_id = std::stoull(std::string(chain));
    m.nonce = std::string(field(next(), "Nonce: "));
    if (m.nonce.size() < 8 || m.nonce.size() > 128 || !std::all_of(m.nonce.begin(), m.nonce.end(), is_alnum))
        bad("nonce must be at least 8 alphanumeric characters");
    m.issued_at = std::string(field(next(), "Issued At: "));
    m.issued_at_ms = parse_rfc3339_ms(m.issued_at);

    // Optional fields, each at most once and in this order.
    if (i < lines.size() && lines[i].starts_with("Expiration Time: ")) {
        m.expiration_time = std::string(field(next(), "Expiration Time: "));
        m.expiration_ms = parse_rfc3339_ms(*m.expiration_time);
    }
    if (i < lines.size() && lines[i].starts_with("Not Before: ")) {
        m.not_before = std::string(field(next(), "Not Before: "));
        m.not_before_ms = parse_rfc3339_ms(*m.not_before);
    }
    if (i < lines.size() && lines[i].starts_with("Request ID: ")) {
        m.request_id = std::string(field(next(), "Request ID: "));
        if (!printable(*m.request_id) || m.request_id->find(' ') != std::string::npos) bad("bad request id");
    }
    if (i < lines.size() && lines[i] == "Resources:") {
        ++i;
        while (i < lines.size() && lines[i].starts_with("- ")) {
            std::string r(lines[i++].substr(2));
            if (!valid_uri(r)) bad("bad resource URI");
            m.resources.push_back(std::move(r));
        }
        if (m.resources.empty()) bad("empty Resources list");
    }
    if (i != lines.size()) bad("unexpected trailing content");
    return m;
}

std::string format(const Message& m) {
    std::string s = (m.scheme.empty() ? "" : m.scheme + "://") + m.domain + std::string(kHeader) + "\n";
    // address LF LF [statement LF] LF: without a statement there are two empty lines.
    s += m.address_text + "\n\n";
    if (m.statement) s += *m.statement + "\n";
    s += "\n";
    s += "URI: " + m.uri + "\n";
    s += "Version: " + m.version + "\n";
    s += "Chain ID: " + std::to_string(m.chain_id) + "\n";
    s += "Nonce: " + m.nonce + "\n";
    s += "Issued At: " + m.issued_at;
    if (m.expiration_time) s += "\nExpiration Time: " + *m.expiration_time;
    if (m.not_before) s += "\nNot Before: " + *m.not_before;
    if (m.request_id) s += "\nRequest ID: " + *m.request_id;
    if (!m.resources.empty()) {
        s += "\nResources:";
        for (const auto& r : m.resources) s += "\n- " + r;
    }
    return s;
}

} // namespace zk::siwe
