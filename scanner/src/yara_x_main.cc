// Native scanner using the official YARA-X C API.
// License: MIT; upstream YARA-X is a separate BSD-3-Clause dependency.
#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "vulnimprint/elf.h"
#include "vulnimprint/json.h"
#include "vulnimprint/match_location.h"
#include "vulnimprint/yara_x_api.h"

namespace fs = std::filesystem;
namespace {
using ByteVec = std::vector<uint8_t>;

struct RuleDeleter {
    void operator()(YRX_RULES* rules) const {
        if (rules) yrx_rules_destroy(rules);
    }
};
struct ScannerDeleter {
    void operator()(YRX_SCANNER* scanner) const {
        if (scanner) yrx_scanner_destroy(scanner);
    }
};
struct BufferDeleter {
    void operator()(YRX_BUFFER* buffer) const {
        if (buffer) yrx_buffer_destroy(buffer);
    }
};
using Rules = std::unique_ptr<YRX_RULES, RuleDeleter>;
using Scanner = std::unique_ptr<YRX_SCANNER, ScannerDeleter>;
using Buffer = std::unique_ptr<YRX_BUFFER, BufferDeleter>;

void checked(YRX_RESULT result, const std::string& operation) {
    if (result == YRX_SUCCESS) return;
    const char* error = yrx_last_error();
    throw std::runtime_error(operation + ": " +
                             (error ? error : "YARA-X API failure"));
}

int checked_rule_count(YRX_RULES* rules) {
    const int count = yrx_rules_count(rules);
    if (count <= 0) {
        throw std::runtime_error("compiled YARA-X database has no valid rules");
    }
    return count;
}

std::string hex(std::uint64_t n) {
    std::ostringstream o;
    o << "0x" << std::hex << n;
    return o.str();
}
ByteVec read_file(const fs::path& path, std::uintmax_t max_size) {
    // Open the descriptor before checking its type and length to avoid TOCTOU.
    const int fd = ::open(path.c_str(),
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        throw std::runtime_error("cannot open regular file " + path.string());
    }
    struct Descriptor {
        int value;
        ~Descriptor() {
            if (value >= 0) ::close(value);
        }
    } descriptor{fd};

    struct stat stat_result{};
    if (::fstat(fd, &stat_result) != 0 || !S_ISREG(stat_result.st_mode) ||
        stat_result.st_size < 0 ||
        static_cast<std::uintmax_t>(stat_result.st_size) > max_size) {
        throw std::runtime_error("unreadable or above max-file-size: " +
                                 path.string());
    }
    ByteVec bytes(static_cast<std::size_t>(stat_result.st_size));
    for (std::size_t offset = 0; offset < bytes.size();) {
        const ssize_t count =
                ::read(fd, bytes.data() + offset, bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            throw std::runtime_error("short read of regular file " +
                                     path.string());
        }
        offset += static_cast<std::size_t>(count);
    }
    return bytes;
}

std::string read_text(const fs::path& path) {
    const auto bytes = read_file(path, 16ULL * 1024 * 1024);
    if (std::find(bytes.begin(), bytes.end(), 0) != bytes.end()) {
        throw std::runtime_error("NUL byte in YARA source: " + path.string());
    }
    return std::string(bytes.begin(), bytes.end());
}

Rules compile_rules(const std::vector<fs::path>& paths) {
    constexpr std::size_t kMaxSourceSize = 64ULL * 1024 * 1024;
    if (paths.empty() || paths.size() > 10000) {
        throw std::runtime_error("rule file count exceeds limit");
    }
    std::string source;
    for (const auto& path : paths) {
        const auto part = read_text(path);
        if (source.size() >= kMaxSourceSize ||
            part.size() >= kMaxSourceSize - source.size()) {
            throw std::runtime_error("combined YARA source exceeds 64 MiB");
        }
        source += part;
        source.push_back('\n');
    }
    YRX_RULES* pointer = nullptr;
    checked(yrx_compile(source.c_str(), &pointer), "yrx_compile");
    if (!pointer) throw std::runtime_error("yrx_compile returned null rules");
    return Rules(pointer);
}

Rules load_compiled(const fs::path& path, std::string& digest) {
    const auto bytes = read_file(path, 512ULL * 1024 * 1024);
    unsigned char hash[EVP_MAX_MD_SIZE]{};
    unsigned int length = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), hash, &length, EVP_sha256(),
                   nullptr) != 1 ||
        length != 32) {
        throw std::runtime_error("cannot compute DB SHA-256");
    }
    std::ostringstream output;
    for (unsigned index = 0; index < length; ++index) {
        output << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<unsigned>(hash[index]);
    }
    digest = output.str();
    YRX_RULES* pointer = nullptr;
    checked(yrx_rules_deserialize(bytes.data(), bytes.size(), &pointer),
            "deserialize");
    return Rules(pointer);
}

void save_compiled(YRX_RULES* rules, const fs::path& path) {
    YRX_BUFFER* pointer = nullptr;
    checked(yrx_rules_serialize(rules, &pointer), "serialize");
    Buffer data(pointer);
    if (!data || (data->length != 0 && data->data == nullptr)) {
        throw std::runtime_error(
                "YARA-X serialization returned invalid buffer");
    }
    std::ofstream output(path, std::ios::binary);
    if (!output || !output.write(reinterpret_cast<const char*>(data->data),
                                 static_cast<std::streamsize>(data->length))) {
        throw std::runtime_error("cannot write compiled rules " +
                                 path.string());
    }
}

struct Hit {
    std::string issue, cves, rule, pattern, evidence;
    std::size_t offset = 0, length = 0;
    bool executable = false;
    std::optional<std::uint64_t> va;
};
struct Report {
    std::string file;
    std::vector<Hit> hits;
    std::string error;
    bool truncated = false;
};
struct CallbackState {
    std::vector<Hit>* hits;
    std::string issue, cves, rule, evidence, pattern;
    std::size_t max_hits;
    std::size_t max_per_pattern = 0;
    std::size_t observed_per_pattern = 0;
    std::atomic<std::size_t>* global_hits = nullptr;
    std::size_t global_hit_limit = 100000;
    bool truncated = false;
    bool failed = false;
    size_t base_offset = 0;
    std::size_t region_length = 0;
    const std::vector<vulnimprint::Segment>* executable_regions = nullptr;
};
std::string identifier(const YRX_RULE* rule) {
    const std::uint8_t* bytes = nullptr;
    std::size_t length = 0;
    if (yrx_rule_identifier(rule, &bytes, &length) != YRX_SUCCESS || !bytes) {
        return "unnamed";
    }
    return std::string(reinterpret_cast<const char*>(bytes), length);
}

std::string pattern_id(const YRX_PATTERN* pattern) {
    const std::uint8_t* bytes = nullptr;
    std::size_t length = 0;
    if (yrx_pattern_identifier(pattern, &bytes, &length) != YRX_SUCCESS ||
        !bytes) {
        return "unnamed";
    }
    return std::string(reinterpret_cast<const char*>(bytes), length);
}

// YARA-X invokes these callbacks from Rust through a C ABI. C++ exceptions
// must never unwind through the FFI boundary (including allocation failure).
// Convert every exception into a fail-closed report, checked after each scan.
template <class F>
void ffi_guard(CallbackState* state, F&& action) noexcept {
    if (state->failed) return;
    try {
        action();
    } catch (...) {
        state->failed = true;
    }
}

void metadata_cb(const YRX_METADATA* metadata, void* user_data) noexcept {
    auto* state = static_cast<CallbackState*>(user_data);
    ffi_guard(state, [&] {
        if (!metadata || !metadata->identifier ||
            metadata->value_type != YRX_STRING || !metadata->value.string) {
            return;
        }
        const std::string key(metadata->identifier);
        if (key == "cve" || key == "issue")
            state->issue = metadata->value.string;
        if (key == "cves") state->cves = metadata->value.string;
        if (key == "evidence") state->evidence = metadata->value.string;
    });
}

void match_cb(const YRX_MATCH* match, void* user_data) noexcept {
    auto* state = static_cast<CallbackState*>(user_data);
    ffi_guard(state, [&] {
        if (!match) return;
        if (match->offset > state->region_length ||
            match->length > state->region_length - match->offset ||
            match->offset > SIZE_MAX - state->base_offset) {
            state->failed = true;
            return;
        }
        ++state->observed_per_pattern;
        // YARA-X suppresses subsequent offsets after its per-pattern cap.
        if (state->observed_per_pattern >= state->max_per_pattern) {
            state->truncated = true;
        }
        if (state->hits->size() >= state->max_hits ||
            (state->global_hits &&
             state->global_hits->load(std::memory_order_relaxed) >=
                     state->global_hit_limit)) {
            state->truncated = true;
            return;
        }
        if (state->global_hits &&
            state->global_hits->fetch_add(1, std::memory_order_relaxed) >=
                    state->global_hit_limit) {
            state->truncated = true;
            return;
        }
        Hit hit{state->issue,    state->cves,
                state->rule,     state->pattern,
                state->evidence, state->base_offset + match->offset,
                match->length,   false,
                std::nullopt};
        const auto location = vulnimprint::LocateMatch(
                *state->executable_regions, hit.offset, hit.length);
        hit.executable = location.executable;
        hit.va = location.virtual_address;
        state->hits->push_back(std::move(hit));
    });
}

void pattern_cb(const YRX_PATTERN* pattern, void* user_data) noexcept {
    auto* state = static_cast<CallbackState*>(user_data);
    ffi_guard(state, [&] {
        state->pattern = pattern_id(pattern);
        state->observed_per_pattern = 0;
        if (yrx_pattern_iter_matches(pattern, match_cb, user_data) !=
            YRX_SUCCESS) {
            state->failed = true;
        }
    });
}

void rule_cb(const YRX_RULE* rule, void* user_data) noexcept {
    auto* state = static_cast<CallbackState*>(user_data);
    ffi_guard(state, [&] {
        state->rule = identifier(rule);
        state->issue = state->rule;
        state->cves.clear();
        state->evidence.clear();
        if (yrx_rule_iter_metadata(rule, metadata_cb, user_data) !=
            YRX_SUCCESS) {
            state->failed = true;
        }
        if (!state->failed &&
            yrx_rule_iter_patterns(rule, pattern_cb, user_data) !=
                    YRX_SUCCESS) {
            state->failed = true;
        }
    });
}

std::uint64_t parse_uint(std::string_view text, std::uint64_t maximum,
                         const std::string& option) {
    std::uint64_t value = 0;
    const auto [end, error] =
            std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || error != std::errc{} ||
        end != text.data() + text.size() || value == 0 || value > maximum) {
        throw std::runtime_error("invalid value for " + option);
    }
    return value;
}

struct Config {
    std::vector<fs::path> rule_paths;
    fs::path compiled, output, target;
    std::string database_version;
    bool recursive = false, json = false, executable_only = true;
    unsigned threads = 1;
    std::size_t max_hits = 2000;
    std::size_t max_per_pattern = 256;
    std::uint64_t timeout_seconds = 10;
    std::uintmax_t max_file = 128ULL * 1024 * 1024;
};
void usage() {
    std::cerr << "Usage:\n"
              << "  vulnimprint-scan compile --rules pack/rules-exec.yar "
                 "[--rules more.yar] --output base.yarc\n"
              << "  vulnimprint-scan verify --compiled base.yarc\n"
              << "  vulnimprint-scan scan "
                 "(--rules rules.yar [--rules ...] | --compiled base.yarc) "
                 "[--recursive] [--threads N] [--all-sections] [--json] "
                 "FILE_OR_DIRECTORY\n";
}

Config parse(int argc, char** argv) {
    Config config;
    for (int index = 2; index < argc; ++index) {
        const std::string option = argv[index];
        const auto take = [&]() -> std::string {
            if (index + 1 >= argc) {
                throw std::runtime_error("argument missing after " + option);
            }
            return argv[++index];
        };
        if (option == "--rules") {
            config.rule_paths.emplace_back(take());
        } else if (option == "--compiled") {
            config.compiled = take();
        } else if (option == "--output") {
            config.output = take();
        } else if (option == "--recursive") {
            config.recursive = true;
        } else if (option == "--db-version") {
            config.database_version = take();
        } else if (option == "--json") {
            config.json = true;
        } else if (option == "--all-sections") {
            config.executable_only = false;
        } else if (option == "--threads") {
            config.threads =
                    static_cast<unsigned>(parse_uint(take(), 4, option));
        } else if (option == "--max-hits") {
            config.max_hits = parse_uint(take(), 20000, option);
        } else if (option == "--max-per-pattern") {
            config.max_per_pattern = parse_uint(take(), 1024, option);
        } else if (option == "--timeout") {
            config.timeout_seconds = parse_uint(take(), 120, option);
        } else if (option == "--max-file-mib") {
            config.max_file =
                    parse_uint(take(), 256, option) * 1024ULL * 1024ULL;
        } else if (option.starts_with("--")) {
            throw std::runtime_error("unknown option " + option);
        } else if (config.target.empty()) {
            config.target = option;
        } else {
            throw std::runtime_error("extra positional argument " + option);
        }
    }
    if (!config.database_version.empty() &&
        (config.database_version.size() > 40 ||
         config.database_version.front() != 'v' ||
         config.database_version.find_first_not_of("v0123456789.-") !=
                 std::string::npos)) {
        throw std::runtime_error("invalid --db-version");
    }
    if ((!config.compiled.empty() && !config.rule_paths.empty()) ||
        (config.compiled.empty() && config.rule_paths.empty())) {
        throw std::runtime_error("provide either --rules or --compiled");
    }
    return config;
}

std::vector<fs::path> discover(const fs::path& target, bool recursive) {
    if (!fs::exists(target)) {
        throw std::runtime_error("target not found " + target.string());
    }
    if (fs::is_symlink(target)) {
        throw std::runtime_error("symlink input denied");
    }
    if (fs::is_regular_file(target)) return {target};
    if (!fs::is_directory(target)) {
        throw std::runtime_error("target is not a regular file/directory");
    }
    std::vector<fs::path> paths;
    const auto add_entry = [&](const fs::directory_entry& entry) {
        if (entry.is_symlink()) {
            throw std::runtime_error(
                    "directory scan incomplete: symlink entry denied " +
                    entry.path().string());
        }
        if (entry.is_directory()) return;
        if (!entry.is_regular_file()) {
            throw std::runtime_error(
                    "directory scan incomplete: non-regular entry " +
                    entry.path().string());
        }
        paths.push_back(entry.path());
        if (paths.size() > 10000) {
            throw std::runtime_error("too many files (limit 10000)");
        }
    };
    if (recursive) {
        for (const auto& entry : fs::recursive_directory_iterator(target)) {
            add_entry(entry);
        }
    } else {
        for (const auto& entry : fs::directory_iterator(target)) {
            add_entry(entry);
        }
    }
    if (paths.empty()) {
        throw std::runtime_error("directory contains no regular files to scan");
    }
    std::sort(paths.begin(), paths.end());
    return paths;
}

Report process(const fs::path& path, YRX_SCANNER* scanner,
               CallbackState& context, const Config& config) {
    Report report;
    report.file = path.native();
    try {
        const auto bytes = read_file(path, config.max_file);
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(config.timeout_seconds);
        context.hits = &report.hits;
        context.max_hits = config.max_hits;
        context.max_per_pattern = config.max_per_pattern;
        context.truncated = false;
        context.failed = false;
        // Even the diagnostic whole-file mode only accepts a supported ELF;
        // it does not turn unknown formats into successful clean scans.
        const auto regions = vulnimprint::executable_regions(bytes);
        context.executable_regions = &regions;
        if (config.executable_only) {
            // Only code ranges are scanned, never DWARF or read-only data.
            for (const auto& region : regions) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    throw std::runtime_error("per-file deadline exceeded");
                }
                context.base_offset = region.offset;
                // Classification and addresses are resolved from file spans
                // by match_cb for both scanning modes.
                context.region_length = region.length;
                checked(yrx_scanner_scan(scanner, bytes.data() + region.offset,
                                         region.length),
                        "scan " + path.string());
                if (context.failed) {
                    throw std::runtime_error("pattern match iteration failed");
                }
            }
        } else {
            context.base_offset = 0;
            // Classification and addresses are resolved by match_cb.
            context.region_length = bytes.size();
            checked(yrx_scanner_scan(scanner, bytes.data(), bytes.size()),
                    "scan " + path.string());
            if (context.failed) {
                throw std::runtime_error("pattern match iteration failed");
            }
        }
        report.truncated = context.truncated;
        std::sort(report.hits.begin(), report.hits.end(),
                  [](const Hit& lhs, const Hit& rhs) {
                      return std::tie(lhs.issue, lhs.offset, lhs.pattern) <
                             std::tie(rhs.issue, rhs.offset, rhs.pattern);
                  });
    } catch (const std::exception& error) {
        report.error = error.what();
        report.hits.clear();
    }
    return report;
}

void print_hit(std::ostream& output, const Hit& hit) {
    output << "{\"cve\":" << vulnimprint::JsonString(hit.issue) << ",\"cves\":"
           << vulnimprint::JsonString(hit.cves.empty() ? hit.issue : hit.cves)
           << ",\"rule\":" << vulnimprint::JsonString(hit.rule)
           << ",\"pattern\":" << vulnimprint::JsonString(hit.pattern)
           << ",\"file_offset\":" << vulnimprint::JsonString(hex(hit.offset))
           << ",\"length\":" << hit.length
           << ",\"evidence\":" << vulnimprint::JsonString(hit.evidence)
           << ",\"executable\":" << (hit.executable ? "true" : "false")
           << ",\"virtual_address\":";
    if (hit.va) {
        output << vulnimprint::JsonString(hex(*hit.va));
    } else {
        output << "null";
    }
    output << '}';
}

void print_report(std::ostream& output, const Report& report) {
    output << "{\"file\":" << vulnimprint::JsonString(report.file)
           << ",\"file_bytes_hex\":"
           << vulnimprint::JsonString(vulnimprint::HexBytes(report.file))
           << ",\"error\":";
    if (report.error.empty()) {
        output << "null";
    } else {
        output << vulnimprint::JsonString(report.error);
    }
    output << ",\"truncated\":" << (report.truncated ? "true" : "false")
           << ",\"matches\":[";
    for (std::size_t index = 0; index < report.hits.size(); ++index) {
        if (index != 0) output << ',';
        print_hit(output, report.hits[index]);
    }
    output << "]}";
}

void print_json(const std::vector<Report>& results, std::size_t rules_count,
                unsigned threads, const std::string& database_sha256,
                const std::string& database_version) {
    std::size_t errors = 0;
    std::size_t truncated = 0;
    std::size_t hits = 0;
    std::set<std::string> unique_cves;
    for (const auto& result : results) {
        if (!result.error.empty()) ++errors;
        if (result.truncated) ++truncated;
        hits += result.hits.size();
        for (const auto& hit : result.hits) unique_cves.insert(hit.issue);
    }
    std::ostream& output = std::cout;
    output << "{\"schema\":\"vulnimprint.scan.yarax.v1\""
           << ",\"engine\":\"yara-x\",\"rules\":" << rules_count
           << ",\"threads\":" << threads
           << ",\"files_scanned\":" << results.size()
           << ",\"errors\":" << errors << ",\"truncated_files\":" << truncated
           << ",\"pattern_hits\":" << hits
           << ",\"cve_count\":" << unique_cves.size() << ",\"unique_cves\":[";
    bool first = true;
    for (const auto& cve : unique_cves) {
        if (!first) output << ',';
        first = false;
        output << vulnimprint::JsonString(cve);
    }
    output << "],\"db_sha256\":";
    if (database_sha256.empty()) {
        output << "null";
    } else {
        output << vulnimprint::JsonString(database_sha256);
    }
    output << ",\"db_version\":";
    if (database_version.empty()) {
        output << "null";
    } else {
        output << vulnimprint::JsonString(database_version);
    }
    output << ",\"results\":[";
    for (std::size_t index = 0; index < results.size(); ++index) {
        if (index != 0) output << ',';
        print_report(output, results[index]);
    }
    output << "]}\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 3) {
            usage();
            return 2;
        }
        const std::string command = argv[1];
        if (command != "compile" && command != "scan" && command != "verify") {
            usage();
            return 2;
        }
        const Config config = parse(argc, argv);
        std::string database_sha256;
        Rules rules = config.compiled.empty()
                              ? compile_rules(config.rule_paths)
                              : load_compiled(config.compiled, database_sha256);
        const int rule_count = checked_rule_count(rules.get());
        if (command == "compile") {
            if (config.output.empty() || !config.compiled.empty() ||
                !config.target.empty()) {
                throw std::runtime_error("compile needs --rules and --output");
            }
            save_compiled(rules.get(), config.output);
            std::cout << "Compiled " << rule_count << " rules into "
                      << config.output.string() << '\n';
            return 0;
        }
        if (command == "verify") {
            if (config.compiled.empty() || !config.rule_paths.empty() ||
                !config.target.empty() || !config.output.empty()) {
                throw std::runtime_error(
                        "verify requires --compiled and no target");
            }
            std::cout << "{\"engine\":\"yara-x\",\"rules\":" << rule_count
                      << ",\"db_sha256\":"
                      << vulnimprint::JsonString(database_sha256) << "}\n";
            return 0;
        }
        if (config.target.empty() || !config.output.empty()) {
            throw std::runtime_error(
                    "scan needs FILE_OR_DIRECTORY, not --output");
        }
        const auto paths = discover(config.target, config.recursive);
        std::vector<Report> reports(paths.size());
        std::atomic<std::size_t> next{0};
        std::atomic<std::size_t> global_hits{0};
        std::exception_ptr worker_error;
        std::mutex worker_error_mutex;

        const auto mark_error = [&](std::string_view message) {
            while (true) {
                const std::size_t index = next.fetch_add(1);
                if (index >= paths.size()) break;
                reports[index].file = paths[index].native();
                reports[index].error = message;
            }
        };
        const auto worker = [&]() {
            try {
                YRX_SCANNER* pointer = nullptr;
                if (yrx_scanner_create(rules.get(), &pointer) != YRX_SUCCESS ||
                    !pointer) {
                    mark_error("cannot create YARA-X scanner");
                    return;
                }
                Scanner scanner(pointer);
                CallbackState context{};
                context.global_hits = &global_hits;
                if (yrx_scanner_set_timeout(scanner.get(),
                                            config.timeout_seconds) !=
                            YRX_SUCCESS ||
                    yrx_scanner_max_matches_per_pattern(
                            scanner.get(), config.max_per_pattern) !=
                            YRX_SUCCESS) {
                    mark_error("cannot set YARA-X scanner limits");
                    return;
                }
                if (yrx_scanner_on_matching_rule(scanner.get(), rule_cb,
                                                 &context) != YRX_SUCCESS) {
                    mark_error("cannot register YARA-X callback");
                    return;
                }
                while (true) {
                    const std::size_t index = next.fetch_add(1);
                    if (index >= paths.size()) break;
                    reports[index] = process(paths[index], scanner.get(),
                                             context, config);
                }
            } catch (...) {
                std::lock_guard<std::mutex> lock(worker_error_mutex);
                if (!worker_error) worker_error = std::current_exception();
            }
        };

        // jthread provides exception-safe cleanup during partial construction.
        const std::size_t count =
                std::min<std::size_t>(config.threads, paths.size());
        std::vector<std::jthread> workers;
        workers.reserve(count);
        for (std::size_t index = 0; index < count; ++index) {
            workers.emplace_back(worker);
        }
        for (auto& worker_thread : workers) worker_thread.join();
        if (worker_error) std::rethrow_exception(worker_error);

        if (config.json) {
            print_json(reports, static_cast<std::size_t>(rule_count),
                       static_cast<unsigned>(count), database_sha256,
                       config.database_version);
        } else {
            for (const auto& report : reports) {
                std::cout << report.file << ": " << report.hits.size()
                          << " pattern hit(s)";
                if (!report.error.empty()) {
                    std::cout << " ERROR: " << report.error;
                }
                if (report.truncated) {
                    std::cout << " POSSIBLY TRUNCATED: per-pattern, per-file "
                                 "or global hit limit reached";
                }
                std::cout << '\n';
            }
        }
        const bool incomplete = std::any_of(
                reports.begin(), reports.end(), [](const Report& report) {
                    return !report.error.empty() || report.truncated;
                });
        return incomplete ? 2 : 0;
    } catch (const std::exception& error) {
        std::cerr << "vulnimprint-scan: " << error.what() << '\n';
        return 2;
    }
}
