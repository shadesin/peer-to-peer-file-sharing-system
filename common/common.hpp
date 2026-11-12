#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <vector>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace p2p {
using Fields = std::vector<std::string>;
constexpr size_t PIECE = 512 * 1024;
constexpr uint64_t MAX_FILE = 1024ULL * 1024 * 1024;
constexpr size_t MAX_FRAME = 1024 * 1024;
constexpr int IO_MS = 2500;
constexpr uint64_t LEASE_SECONDS = 20;
constexpr uint64_t TICKET_SECONDS = 60;

inline uint64_t now() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}
inline void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
inline uint64_t number(const std::string& s, uint64_t max = std::numeric_limits<uint64_t>::max()) {
    require(!s.empty() && s.size() <= 20, "invalid number");
    uint64_t value = 0;
    for (unsigned char c : s) {
        require(c >= '0' && c <= '9', "invalid number");
        const uint64_t digit = c - '0';
        require(digit <= max && value <= (max - digit) / 10, "number out of range");
        value = value * 10 + digit;
    }
    return value;
}
inline bool hex_string(const std::string& s, size_t n) {
    return s.size() == n && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
inline void identifier(const std::string& s) {
    require(!s.empty() && s.size() <= 64, "invalid identifier");
    for (unsigned char c : s)
        require((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.', "invalid identifier");
}
inline void filename(const std::string& s) {
    require(!s.empty() && s.size() <= 255 && s != "." && s != ".." &&
            s.find('/') == std::string::npos && s.find('\0') == std::string::npos, "invalid filename");
    for (unsigned char c : s) require(c >= 32 && c != 127, "invalid filename");
}
inline void path_string(const std::string& s) {
    require(!s.empty() && s.size() <= 4096 && s.find('\0') == std::string::npos, "invalid path");
}
inline std::string hex(const unsigned char* p, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out; out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { out += digits[p[i] >> 4]; out += digits[p[i] & 15]; }
    return out;
}
inline std::string random_id(size_t bytes = 16) {
    std::vector<unsigned char> data(bytes);
    require(RAND_bytes(data.data(), static_cast<int>(bytes)) == 1, "random generator failed");
    return hex(data.data(), data.size());
}

// Every message and every field has an explicit network-order length. No delimiter parsing.
inline void put32(std::string& out, uint32_t value) {
    value = htonl(value); out.append(reinterpret_cast<const char*>(&value), 4);
}
inline uint32_t get32(const std::string& data, size_t& offset) {
    require(offset <= data.size() && data.size() - offset >= 4, "truncated field length");
    uint32_t value; std::memcpy(&value, data.data() + offset, 4); offset += 4;
    return ntohl(value);
}
inline std::string pack(const Fields& fields) {
    require(fields.size() <= 16384, "too many fields");
    std::string out; put32(out, static_cast<uint32_t>(fields.size()));
    for (const auto& f : fields) {
        require(f.size() <= MAX_FRAME && out.size() + f.size() + 4 <= MAX_FRAME, "message too large");
        put32(out, static_cast<uint32_t>(f.size())); out += f;
    }
    return out;
}
inline Fields unpack(const std::string& data) {
    size_t offset = 0;
    uint32_t count = get32(data, offset);
    require(count <= 16384 && count <= (data.size() - offset) / 4, "invalid field count");
    Fields out; out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t length = get32(data, offset);
        require(length <= data.size() - offset, "truncated field");
        out.emplace_back(data.data() + offset, length); offset += length;
    }
    require(offset == data.size(), "trailing message bytes");
    return out;
}
inline void arity(const Fields& fields, size_t n) { require(fields.size() == n, "invalid arguments"); }

struct Fd {
    int value = -1;
    explicit Fd(int fd = -1) : value(fd) {}
    ~Fd() { if (value >= 0) ::close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value(other.value) { other.value = -1; }
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) { if (value >= 0) ::close(value); value = other.value; other.value = -1; }
        return *this;
    }
    explicit operator bool() const { return value >= 0; }
};
struct Address { std::string ip; uint16_t port; };
inline Address address(const std::string& s) {
    size_t colon = s.find(':');
    require(colon != std::string::npos, "expected IPv4:PORT");
    Address a{s.substr(0, colon), static_cast<uint16_t>(number(s.substr(colon + 1), 65535))};
    in_addr check{};
    require(a.port != 0 && inet_pton(AF_INET, a.ip.c_str(), &check) == 1, "invalid IPv4 address or port");
    return a;
}
inline std::string address_text(const Address& a) { return a.ip + ":" + std::to_string(a.port); }
inline void nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    require(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0, "fcntl failed");
}
using Deadline = std::chrono::steady_clock::time_point;
inline Deadline deadline(int ms = IO_MS) { return std::chrono::steady_clock::now() + std::chrono::milliseconds(ms); }
inline void wait_fd(int fd, short events, Deadline until) {
    while (true) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(until - std::chrono::steady_clock::now()).count();
        require(left > 0, "network timeout");
        pollfd p{fd, events, 0};
        int r = poll(&p, 1, static_cast<int>(std::min<int64_t>(left, 2147483647)));
        if (r < 0 && errno == EINTR) continue;
        require(r > 0, r == 0 ? "network timeout" : "poll failed");
        require(!(p.revents & POLLNVAL), "invalid socket");
        return; // recv/send reports EOF and connection errors, including POLLHUP.
    }
}
inline void socket_write(int fd, const char* data, size_t n, Deadline until,
                         const std::function<bool()>& cancelled = {}) {
    while (n) {
        require(!cancelled || !cancelled(), "operation cancelled");
        wait_fd(fd, POLLOUT, until);
        ssize_t sent = send(fd, data, std::min<size_t>(n, 16384), 0);
        if (sent < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        require(sent > 0, "socket write failed"); data += sent; n -= static_cast<size_t>(sent);
    }
}
inline void socket_read(int fd, char* data, size_t n, Deadline until) {
    while (n) {
        wait_fd(fd, POLLIN, until);
        ssize_t got = recv(fd, data, n, 0);
        if (got < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        require(got > 0, "connection closed or socket read failed");
        data += got; n -= static_cast<size_t>(got);
    }
}
inline void send_frame(int fd, const std::string& data, const std::function<bool()>& cancelled = {}) {
    require(data.size() <= MAX_FRAME, "message too large");
    std::string header; put32(header, static_cast<uint32_t>(data.size()));
    auto until = deadline();
    socket_write(fd, header.data(), header.size(), until, cancelled);
    socket_write(fd, data.data(), data.size(), until, cancelled);
}
inline std::string receive_frame(int fd, size_t limit = MAX_FRAME) {
    auto until = deadline();
    uint32_t n; socket_read(fd, reinterpret_cast<char*>(&n), 4, until); n = ntohl(n);
    require(n >= 4 && n <= limit, "invalid frame length");
    std::string data(n, '\0'); socket_read(fd, &data[0], n, until); return data;
}
inline Fd connect_to(const Address& a) {
    Fd fd(socket(AF_INET, SOCK_STREAM, 0)); require(static_cast<bool>(fd), "socket failed"); nonblocking(fd.value);
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons(a.port);
    require(inet_pton(AF_INET, a.ip.c_str(), &sa.sin_addr) == 1, "invalid IP");
    int r = connect(fd.value, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    if (r < 0) {
        require(errno == EINPROGRESS, "connect failed");
        wait_fd(fd.value, POLLOUT, deadline(800));
        int error = 0; socklen_t size = sizeof(error);
        require(getsockopt(fd.value, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0, "connect failed");
    }
    return fd;
}
inline Fd listen_on(const Address& a) {
    Fd fd(socket(AF_INET, SOCK_STREAM, 0)); require(static_cast<bool>(fd), "socket failed");
    int one = 1; require(setsockopt(fd.value, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0, "setsockopt failed");
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons(a.port);
    require(inet_pton(AF_INET, a.ip.c_str(), &sa.sin_addr) == 1, "invalid IP");
    require(bind(fd.value, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0, "bind failed: " + std::string(strerror(errno)));
    require(listen(fd.value, 64) == 0, "listen failed"); nonblocking(fd.value); return fd;
}
inline Fields exchange(const Address& a, const Fields& message) {
    Fd fd = connect_to(a); send_frame(fd.value, pack(message)); return unpack(receive_frame(fd.value));
}

inline void write_fd(int fd, const char* p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        require(w > 0, "file write failed: " + std::string(strerror(errno)));
        n -= static_cast<size_t>(w); p += w;
    }
}
inline std::string read_file(const std::string& path, size_t limit) {
    path_string(path); Fd fd(open(path.c_str(), O_RDONLY | O_NOFOLLOW));
    require(static_cast<bool>(fd), "cannot open " + path);
    struct stat st{}; require(fstat(fd.value, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_size >= 0 && static_cast<uint64_t>(st.st_size) <= limit, "invalid file size or type");
    std::string out; char buffer[8192];
    while (true) {
        ssize_t n = read(fd.value, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        require(n >= 0, "file read failed"); if (n == 0) break;
        require(out.size() + static_cast<size_t>(n) <= limit, "file too large"); out.append(buffer, static_cast<size_t>(n));
    }
    return out;
}
inline void sync_parent(const std::string& path) {
    auto pos = path.find_last_of('/'); std::string dir = pos == std::string::npos ? "." : (pos == 0 ? "/" : path.substr(0, pos));
    Fd fd(open(dir.c_str(), O_RDONLY)); require(static_cast<bool>(fd), "cannot open parent directory");
    require(fsync(fd.value) == 0, "directory sync failed");
}
inline void atomic_file(const std::string& path, const std::string& data) {
    std::string tmp = path + ".tmp-" + random_id();
    try {
        Fd fd(open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600));
        require(static_cast<bool>(fd), "cannot create temporary file");
        write_fd(fd.value, data.data(), data.size()); require(fsync(fd.value) == 0, "file sync failed");
        require(rename(tmp.c_str(), path.c_str()) == 0, "atomic rename failed"); sync_parent(path);
    } catch (...) { unlink(tmp.c_str()); throw; }
}
inline std::vector<Address> tracker_info(const std::string& path) {
    std::istringstream in(read_file(path, 8192)); std::string line; std::vector<Address> result;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) result.push_back(address(line));
    }
    require(result.size() == 2 && address_text(result[0]) != address_text(result[1]), "configure exactly two distinct trackers");
    return result;
}

inline std::string digest(const std::string& data, const EVP_MD* algorithm = EVP_sha1()) {
    unsigned char out[EVP_MAX_MD_SIZE]; unsigned size = 0;
    require(EVP_Digest(data.data(), data.size(), out, &size, algorithm, nullptr) == 1, "hash failed");
    return hex(out, size);
}
inline std::string mac(const std::string& key, const std::string& data) {
    unsigned char out[EVP_MAX_MD_SIZE]; unsigned size = 0;
    require(HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
        reinterpret_cast<const unsigned char*>(data.data()), data.size(), out, &size) != nullptr, "MAC failed");
    return hex(out, size);
}
inline bool equal_secret(const std::string& a, const std::string& b) {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
inline std::string password_hash(const std::string& password, const std::string& salt) {
    unsigned char out[32];
    require(PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
        reinterpret_cast<const unsigned char*>(salt.data()), static_cast<int>(salt.size()),
        100000, EVP_sha256(), sizeof(out), out) == 1, "password hash failed");
    return hex(out, sizeof(out));
}
struct SigningKey {
    std::string secret, public_key;
    explicit SigningKey(std::string seed) : secret(std::move(seed)) {
        require(secret.size() == 32, "cluster key must contain exactly 32 bytes");
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char*>(secret.data()), secret.size()), EVP_PKEY_free);
        require(static_cast<bool>(key), "signing key failed");
        public_key.resize(32); size_t n = public_key.size();
        require(EVP_PKEY_get_raw_public_key(key.get(), reinterpret_cast<unsigned char*>(&public_key[0]), &n) == 1, "public key failed");
    }
    std::string sign(const std::string& message) const {
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char*>(secret.data()), secret.size()), EVP_PKEY_free);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        require(key && ctx && EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1, "sign init failed");
        std::string signature(64, '\0'); size_t n = signature.size();
        require(EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(&signature[0]), &n,
            reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1, "signature failed");
        signature.resize(n); return signature;
    }
    std::string token(Fields fields) const { fields.push_back(sign(pack(fields))); return pack(fields); }
};
inline Fields verify_token(const std::string& token, const std::string& public_key) {
    require(public_key.size() == 32, "invalid public key");
    Fields f = unpack(token); require(!f.empty(), "invalid signed token");
    std::string signature = f.back(); f.pop_back(); require(signature.size() == 64, "invalid signature");
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char*>(public_key.data()), public_key.size()), EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(key && ctx && EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1, "verify init failed");
    std::string message = pack(f);
    require(EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char*>(signature.data()), signature.size(),
        reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1, "invalid signature");
    return f;
}

struct Metadata {
    uint64_t size = 0; std::string hash; Fields pieces;
    Fields fields() const { return {std::to_string(size), hash, pack(pieces)}; }
    static Metadata from(const Fields& f) {
        arity(f, 3); Metadata m{number(f[0], MAX_FILE), f[1], unpack(f[2])};
        require(hex_string(m.hash, 40), "invalid file hash");
        require(m.pieces.size() == (m.size + PIECE - 1) / PIECE, "piece count does not match file size");
        for (const auto& h : m.pieces) require(hex_string(h, 40), "invalid piece hash");
        return m;
    }
    size_t piece_size(size_t index) const {
        require(index < pieces.size(), "invalid piece index");
        return static_cast<size_t>(std::min<uint64_t>(PIECE, size - index * PIECE));
    }
};
inline Metadata hash_file(const std::string& path) {
    path_string(path); Fd fd(open(path.c_str(), O_RDONLY | O_NOFOLLOW));
    require(static_cast<bool>(fd), "cannot open file"); struct stat before{}, after{};
    require(fstat(fd.value, &before) == 0 && S_ISREG(before.st_mode) && before.st_size >= 0 &&
        static_cast<uint64_t>(before.st_size) <= MAX_FILE, "file must be regular and at most 1 GiB");
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(ctx && EVP_DigestInit_ex(ctx.get(), EVP_sha1(), nullptr) == 1, "hash init failed");
    Metadata m; std::string buffer(PIECE, '\0');
    while (true) {
        size_t total = 0;
        while (total < PIECE) {
            ssize_t got = read(fd.value, &buffer[total], PIECE - total);
            if (got < 0 && errno == EINTR) continue;
            require(got >= 0, "file read failed"); if (!got) break; total += static_cast<size_t>(got);
        }
        if (!total) break;
        m.size += total; require(m.size <= MAX_FILE, "file grew past 1 GiB");
        require(EVP_DigestUpdate(ctx.get(), buffer.data(), total) == 1, "hash update failed");
        m.pieces.push_back(digest(std::string(buffer.data(), total)));
    }
    unsigned char out[EVP_MAX_MD_SIZE]; unsigned n = 0;
    require(EVP_DigestFinal_ex(ctx.get(), out, &n) == 1, "hash finalize failed"); m.hash = hex(out, n);
    require(fstat(fd.value, &after) == 0 && before.st_size == after.st_size &&
        before.st_mtime == after.st_mtime && before.st_ctime == after.st_ctime &&
        m.size == static_cast<uint64_t>(after.st_size), "file changed while hashing");
#ifdef __APPLE__
    require(before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
            before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec, "file changed while hashing");
#else
    require(before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
            before.st_ctim.tv_nsec == after.st_ctim.tv_nsec, "file changed while hashing");
#endif
    return m;
}

// A bounded accept queue and fixed workers avoid a detached thread per connection.
class Server {
    Fd listener; std::atomic<bool> stopping{false}; std::mutex mutex;
    std::condition_variable ready; std::deque<int> queue; std::vector<std::thread> workers;
    std::thread acceptor; std::function<void(int)> handler;
public:
    Server(const Address& addr, std::function<void(int)> fn, size_t count = 8)
        : listener(listen_on(addr)), handler(std::move(fn)) {
        try {
            for (size_t i = 0; i < count; ++i) workers.emplace_back([this] {
                while (true) {
                    Fd socket;
                    { std::unique_lock<std::mutex> lock(mutex); ready.wait(lock, [this] { return stopping || !queue.empty(); });
                      if (stopping && queue.empty()) return; socket.value = queue.front(); queue.pop_front(); }
                    try { handler(socket.value); } catch (...) { /* A bad connection cannot terminate a worker. */ }
                }
            });
            acceptor = std::thread([this] {
                while (!stopping) {
                    pollfd p{listener.value, POLLIN, 0}; int r = poll(&p, 1, 100);
                    if (r <= 0) continue;
                    int cs = accept(listener.value, nullptr, nullptr); if (cs < 0) continue;
                    try { nonblocking(cs); } catch (...) { close(cs); continue; }
                    { std::lock_guard<std::mutex> lock(mutex);
                      if (stopping || queue.size() >= 64) { close(cs); continue; } queue.push_back(cs); }
                    ready.notify_one();
                }
            });
        } catch (...) { stop(); throw; }
    }
    Server(const Server&) = delete; Server& operator=(const Server&) = delete;
    void stop() {
        stopping = true;
        if (acceptor.joinable()) acceptor.join();
        { std::lock_guard<std::mutex> lock(mutex); for (int fd : queue) close(fd); queue.clear(); }
        ready.notify_all(); for (auto& t : workers) if (t.joinable()) t.join();
    }
    ~Server() { stop(); }
};

inline Fields tokenize(const std::string& line) {
    Fields out; std::string word; char quote = 0; bool escaped = false, started = false;
    for (char c : line) {
        if (escaped) { word += c; escaped = false; started = true; }
        else if (c == '\\') { escaped = true; started = true; }
        else if (quote) { if (c == quote) quote = 0; else word += c; }
        else if (c == '\'' || c == '"') { quote = c; started = true; }
        else if (c == ' ' || c == '\t' || c == '\r') { if (started) { out.push_back(word); word.clear(); started = false; } }
        else { word += c; started = true; }
    }
    require(!quote && !escaped, "unterminated quote or escape"); if (started) out.push_back(word);
    if (out.size() >= 2) {
        static const std::set<std::string> aliases{"create_user", "create_group", "join_group", "leave_group",
            "list_groups", "list_requests", "accept_request", "upload_file", "list_files", "download_file", "show_downloads", "stop_share"};
        std::string joined = out[0] + "_" + out[1];
        if (aliases.count(joined)) { out[0] = joined; out.erase(out.begin() + 1); }
    }
    return out;
}
} // namespace p2p
