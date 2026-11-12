#include "../common/common.hpp"

using namespace p2p;
namespace {
std::mutex output_mutex;
void print(const std::string& s) { std::lock_guard<std::mutex> lock(output_mutex); std::cout << s << std::endl; }

class Rpc {
    std::vector<Address> trackers;
    std::string public_key;
public:
    explicit Rpc(std::vector<Address> a) : trackers(std::move(a)) {
        std::string last;
        for (const auto& tracker : trackers) {
            try {
                auto hello = p2p::exchange(tracker, {"HELLO"}); arity(hello, 3);
                require(hello[0] == "OK" && hello[1] == "P2P/2" && hello[2].size() == 32, "invalid tracker greeting");
                public_key = hello[2];
                std::string pin = ".p2p-public-key-" + digest(pack({address_text(trackers[0]), address_text(trackers[1])}), EVP_sha256());
                Fd file(open(pin.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600));
                if (file) { write_fd(file.value, public_key.data(), public_key.size()); require(fsync(file.value) == 0, "public key sync failed"); }
                else { require(errno == EEXIST, "cannot create public key pin"); require(read_file(pin, 32) == public_key, "tracker public key changed; inspect cluster configuration"); }
                print("Connected to tracker " + address_text(tracker)); return;
            } catch (const std::exception& e) { last = e.what(); }
        }
        throw std::runtime_error("no trusted tracker available: " + last);
    }
    const std::string& key() const { return public_key; }
    Fields call(const std::string& command, const Fields& args, const std::string& token = {}, std::string rid = {}) const {
        if (rid.empty()) rid = random_id();
        Fields request{"RPC", rid, token, command, pack(args)};
        std::string last;
        for (int round = 0; round < 2; ++round) for (const auto& tracker : trackers) {
            try {
                Fields response = p2p::exchange(tracker, request); arity(response, 4);
                require(response[0] == "SIGNED" && response[1] == rid, "invalid tracker response envelope");
                auto verified = verify_token(pack({rid, response[2], response[3]}), public_key);
                arity(verified, 2); require(verified[0] == rid && verified[1] == response[2], "response identity mismatch");
                Fields result = unpack(response[2]); require(result.size() >= 2, "invalid tracker response");
                if (result[0] == "ERROR") throw std::domain_error(result[1]);
                require(result[0] == "OK", "invalid response status"); return result;
            } catch (const std::domain_error&) { throw; }
              catch (const std::exception& e) { last = e.what(); }
        }
        throw std::runtime_error("trackers unavailable: " + last);
    }
};
struct Share { std::string path; Metadata metadata; };
struct Job {
    std::string uid, token, gid, name, destination;
    Metadata metadata;
    std::atomic<size_t> done{0};
    std::atomic<bool> cancel{false}, finished{false};
    std::string error;
    bool completed = false;
    std::mutex mutex;
    std::thread thread;
    ~Job() { if (thread.joinable()) thread.join(); }
};
struct History { std::string uid, gid, name, path, hash; uint64_t size; };
class Client {
    Address endpoint;
    Rpc rpc;
    std::mutex state_mutex;
    std::string token, uid;
    uint64_t active_until = 0;
    std::map<std::pair<std::string, std::string>, Share> shares;
    std::vector<std::shared_ptr<Job>> jobs;
    std::vector<History> history;
    std::string history_path;
    std::atomic<bool> stopping{false};
    std::thread heartbeat;
    std::unique_ptr<Server> server;
    std::mutex slots_mutex;
    std::condition_variable slots_ready;
    unsigned slots_used = 0;

    bool same_session(const std::string& session) {
        std::lock_guard<std::mutex> lock(state_mutex);
        return !stopping && !token.empty() && token == session && active_until > now();
    }
    std::pair<std::string, std::string> auth() {
        std::lock_guard<std::mutex> lock(state_mutex); require(!token.empty(), "not logged in"); return {uid, token};
    }
    void deactivate(const std::string& expected) {
        std::lock_guard<std::mutex> lock(state_mutex);
        if (token != expected) return;
        token.clear(); uid.clear(); active_until = 0; shares.clear();
        for (const auto& job : jobs) job->cancel = true;
        slots_ready.notify_all();
    }
    void save_history_locked() {
        Fields records;
        for (const auto& h : history) records.push_back(pack({h.uid, h.gid, h.name, h.path, h.hash, std::to_string(h.size)}));
        atomic_file(history_path, pack(records));
    }
    void load_history() {
        struct stat st{};
        if (lstat(history_path.c_str(), &st) < 0) { require(errno == ENOENT, "cannot stat download history"); return; }
        try {
            auto records = unpack(read_file(history_path, MAX_FRAME)); require(records.size() <= 1000, "too many history records");
            for (const auto& record : records) {
                auto f = unpack(record); arity(f, 6); identifier(f[0]); identifier(f[1]); filename(f[2]); path_string(f[3]);
                require(hex_string(f[4], 40), "invalid history hash"); history.push_back({f[0], f[1], f[2], f[3], f[4], number(f[5], MAX_FILE)});
            }
        } catch (const std::exception& e) { print(std::string("WARNING download history ignored: ") + e.what()); history.clear(); }
    }
    void handle_peer(int fd) {
        try {
            auto request = unpack(receive_frame(fd, 16384)); arity(request, 5);
            require(request[0] == "GET", "unknown peer command");
            auto ticket = verify_token(request[1], rpc.key()); arity(ticket, 8);
            require(ticket[0] == "TICKET" && number(ticket[7]) > now() &&
                number(ticket[7]) <= now() + TICKET_SECONDS + 5 && ticket[3] == request[2] && ticket[5] == request[3], "invalid or expired download ticket");
            size_t index = static_cast<size_t>(number(request[4], MAX_FILE / PIECE));
            std::string session; Share share;
            {
                std::lock_guard<std::mutex> lock(state_mutex);
                require(!token.empty() && active_until > now(), "seeder is logged out");
                auto found = shares.find({request[2], ticket[4]}); require(found != shares.end(), "file is not shared in this group");
                require(found->second.metadata.hash == request[3] && found->second.metadata.size == number(ticket[6], MAX_FILE), "content identity mismatch");
                share = found->second; session = token;
            }
            rpc.call("authorize_piece", {request[1]}, session);
            size_t length = share.metadata.piece_size(index);
            Fd file(open(share.path.c_str(), O_RDONLY | O_NOFOLLOW)); require(static_cast<bool>(file), "shared file unavailable");
            struct stat st{}; require(fstat(file.value, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0 &&
                static_cast<uint64_t>(st.st_size) == share.metadata.size, "shared file size changed");
            std::string data(length, '\0'); size_t total = 0;
            while (total < length) {
                ssize_t got = pread(file.value, &data[total], length - total, static_cast<off_t>(index * PIECE + total));
                if (got < 0 && errno == EINTR) continue;
                require(got > 0, "cannot read complete piece"); total += static_cast<size_t>(got);
            }
            require(digest(data) == share.metadata.pieces[index], "shared file content changed");
            auto cancelled = [&] {
                std::lock_guard<std::mutex> lock(state_mutex);
                return stopping || token != session || active_until <= now() ||
                    !shares.count({request[2], ticket[4]});
            };
            send_frame(fd, pack({"OK", data}), cancelled);
        } catch (const std::exception& e) { try { send_frame(fd, pack({"ERROR", e.what()})); } catch (...) {} }
    }
    void renew() {
        while (!stopping) {
            std::string session;
            { std::lock_guard<std::mutex> lock(state_mutex); session = token; }
            if (!session.empty()) {
                try {
                    auto response = rpc.call("heartbeat", {}, session); arity(response, 3);
                    std::lock_guard<std::mutex> lock(state_mutex);
                    if (token == session) active_until = number(response[2]);
                } catch (const std::domain_error& e) {
                    deactivate(session); print(std::string("ERROR session ended: ") + e.what());
                } catch (const std::exception&) {
                    // The confirmed lease expires locally even if both trackers are unreachable.
                }
            }
            for (int i = 0; i < 40 && !stopping; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    void reap() {
        std::vector<std::shared_ptr<Job>> completed;
        { std::lock_guard<std::mutex> lock(state_mutex); for (const auto& j : jobs) if (j->finished) completed.push_back(j); }
        for (const auto& job : completed) if (job->thread.joinable()) job->thread.join();
    }
    void show_downloads() {
        auto who = auth(); std::ostringstream out;
        std::lock_guard<std::mutex> lock(state_mutex); std::set<std::string> shown;
        for (const auto& job : jobs) {
            if (job->uid != who.first) continue;
            std::lock_guard<std::mutex> job_lock(job->mutex);
            shown.insert(pack({job->gid, job->name, job->destination}));
            if (job->completed) out << "[C] [" << job->gid << "] " << job->name << '\n';
            else if (job->finished) out << "[F] [" << job->gid << "] " << job->name << " " << job->error << '\n';
            else {
                size_t total = job->metadata.pieces.size(), done = job->done.load();
                out << "[D] [" << job->gid << "] " << job->name << " " << (total ? done * 100 / total : 0) << "%\n";
            }
        }
        for (const auto& h : history) {
            if (h.uid != who.first || shown.count(pack({h.gid, h.name, h.path}))) continue;
            struct stat st{};
            if (stat(h.path.c_str(), &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0 && static_cast<uint64_t>(st.st_size) == h.size)
                out << "[C] [" << h.gid << "] " << h.name << '\n';
        }
        print(out.str().empty() ? "No downloads" : out.str());
    }
    void acquire_slot(const std::shared_ptr<Job>& job) {
        std::unique_lock<std::mutex> lock(slots_mutex);
        slots_ready.wait(lock, [&] { return slots_used < 8 || stopping || job->cancel; });
        require(!stopping && !job->cancel, "download cancelled"); ++slots_used;
    }
    void release_slot() { { std::lock_guard<std::mutex> lock(slots_mutex); --slots_used; } slots_ready.notify_one(); }
    std::string download_piece(const Address& peer, const std::string& ticket, const std::shared_ptr<Job>& job, size_t piece) {
        Fd fd = connect_to(peer);
        send_frame(fd.value, pack({"GET", ticket, job->gid, job->metadata.hash, std::to_string(piece)}));
        auto response = unpack(receive_frame(fd.value, PIECE + 4096)); arity(response, 2);
        require(response[0] == "OK", "peer rejected request: " + response[1]);
        require(response[1].size() == job->metadata.piece_size(piece), "incorrect piece length");
        require(digest(response[1]) == job->metadata.pieces[piece], "corrupted piece"); return response[1];
    }
    void download(const std::shared_ptr<Job>& job) {
        std::string temporary;
        try {
            auto response = rpc.call("download_file", {job->gid, job->name}, job->token); arity(response, 5);
            Metadata metadata = Metadata::from(unpack(response[2]));
            auto addresses = unpack(response[3]); require(!addresses.empty() && addresses.size() <= 4096, "invalid peers");
            std::vector<Address> peers; for (const auto& a : addresses) peers.push_back(address(a));
            auto ticket_claims = verify_token(response[4], rpc.key()); arity(ticket_claims, 8);
            require(ticket_claims[0] == "TICKET" && ticket_claims[3] == job->gid && ticket_claims[4] == job->name &&
                ticket_claims[5] == metadata.hash && number(ticket_claims[6], MAX_FILE) == metadata.size && number(ticket_claims[7]) > now(), "metadata ticket mismatch");
            { std::lock_guard<std::mutex> lock(job->mutex); job->metadata = metadata; }
            require(same_session(job->token) && !job->cancel, "download cancelled or session expired");
            auto slash = job->destination.find_last_of('/');
            std::string directory = slash == std::string::npos ? "." :
                (slash == 0 ? "/" : job->destination.substr(0, slash));
            temporary = directory + "/.p2p-" + random_id() + ".part";
            Fd file(open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600)); require(static_cast<bool>(file), "cannot create destination temporary file");
            require(ftruncate(file.value, static_cast<off_t>(metadata.size)) == 0, "cannot allocate destination");
            std::atomic<size_t> next{0}; std::atomic<bool> failed{false};
            std::mutex failure_mutex, ticket_mutex; std::string failure, ticket = response[4]; uint64_t ticket_expiry = number(ticket_claims[7]);
            auto worker = [&] {
                try {
                    while (!failed && !job->cancel && !stopping) {
                        size_t index = next.fetch_add(1); if (index >= metadata.pieces.size()) return;
                        acquire_slot(job);
                        struct Slot { Client* client; ~Slot() { client->release_slot(); } } slot{this};
                        bool done = false; std::string last;
                        for (int round = 0; round < 2 && !done; ++round) for (size_t offset = 0; offset < peers.size() && !done; ++offset) {
                            require(!failed && !job->cancel && same_session(job->token), "download cancelled or session expired");
                            size_t selected = (index + offset) % peers.size();
                            try {
                                std::string current_ticket;
                                { std::lock_guard<std::mutex> lock(ticket_mutex);
                                  if (ticket_expiry <= now() + 5) {
                                      auto updated = rpc.call("download_file", {job->gid, job->name}, job->token); arity(updated, 5);
                                      require(Metadata::from(unpack(updated[2])).fields() == metadata.fields(), "file identity changed during download");
                                      auto claims = verify_token(updated[4], rpc.key()); arity(claims, 8);
                                      require(claims[3] == job->gid && claims[4] == job->name && claims[5] == metadata.hash, "invalid refreshed ticket");
                                      ticket = updated[4]; ticket_expiry = number(claims[7]);
                                  }
                                  current_ticket = ticket; }
                                auto data = download_piece(peers[selected], current_ticket, job, index); size_t written = 0;
                                while (written < data.size()) {
                                    ssize_t n = pwrite(file.value, data.data() + written, data.size() - written, static_cast<off_t>(index * PIECE + written));
                                    if (n < 0 && errno == EINTR) continue;
                                    require(n > 0, "destination write failed"); written += static_cast<size_t>(n);
                                }
                                job->done++; done = true;
                                print("Downloaded piece " + std::to_string(index) + " of " + job->name + " from " + address_text(peers[selected]));
                            } catch (const std::exception& e) { last = e.what(); }
                        }
                        require(done, "piece " + std::to_string(index) + " failed: " + last);
                    }
                } catch (const std::exception& e) { failed = true; std::lock_guard<std::mutex> lock(failure_mutex); if (failure.empty()) failure = e.what(); }
            };
            std::vector<std::thread> workers;
            try {
                for (size_t i = 0; i < std::min<size_t>(4, metadata.pieces.size()); ++i) workers.emplace_back(worker);
            } catch (...) { failed = true; for (auto& t : workers) t.join(); throw; }
            for (auto& t : workers) t.join();
            require(!failed, failure.empty() ? "download failed" : failure);
            require(!job->cancel && same_session(job->token), "download cancelled or session expired");
            require(job->done == metadata.pieces.size(), "incomplete download");
            require(fsync(file.value) == 0, "destination sync failed");
            auto actual = hash_file(temporary); require(actual.fields() == metadata.fields(), "final file hash mismatch");
            require(!job->cancel && same_session(job->token), "download cancelled or session expired");
            // link() publishes only if the destination is absent: an existing file is never overwritten.
            require(link(temporary.c_str(), job->destination.c_str()) == 0, "cannot publish destination (it may already exist)");
            require(unlink(temporary.c_str()) == 0, "cannot remove temporary link"); temporary.clear(); sync_parent(job->destination);
            { std::lock_guard<std::mutex> lock(job->mutex); job->completed = true; }
            try {
                std::lock_guard<std::mutex> lock(state_mutex);
                history.erase(std::remove_if(history.begin(), history.end(), [&](const History& h) {
                    return h.uid == job->uid && h.gid == job->gid && h.name == job->name && h.path == job->destination;
                }), history.end());
                if (history.size() == 1000) history.erase(history.begin());
                history.push_back({job->uid, job->gid, job->name, job->destination, metadata.hash, metadata.size}); save_history_locked();
            } catch (const std::exception& e) { print(std::string("WARNING cannot persist download history: ") + e.what()); }
            print("SUCCESS file downloaded to " + job->destination);
            try {
                require(same_session(job->token) && !job->cancel, "session ended before seeder registration");
                rpc.call("upload_file", {job->gid, job->name, pack(metadata.fields())}, job->token);
                { std::lock_guard<std::mutex> lock(state_mutex);
                  require(token == job->token && active_until > now(), "session ended before sharing");
                  shares[{job->gid, job->name}] = {job->destination, metadata}; }
                print("[Client] Now sharing " + job->name + " -> " + job->destination);
                print("[Client] Tracker registered you as seeder");
            } catch (const std::exception& e) { print(std::string("WARNING downloaded successfully; seeder registration failed: ") + e.what()); }
        } catch (const std::exception& e) {
            { std::lock_guard<std::mutex> lock(job->mutex); job->error = e.what(); }
            print("ERROR download " + job->name + ": " + e.what());
        }
        if (!temporary.empty() && unlink(temporary.c_str()) < 0 && errno != ENOENT) print("WARNING could not remove " + temporary);
        job->finished = true; slots_ready.notify_all();
    }
    void start_download(const Fields& args) {
        arity(args, 3); identifier(args[0]); filename(args[1]); path_string(args[2]); auto who = auth(); reap();
        std::string destination = args[2]; struct stat st{};
        if (stat(destination.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) destination += "/" + args[1];
        path_string(destination);
        require(lstat(destination.c_str(), &st) < 0 && errno == ENOENT, "destination exists or cannot be inspected");
        auto job = std::make_shared<Job>(); job->uid = who.first; job->token = who.second; job->gid = args[0]; job->name = args[1]; job->destination = destination;
        {
            std::lock_guard<std::mutex> lock(state_mutex); size_t active = 0;
            for (const auto& other : jobs) if (!other->finished) {
                ++active; require(other->gid != job->gid || other->name != job->name, "file already downloading");
                require(other->destination != destination, "destination already in use");
            }
            require(active < 4 && jobs.size() < 1000, "download job limit reached"); jobs.push_back(job);
        }
        try { job->thread = std::thread([this, job] { download(job); }); }
        catch (...) { job->finished = true; throw; }
        print("SUCCESS download started: " + job->name);
    }
public:
    Client(Address a, std::vector<Address> trackers) : endpoint(std::move(a)), rpc(std::move(trackers)),
        history_path(".p2p-downloads-" + endpoint.ip + "-" + std::to_string(endpoint.port)) {
        load_history(); server = std::make_unique<Server>(endpoint, [&](int fd) { handle_peer(fd); });
        heartbeat = std::thread([this] { renew(); });
        print("[Client] Peer listener started on " + address_text(endpoint));
    }
    void command(Fields fields) {
        require(!fields.empty(), "empty command"); std::string cmd = fields[0]; fields.erase(fields.begin()); reap();
        if (cmd == "show_downloads") { arity(fields, 0); show_downloads(); return; }
        if (cmd == "download_file") { start_download(fields); return; }
        if (cmd == "login") {
            arity(fields, 2);
            { std::lock_guard<std::mutex> lock(state_mutex); require(token.empty(), "already logged in; logout first"); }
            auto response = rpc.call(cmd, {fields[0], fields[1], address_text(endpoint)}); arity(response, 4);
            auto claims = verify_token(response[2], rpc.key()); arity(claims, 5);
            require(claims[0] == "SESSION" && claims[1] == fields[0] && claims[3] == address_text(endpoint) && response[3] == rpc.key(), "invalid session token");
            { std::lock_guard<std::mutex> lock(state_mutex); token = response[2]; uid = fields[0]; active_until = now() + LEASE_SECONDS; }
            print("SUCCESS " + response[1]); return;
        }
        if (cmd == "create_user") { auto response = rpc.call(cmd, fields); print("SUCCESS " + response[1]); return; }
        auto who = auth();
        if (cmd == "upload_file") {
            arity(fields, 2); identifier(fields[0]); path_string(fields[1]);
            size_t slash = fields[1].find_last_of('/'); std::string name = slash == std::string::npos ? fields[1] : fields[1].substr(slash + 1); filename(name);
            Metadata metadata = hash_file(fields[1]); auto response = rpc.call(cmd, {fields[0], name, pack(metadata.fields())}, who.second);
            { std::lock_guard<std::mutex> lock(state_mutex); require(token == who.second, "session changed"); shares[{fields[0], name}] = {fields[1], metadata}; }
            print("SUCCESS " + response[1]); print("[Client] Now sharing " + name + " -> " + fields[1]); return;
        }
        auto response = rpc.call(cmd, fields, who.second);
        if (cmd == "logout") deactivate(who.second);
        if (cmd == "stop_share") {
            arity(fields, 2); std::lock_guard<std::mutex> lock(state_mutex); shares.erase({fields[0], fields[1]});
        }
        if (cmd == "leave_group") {
            arity(fields, 1); std::lock_guard<std::mutex> lock(state_mutex);
            for (auto it = shares.begin(); it != shares.end();) { if (it->first.first == fields[0]) it = shares.erase(it); else ++it; }
            for (const auto& job : jobs) if (job->gid == fields[0]) job->cancel = true;
        }
        if (cmd == "list_groups" || cmd == "list_requests" || cmd == "list_files") {
            std::ostringstream out; out << response[1]; for (size_t i = 2; i < response.size(); ++i) out << '\n' << response[i]; print(out.str());
        } else print("SUCCESS " + response[1]);
    }
    ~Client() {
        stopping = true;
        std::string ending_session;
        { std::lock_guard<std::mutex> lock(state_mutex); for (const auto& job : jobs) job->cancel = true; ending_session = token; token.clear(); shares.clear(); }
        slots_ready.notify_all();
        if (heartbeat.joinable()) heartbeat.join();
        for (const auto& job : jobs) if (job->thread.joinable()) job->thread.join();
        if (server) server->stop();
        if (!ending_session.empty()) { try { rpc.call("logout", {}, ending_session); } catch (...) {} }
    }
};
volatile std::sig_atomic_t interrupted = 0;
void signal_handler(int) { interrupted = 1; }
} // namespace
int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN); std::signal(SIGINT, signal_handler); std::signal(SIGTERM, signal_handler);
    try {
        require(argc == 3, "Usage: ./client <IPv4>:<PORT> tracker_info.txt");
        Client client(address(argv[1]), tracker_info(argv[2])); std::string pending; bool done = false;
        print("> ");
        while (!interrupted && !done) {
            pollfd p{STDIN_FILENO, POLLIN, 0}; int r = poll(&p, 1, 100);
            if (r < 0 && errno == EINTR) continue; require(r >= 0, "console poll failed");
            if (!r) continue;
            char buffer[4096]; ssize_t n = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break; pending.append(buffer, static_cast<size_t>(n));
            require(pending.size() <= 65536, "console command too long"); size_t pos;
            while ((pos = pending.find('\n')) != std::string::npos) {
                auto line = pending.substr(0, pos); pending.erase(0, pos + 1);
                try {
                    auto fields = tokenize(line); if (fields.empty()) continue;
                    if (fields[0] == "quit") { arity(fields, 1); done = true; break; }
                    client.command(std::move(fields));
                } catch (const std::exception& e) { print(std::string("ERROR ") + e.what()); }
                print("> ");
            }
        }
        return 0;
    } catch (const std::exception& e) { std::cerr << "ERROR " << e.what() << std::endl; return 1; }
}
