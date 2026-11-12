#include "../common/common.hpp"
#include <sys/file.h>

using namespace p2p;
namespace {
struct User { std::string salt, password; };
struct Session { std::string uid, endpoint; uint64_t expires = 0; bool revoked = false; };
struct SharedFile { Metadata metadata; std::set<std::string> seeders; };
struct Group {
    std::string owner; std::set<std::string> members, requests;
    std::map<std::string, SharedFile> files;
};
struct Event {
    unsigned origin; uint64_t sequence, clock; std::string request, fingerprint, action, response, encoded;
};
class Tracker {
    std::vector<Address> addresses;
    unsigned identity;
    SigningKey key;
    Fd journal;
    std::mutex state_mutex, sync_mutex, nonce_mutex;
    std::array<std::vector<Event>, 2> logs;
    uint64_t logical_clock = 0;
    bool storage_failed = false;
    std::map<std::string, User> users;
    std::map<std::string, Group> groups;
    std::map<std::string, Session> sessions;
    std::map<std::string, std::string> current_session;
    std::map<std::string, uint64_t> leases;
    std::map<std::string, std::string> replies;
    std::map<std::string, std::string> fingerprints;
    std::map<std::string, uint64_t> nonces;
    std::array<uint64_t, 2> remote_counts{{0, 0}};

    static std::string cluster_key(const std::string& path) {
        // O_EXCL makes simultaneous first startup safe. The seed is never sent to clients.
        Fd fd(open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600));
        if (fd) {
            std::string seed(32, '\0');
            require(RAND_bytes(reinterpret_cast<unsigned char*>(&seed[0]), 32) == 1, "key generation failed");
            write_fd(fd.value, seed.data(), seed.size()); require(fsync(fd.value) == 0, "key sync failed");
            sync_parent(path); return seed;
        }
        require(errno == EEXIST, "cannot create cluster key");
        for (int attempt = 0; attempt < 50; ++attempt) {
            auto seed = read_file(path, 32);
            if (seed.size() == 32) return seed;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        throw std::runtime_error("incomplete cluster key file");
    }
    Event decode_event(const std::string& data) const {
        Fields f = unpack(data); arity(f, 8);
        std::string signature = f.back(); f.pop_back();
        require(equal_secret(signature, mac(key.secret, pack(f))), "invalid event authentication");
        unsigned origin = static_cast<unsigned>(number(f[0], 2)); require(origin >= 1, "invalid event origin");
        uint64_t seq = number(f[1], 1000000), clock = number(f[2], 1000000000);
        require(seq > 0 && clock > 0 && hex_string(f[3], 32), "invalid event identity");
        require(hex_string(f[4], 64), "invalid request fingerprint");
        Fields action = unpack(f[5]); arity(action, 4); unpack(action[3]);
        Fields response = unpack(f[6]); require(response.size() >= 2 && response[0] == "OK", "invalid event response");
        return {origin, seq, clock, f[3], f[4], f[5], f[6], data};
    }
    void remove_seeder(const std::string& sid) {
        for (auto& g : groups) for (auto& f : g.second.files) f.second.seeders.erase(sid);
    }
    void apply(const Event& event) {
        // Replaying the same union in Lamport/origin/sequence order produces the same state.
        // Preconditions also give deterministic outcomes to genuinely conflicting partition writes.
        Fields f = unpack(event.action); Fields a = unpack(f[3]);
        const std::string& cmd = f[0]; const std::string& uid = f[1]; const std::string& sid = f[2];
        if (cmd == "create_user") { if (!users.count(a[0])) users[a[0]] = {a[1], a[2]}; }
        else if (cmd == "login") {
            auto old = current_session.find(uid);
            if (old != current_session.end()) { sessions[old->second].revoked = true; remove_seeder(old->second); }
            sessions[sid] = {uid, a[0], number(a[1]), false}; current_session[uid] = sid;
            leases[sid] = std::max(leases[sid], number(a[2]));
        } else if (cmd == "logout") {
            if (sessions.count(sid)) sessions[sid].revoked = true;
            remove_seeder(sid);
        } else if (cmd == "create_group") {
            if (!groups.count(a[0]) && users.count(uid)) {
                Group g; g.owner = uid; g.members.insert(uid); groups[a[0]] = std::move(g);
            }
        } else {
            auto found = groups.find(a[0]); if (found == groups.end()) return;
            auto& g = found->second;
            if (cmd == "join_group") {
                if (!g.members.count(uid)) g.requests.insert(uid);
            } else if (cmd == "accept_request") {
                if (g.owner == uid && g.requests.erase(a[1])) g.members.insert(a[1]);
            } else if (cmd == "leave_group") {
                if (!g.members.erase(uid)) return;
                g.requests.erase(uid);
                for (auto& file : g.files) {
                    for (auto it = file.second.seeders.begin(); it != file.second.seeders.end();) {
                        auto s = sessions.find(*it);
                        if (s == sessions.end() || s->second.uid == uid) it = file.second.seeders.erase(it); else ++it;
                    }
                }
                if (g.members.empty()) groups.erase(found);
                else if (g.owner == uid) g.owner = *g.members.begin();
            } else if (cmd == "upload_file" && g.members.count(uid)) {
                auto m = Metadata::from(unpack(a[2])); auto existing = g.files.find(a[1]);
                if (existing == g.files.end() || existing->second.seeders.empty()) g.files[a[1]] = {m, {}};
                auto& file = g.files[a[1]];
                if (file.metadata.fields() == m.fields()) file.seeders.insert(sid);
            } else if (cmd == "stop_share") {
                auto file = g.files.find(a[1]); if (file != g.files.end()) file->second.seeders.erase(sid);
            }
        }
    }
    void rebuild() {
        users.clear(); groups.clear(); sessions.clear(); current_session.clear(); replies.clear(); fingerprints.clear();
        std::vector<const Event*> ordered;
        for (const auto& log : logs) for (const auto& e : log) ordered.push_back(&e);
        std::sort(ordered.begin(), ordered.end(), [](const Event* a, const Event* b) {
            return std::tie(a->clock, a->origin, a->sequence) < std::tie(b->clock, b->origin, b->sequence);
        });
        for (const Event* e : ordered) {
            if (!replies.emplace(e->request, e->response).second) continue;
            fingerprints[e->request] = e->fingerprint;
            apply(*e);
        }
    }
    bool ingest(const std::string& data, bool persist) {
        Event e = decode_event(data); auto& log = logs[e.origin - 1];
        if (e.sequence <= log.size()) {
            require(log[static_cast<size_t>(e.sequence - 1)].encoded == data, "conflicting event identity; check tracker storage/identity");
            return false;
        }
        require(e.sequence == log.size() + 1, "noncontiguous event sequence");
        if (persist) {
            require(!storage_failed, "journal unavailable; restart after repairing storage");
            try {
                std::string record; put32(record, static_cast<uint32_t>(data.size())); record += data;
                off_t end = lseek(journal.value, 0, SEEK_CUR);
                require(end >= 0 && static_cast<uint64_t>(end) + record.size() <= 128 * 1024 * 1024, "journal exceeds 128 MiB safety limit");
                write_fd(journal.value, record.data(), record.size());
                require(fsync(journal.value) == 0, "journal sync failed");
            } catch (...) { storage_failed = true; throw; }
        }
        logical_clock = std::max(logical_clock, e.clock); log.push_back(std::move(e)); return true;
    }
    void load_journal() {
        struct stat st{}; require(fstat(journal.value, &st) == 0 && st.st_size >= 0, "journal stat failed");
        require(static_cast<uint64_t>(st.st_size) <= 128 * 1024 * 1024, "journal exceeds 128 MiB safety limit");
        off_t offset = 0;
        while (offset < st.st_size) {
            uint32_t n = 0; ssize_t got = pread(journal.value, &n, 4, offset);
            if (got < 0 && errno == EINTR) continue;
            require(got >= 0, "journal read failed");
            if (got < 4) break;
            n = ntohl(n); require(n >= 4 && n <= MAX_FRAME, "corrupt journal length");
            if (st.st_size - offset - 4 < static_cast<off_t>(n)) break;
            std::string data(n, '\0'); size_t read_bytes = 0;
            while (read_bytes < n) {
                ssize_t r = pread(journal.value, &data[read_bytes], n - read_bytes, offset + 4 + static_cast<off_t>(read_bytes));
                if (r < 0 && errno == EINTR) continue;
                require(r > 0, "journal read failed"); read_bytes += static_cast<size_t>(r);
            }
            ingest(data, false); offset += 4 + n;
        }
        if (offset != st.st_size) {
            require(ftruncate(journal.value, offset) == 0 && fsync(journal.value) == 0, "cannot repair incomplete journal tail");
            std::cerr << "Recovered incomplete final journal record\n";
        }
        require(lseek(journal.value, 0, SEEK_END) >= 0, "journal seek failed"); rebuild();
    }
    std::string commit(const std::string& rid, const std::string& fingerprint, const Fields& action, const Fields& response) {
        Fields f{std::to_string(identity), std::to_string(logs[identity - 1].size() + 1),
            std::to_string(logical_clock + 1), rid, fingerprint, pack(action), pack(response)};
        f.push_back(mac(key.secret, pack(f))); ingest(pack(f), true); rebuild(); return pack(response);
    }
    std::string summary() const { return pack({std::to_string(logs[0].size()), std::to_string(logs[1].size())}); }
    Fields missing(const std::array<uint64_t, 2>& counts) const {
        Fields result; size_t total = 0;
        for (size_t i = 0; i < 2; ++i) {
            require(counts[i] <= 1000000, "invalid log cursor");
            for (uint64_t j = counts[i]; j < logs[i].size(); ++j) {
                const auto& data = logs[i][static_cast<size_t>(j)].encoded;
                if (total + data.size() > 350 * 1024) return result;
                total += data.size() + 4; result.push_back(data);
            }
        }
        return result;
    }
    static std::array<uint64_t, 2> counts(const std::string& data) {
        Fields f = unpack(data); arity(f, 2); return {{number(f[0], 1000000), number(f[1], 1000000)}};
    }
    std::string lease_data() {
        Fields result; uint64_t t = now();
        for (auto it = leases.begin(); it != leases.end();) {
            if (it->second < t) it = leases.erase(it);
            else { result.push_back(pack({it->first, std::to_string(it->second)})); ++it; }
        }
        require(result.size() <= 4096, "too many live sessions"); return pack(result);
    }
    void merge_leases(const std::string& data) {
        Fields list = unpack(data); require(list.size() <= 4096, "too many leases");
        for (const auto& record : list) {
            Fields f = unpack(record); arity(f, 2); require(hex_string(f[0], 32), "invalid lease session");
            uint64_t expiry = number(f[1]);
            require(expiry <= now() + LEASE_SECONDS + 5, "invalid lease expiry");
            if (expiry >= now()) leases[f[0]] = std::max(leases[f[0]], expiry);
        }
    }
    Fields signed_rpc(const Fields& body) {
        std::string nonce = random_id(), timestamp = std::to_string(now()), encoded = pack(body);
        Fields request{"REPLICA", timestamp, nonce, encoded}; request.push_back(mac(key.secret, pack(request)));
        Fields response = p2p::exchange(addresses[2 - identity], request); arity(response, 3);
        require(response[0] == nonce && equal_secret(response[2], mac(key.secret, pack({response[0], response[1]}))), "invalid replica response");
        return unpack(response[1]);
    }
    Fields replica(const Fields& request) {
        arity(request, 5);
        uint64_t timestamp = number(request[1]), t = now();
        require(timestamp <= t + 30 && timestamp + 30 >= t && hex_string(request[2], 32), "expired replica request");
        Fields signed_fields(request.begin(), request.begin() + 4);
        require(equal_secret(request[4], mac(key.secret, pack(signed_fields))), "replica authentication failed");
        {
            std::lock_guard<std::mutex> lock(nonce_mutex);
            for (auto it = nonces.begin(); it != nonces.end();) {
                if (it->second + 60 < t) it = nonces.erase(it); else ++it;
            }
            require(nonces.size() < 4096 && nonces.emplace(request[2], timestamp).second, "replayed replica request");
        }
        Fields body = unpack(request[3]), result;
        require(!body.empty(), "empty replica command");
        if (body[0] == "SYNC") {
            arity(body, 4); auto wanted = counts(body[1]); Fields incoming = unpack(body[2]);
            std::lock_guard<std::mutex> lock(state_mutex);
            bool changed = false;
            for (const auto& data : incoming) changed = ingest(data, true) || changed;
            if (changed) rebuild(); merge_leases(body[3]);
            result = {"OK", summary(), pack(missing(wanted)), lease_data()};
        } else if (body[0] == "FORWARD") {
            arity(body, 2); require(identity == 1, "forward target must be tracker 1");
            try { result = execute(unpack(body[1])); }
            catch (const std::exception& e) { result = {"ERROR", e.what()}; }
        } else throw std::runtime_error("unknown replica command");
        std::string response = pack(result);
        return {request[2], response, mac(key.secret, pack({request[2], response}))};
    }
    bool live(const std::string& sid) const {
        auto s = sessions.find(sid); auto lease = leases.find(sid);
        if (s == sessions.end() || s->second.revoked || s->second.expires <= now() || lease == leases.end() || lease->second <= now()) return false;
        auto active = current_session.find(s->second.uid);
        return active != current_session.end() && active->second == sid;
    }
    std::pair<std::string, std::string> authenticate(const std::string& token) const {
        auto f = verify_token(token, key.public_key); arity(f, 5);
        require(f[0] == "SESSION" && number(f[4]) > now(), "expired session");
        auto s = sessions.find(f[2]); auto current = current_session.find(f[1]);
        require(s != sessions.end() && !s->second.revoked && s->second.uid == f[1] &&
            s->second.endpoint == f[3] && s->second.expires == number(f[4]) &&
            current != current_session.end() && current->second == f[2], "session is no longer active");
        return {f[1], f[2]};
    }
    Fields execute(const Fields& request) {
        arity(request, 5); require(request[0] == "RPC" && hex_string(request[1], 32), "invalid request");
        const std::string& rid = request[1]; const std::string& token = request[2];
        const std::string& command = request[3]; Fields args = unpack(request[4]);
        const std::string fingerprint = mac(key.secret, pack(request));
        Fields response; bool changed = false;
        {
            std::unique_lock<std::mutex> lock(state_mutex);
            auto previous = replies.find(rid);
            if (previous != replies.end()) {
                require(equal_secret(fingerprints.at(rid), fingerprint), "request ID was already used for different arguments");
                Fields cached = unpack(previous->second);
                lock.unlock(); synchronize(true); return cached;
            }
            std::string uid, sid;
            if (command != "create_user" && command != "login") {
                auto who = authenticate(token); uid = who.first; sid = who.second;
            }
            Fields action_args = args;
            response = {"OK", "operation completed"};
            if (command == "create_user") {
                arity(args, 2); identifier(args[0]); require(!args[1].empty() && args[1].size() <= 256, "invalid password length");
                require(!users.count(args[0]), "user exists");
                std::string salt = random_id(); action_args = {args[0], salt, password_hash(args[1], salt)};
                response[1] = "user created"; changed = true;
            } else if (command == "login") {
                arity(args, 3); identifier(args[0]); require(args[1].size() <= 256, "invalid password length"); address(args[2]);
                lease_data(); require(leases.size() < 4096, "live session limit reached");
                auto user = users.find(args[0]);
                require(user != users.end() && equal_secret(password_hash(args[1], user->second.salt), user->second.password), "invalid user or password");
                auto active = current_session.find(args[0]);
                require(active == current_session.end() || !live(active->second), "user already logged in");
                uid = args[0]; sid = rid; uint64_t expiry = now() + 12 * 60 * 60;
                action_args = {args[2], std::to_string(expiry), std::to_string(now() + LEASE_SECONDS)};
                response = {"OK", "logged in", key.token({"SESSION", uid, sid, args[2], std::to_string(expiry)}), key.public_key};
                changed = true;
            } else if (command == "heartbeat") {
                arity(args, 0); leases[sid] = now() + LEASE_SECONDS;
                response = {"OK", "session renewed", std::to_string(leases[sid])};
            } else if (command == "authorize_piece") {
                arity(args, 1); auto ticket = verify_token(args[0], key.public_key); arity(ticket, 8);
                require(ticket[0] == "TICKET" && number(ticket[7]) > now() && live(ticket[2]), "expired or revoked download authorization");
                auto requester = sessions.find(ticket[2]);
                require(requester != sessions.end() && requester->second.uid == ticket[1], "invalid ticket session");
                auto group = groups.find(ticket[3]);
                require(group != groups.end() && group->second.members.count(uid) && group->second.members.count(ticket[1]), "group access revoked");
                auto file = group->second.files.find(ticket[4]);
                require(file != group->second.files.end() && file->second.seeders.count(sid) &&
                    file->second.metadata.hash == ticket[5] && file->second.metadata.size == number(ticket[6], MAX_FILE), "share authorization revoked");
                response[1] = "piece authorized";
            } else if (command == "logout") {
                arity(args, 0); response[1] = "logged out"; changed = true;
            } else if (command == "list_groups") {
                arity(args, 0); response[1] = "GROUPS";
                for (const auto& g : groups) response.push_back(g.first);
            } else if (command == "create_group") {
                arity(args, 1); identifier(args[0]); require(!groups.count(args[0]), "group exists");
                response[1] = "group created"; changed = true;
            } else {
                require(!args.empty(), "missing group"); identifier(args[0]);
                auto found = groups.find(args[0]); require(found != groups.end(), "no such group"); auto& group = found->second;
                if (command == "join_group") {
                    arity(args, 1); require(!group.members.count(uid), "already a member");
                    require(!group.requests.count(uid), "join request already pending"); response[1] = "join request sent"; changed = true;
                } else {
                    require(group.members.count(uid), "not a group member");
                    if (command == "leave_group") { arity(args, 1); response[1] = "left group"; changed = true; }
                    else if (command == "list_requests") {
                        arity(args, 1); require(group.owner == uid, "only owner may view requests");
                        response[1] = "REQUESTS"; for (const auto& user : group.requests) response.push_back(user);
                    } else if (command == "accept_request") {
                        arity(args, 2); require(group.owner == uid, "only owner may accept requests");
                        require(group.requests.count(args[1]), "request not found"); response[1] = "request accepted"; changed = true;
                    } else if (command == "upload_file") {
                        arity(args, 3); filename(args[1]); Metadata m = Metadata::from(unpack(args[2]));
                        auto old = group.files.find(args[1]);
                        require(old == group.files.end() || old->second.seeders.empty() || old->second.metadata.fields() == m.fields(), "filename already identifies different content");
                        response[1] = "file uploaded"; changed = true;
                    } else if (command == "stop_share") {
                        arity(args, 2); filename(args[1]); auto file = group.files.find(args[1]);
                        require(file != group.files.end() && file->second.seeders.count(sid), "file is not shared by this session");
                        response[1] = "stopped sharing file"; changed = true;
                    } else if (command == "list_files") {
                        arity(args, 1); response[1] = "FILES";
                        for (const auto& file : group.files) {
                            bool available = false; for (const auto& peer : file.second.seeders) available = available || live(peer);
                            if (available) response.push_back(file.first);
                        }
                    } else if (command == "download_file") {
                        arity(args, 2); filename(args[1]); auto file = group.files.find(args[1]);
                        require(file != group.files.end(), "file not found"); Fields peers;
                        for (const auto& peer : file->second.seeders) if (live(peer)) peers.push_back(sessions.at(peer).endpoint);
                        require(!peers.empty(), "no online seeders");
                        auto& m = file->second.metadata;
                        std::string ticket = key.token({"TICKET", uid, sid, args[0], args[1], m.hash,
                            std::to_string(m.size), std::to_string(now() + TICKET_SECONDS)});
                        response = {"OK", "file metadata", pack(m.fields()), pack(peers), ticket};
                    } else throw std::runtime_error("unknown command");
                }
            }
            if (changed) {
                require(logs[0].size() + logs[1].size() < 100000, "journal event limit reached");
                commit(rid, fingerprint, {command, uid, sid, pack(action_args)}, response);
            }
        }
        if (changed) synchronize(true);
        else if (command == "heartbeat") synchronize();
        return response;
    }
public:
    Tracker(std::vector<Address> a, unsigned id, const std::string& key_path)
        : addresses(std::move(a)), identity(id), key(cluster_key(key_path)) {
        std::string path = "tracker_state_" + std::to_string(identity) + ".log";
        journal = Fd(open(path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW, 0600));
        require(static_cast<bool>(journal), "cannot open journal");
        require(flock(journal.value, LOCK_EX | LOCK_NB) == 0, "tracker journal already in use");
        load_journal(); sync_parent(path);
    }
    bool synchronize(bool wait = false) {
        std::unique_lock<std::mutex> syncing(sync_mutex, std::defer_lock);
        if (wait) syncing.lock();
        else if (!syncing.try_lock()) return false;
        try {
            for (int round = 0; round < 512; ++round) {
                Fields request;
                { std::lock_guard<std::mutex> lock(state_mutex);
                  request = {"SYNC", summary(), pack(missing(remote_counts)), lease_data()}; }
                Fields response = signed_rpc(request); arity(response, 4); require(response[0] == "OK", "replica sync rejected");
                auto remote = counts(response[1]); Fields incoming = unpack(response[2]);
                bool done;
                { std::lock_guard<std::mutex> lock(state_mutex);
                  bool changed = false; for (const auto& data : incoming) changed = ingest(data, true) || changed;
                  if (changed) rebuild(); merge_leases(response[3]); remote_counts = remote;
                  done = remote[0] == logs[0].size() && remote[1] == logs[1].size(); }
                if (done) return true;
            }
        } catch (const std::exception&) { return false; }
        return false;
    }
    void handle(int fd) {
      while (true) {
        Fields request;
        auto respond = [&](const Fields& response) {
            if (request.size() == 5 && request[0] == "RPC" && hex_string(request[1], 32)) {
                std::string body = pack(response);
                send_frame(fd, pack({"SIGNED", request[1], body, key.sign(pack({request[1], body}))}));
            } else send_frame(fd, pack(response));
        };
        try {
            request = unpack(receive_frame(fd)); require(!request.empty(), "empty command"); Fields response;
            if (request[0] == "HELLO") { arity(request, 1); response = {"OK", "P2P/2", key.public_key}; }
            else if (request[0] == "REPLICA") response = replica(request);
            else {
                arity(request, 5); require(request[0] == "RPC", "unknown protocol role");
                bool forwarded = false;
                // Prefer one writer while connected, but retain availability during an outage.
                if (identity == 2) {
                    try { response = signed_rpc({"FORWARD", pack(request)}); forwarded = true; }
                    catch (const std::exception&) { /* Independent log is reconciled on recovery. */ }
                }
                if (!forwarded) response = execute(request);
            }
            respond(response);
        } catch (const std::exception& e) {
            try { respond({"ERROR", e.what()}); } catch (...) {}
            return;
        }
      }
    }
};
volatile std::sig_atomic_t interrupted = 0;
void signal_handler(int) { interrupted = 1; }
} // namespace

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN); std::signal(SIGINT, signal_handler); std::signal(SIGTERM, signal_handler);
    try {
        require(argc == 3 || argc == 4, "Usage: ./tracker tracker_info.txt <1|2> [cluster-key-file]");
        auto addresses = tracker_info(argv[1]); unsigned id = static_cast<unsigned>(number(argv[2], 2)); require(id >= 1, "tracker number must be 1 or 2");
        Tracker tracker(addresses, id, argc == 4 ? argv[3] : std::string(argv[1]) + ".key");
        tracker.synchronize();
        Server server(addresses[id - 1], [&](int fd) { tracker.handle(fd); });
        std::atomic<bool> stopping{false};
        std::thread replication([&] {
            while (!stopping) {
                tracker.synchronize();
                for (int i = 0; i < 5 && !stopping; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        });
        std::cout << "Tracker listening on " << address_text(addresses[id - 1]) << std::endl;
        // Poll console input so shutdown can join all workers and the replication thread.
        std::string input; bool console_open = true;
        while (!interrupted) {
            pollfd p{STDIN_FILENO, POLLIN, 0}; int r = poll(console_open ? &p : nullptr, console_open ? 1 : 0, 100);
            if (r > 0 && (p.revents & (POLLIN | POLLHUP))) {
                char buffer[256]; ssize_t n = read(STDIN_FILENO, buffer, sizeof(buffer));
                if (n <= 0) console_open = false;
                else {
                    input.append(buffer, static_cast<size_t>(n)); size_t pos;
                    while ((pos = input.find('\n')) != std::string::npos) {
                        auto line = input.substr(0, pos); input.erase(0, pos + 1);
                        if (line == "quit" || line == "quit\r") interrupted = 1;
                    }
                    if (input.size() > 4096) input.clear();
                }
            }
        }
        stopping = true; if (replication.joinable()) replication.join(); server.stop();
        std::cout << "Tracker stopped; durable journal retained" << std::endl;
        return 0;
    } catch (const std::exception& e) { std::cerr << "ERROR " << e.what() << std::endl; return 1; }
}
