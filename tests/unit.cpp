#include "../common/common.hpp"

using namespace p2p;
namespace {
void rejects(const std::function<void()>& fn) {
    bool rejected = false;
    try { fn(); } catch (const std::exception&) { rejected = true; }
    require(rejected, "invalid input was accepted");
}
}
int main() {
    std::signal(SIGPIPE, SIG_IGN);
    try {
        // Exercise the former metadata overflow and integer/length boundary failures.
        const std::string h = digest("X");
        rejects([&] { Metadata::from({"524289", h, pack({h})}); });
        rejects([&] { Metadata::from({"1073741825", h, pack({})}); });
        rejects([&] { Metadata::from({"1", "not-a-hash", pack({h})}); });
        rejects([&] { number("18446744073709551616"); });
        rejects([&] { number("-1"); });
        rejects([&] { address("127.0.0.1:notaport"); });
        rejects([&] { address("999.1.2.3:80"); });
        rejects([&] { address("127.0.0.1:65536"); });
        rejects([&] { unpack(std::string(8192, 'X')); });
        rejects([&] { unpack(std::string("\xff\xff\xff\xff", 4)); });
        Metadata empty = Metadata::from({"0", digest(""), pack({})});
        require(empty.pieces.empty(), "empty file metadata failed");
        rejects([&] { empty.piece_size(0); });
        std::string binary("a\0b\n\xff", 5);
        require(unpack(pack({"name with spaces:colon", binary}))[1] == binary, "binary framing failed");
        for (size_t length = 0; length < 4096; ++length) {
            std::string input(length, '\0');
            if (length) require(RAND_bytes(reinterpret_cast<unsigned char*>(&input[0]), static_cast<int>(length)) == 1, "random failed");
            try { auto fields = unpack(input); require(pack(fields) == input, "parser round-trip failed"); }
            catch (const std::runtime_error&) { /* Rejection is the expected outcome for random input. */ }
        }
        SigningKey signer(std::string(32, 'K'));
        std::string token = signer.token({"TICKET", "group", "file"});
        require(verify_token(token, signer.public_key)[1] == "group", "signature validation failed");
        token.back() ^= 1;
        rejects([&] { verify_token(token, signer.public_key); });
        require(tokenize("upload_file a 'a path: with spaces'") == Fields({"upload_file", "a", "a path: with spaces"}), "tokenizer failed");
        rejects([&] { tokenize("upload_file a 'unterminated"); });
        std::cout << "Unit checks passed (including 4096 malformed-message cases)\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
