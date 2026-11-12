CXX ?= c++
CPPFLAGS ?=
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++17 -pthread -Wall -Wextra -Wpedantic
LDFLAGS ?=
LDLIBS += -lcrypto -pthread

# Prefer pkg-config (Linux and macOS), then Homebrew, then system defaults.
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs-only-L openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_CFLAGS)),)
OPENSSL_PREFIX := $(shell command -v brew >/dev/null 2>&1 && brew --prefix openssl@3 2>/dev/null)
ifneq ($(strip $(OPENSSL_PREFIX)),)
OPENSSL_CFLAGS := -I$(OPENSSL_PREFIX)/include
OPENSSL_LIBS := -L$(OPENSSL_PREFIX)/lib
endif
endif
CPPFLAGS += $(OPENSSL_CFLAGS)
LDFLAGS += $(OPENSSL_LIBS)

ifeq ($(SANITIZE),address)
CXXFLAGS += -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif
ifeq ($(SANITIZE),thread)
CXXFLAGS += -O1 -fsanitize=thread -fno-omit-frame-pointer
LDFLAGS += -fsanitize=thread
endif
