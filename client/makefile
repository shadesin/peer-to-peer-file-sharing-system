include ../common/build.mk
.DEFAULT_GOAL := all
.PHONY: all clean
all: client
client: client.cpp ../common/common.hpp ../common/build.mk
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) client.cpp $(LDFLAGS) $(LDLIBS) -o $@
clean:
	rm -f client
