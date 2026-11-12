include ../common/build.mk
.DEFAULT_GOAL := all
.PHONY: all clean
all: tracker
tracker: tracker.cpp ../common/common.hpp ../common/build.mk
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tracker.cpp $(LDFLAGS) $(LDLIBS) -o $@
clean:
	rm -f tracker
