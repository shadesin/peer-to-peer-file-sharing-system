include common/build.mk
.DEFAULT_GOAL := all
.PHONY: all clean test unit
all:
	$(MAKE) -C tracker
	$(MAKE) -C client
clean:
	$(MAKE) -C tracker clean
	$(MAKE) -C client clean
	rm -f tests/unit
tests/unit: tests/unit.cpp common/common.hpp common/build.mk
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/unit.cpp $(LDFLAGS) $(LDLIBS) -o $@
unit: tests/unit
	./tests/unit
test: all unit
	python3 tests/integration.py
