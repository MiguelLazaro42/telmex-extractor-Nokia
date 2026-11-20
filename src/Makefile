CXX ?= g++
CXXFLAGS ?= -std=c++11 -O2 -Wall

# Detect OpenSSL on macOS / Linux
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    HOMEBREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
    CXXFLAGS += -I$(HOMEBREW_PREFIX)/opt/openssl/include
    LDFLAGS += -L$(HOMEBREW_PREFIX)/opt/openssl/lib
endif

LDFLAGS += -lcrypto

TARGET = ../hw_passwd
SRCS = hw_passwd.cpp rev_hw.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
