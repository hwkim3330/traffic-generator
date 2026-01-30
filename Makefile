# trafgen - High-Performance Traffic Generator
# Based on Mausezahn, enhanced with sendmmsg() and multi-threading

CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -pthread -D_GNU_SOURCE
LDFLAGS = -lpthread

SRCDIR = src
TARGET = trafgen
SOURCES = $(SRCDIR)/trafgen.c

.PHONY: all clean install uninstall debug

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo ""
	@echo "Build complete: $(TARGET)"
	@echo "Run: sudo ./$(TARGET) --help"

debug: CFLAGS = -g -O0 -Wall -Wextra -pthread -D_GNU_SOURCE -DDEBUG
debug: $(TARGET)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(TARGET)"

uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Run quick test (requires sudo)
test: $(TARGET)
	@echo "Quick test (dry run):"
	sudo ./$(TARGET) lo -B 127.0.0.1 -b ff:ff:ff:ff:ff:ff -S
