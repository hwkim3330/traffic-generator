# TSN Traffic Generator & Capture Tools
# High-performance tools for TSN (Time-Sensitive Networking) testing

CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -pthread -D_GNU_SOURCE
LDFLAGS = -lpthread

SRCDIR = src

# Targets
TSNGEN = tsngen
TSNCAP = tsncap

.PHONY: all clean install uninstall debug

all: $(TSNGEN) $(TSNCAP)

$(TSNGEN): $(SRCDIR)/tsngen.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built: $(TSNGEN)"

$(TSNCAP): $(SRCDIR)/tsncap.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built: $(TSNCAP)"

debug: CFLAGS = -g -O0 -Wall -Wextra -pthread -D_GNU_SOURCE -DDEBUG
debug: all

clean:
	rm -f $(TSNGEN) $(TSNCAP)

install: all
	install -m 755 $(TSNGEN) /usr/local/bin/
	install -m 755 $(TSNCAP) /usr/local/bin/
	@echo "Installed to /usr/local/bin/"

uninstall:
	rm -f /usr/local/bin/$(TSNGEN)
	rm -f /usr/local/bin/$(TSNCAP)

# Quick test
test-gen: $(TSNGEN)
	@echo "tsngen dry run:"
	sudo ./$(TSNGEN) lo -B 127.0.0.1 -b ff:ff:ff:ff:ff:ff -S

test-cap: $(TSNCAP)
	@echo "tsncap test (3 sec):"
	sudo ./$(TSNCAP) lo --duration 3
