# TSN Traffic Generator & Receiver
# High-performance tools for TSN (Time-Sensitive Networking) testing

CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -pthread -D_GNU_SOURCE
LDFLAGS = -lpthread

SRCDIR = src

# Targets
TSNGEN = tsngen
TSNRECV = tsnrecv

.PHONY: all clean install uninstall debug

all: $(TSNGEN) $(TSNRECV)

$(TSNGEN): $(SRCDIR)/tsngen.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built: $(TSNGEN)"

$(TSNRECV): $(SRCDIR)/tsnrecv.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built: $(TSNRECV)"

debug: CFLAGS = -g -O0 -Wall -Wextra -pthread -D_GNU_SOURCE -DDEBUG
debug: all

clean:
	rm -f $(TSNGEN) $(TSNRECV)

install: all
	install -m 755 $(TSNGEN) /usr/local/bin/
	install -m 755 $(TSNRECV) /usr/local/bin/
	@echo "Installed to /usr/local/bin/"

uninstall:
	rm -f /usr/local/bin/$(TSNGEN)
	rm -f /usr/local/bin/$(TSNRECV)

# Quick test
test-gen: $(TSNGEN)
	@echo "tsngen dry run:"
	sudo ./$(TSNGEN) lo -B 127.0.0.1 -b ff:ff:ff:ff:ff:ff -S

test-recv: $(TSNRECV)
	@echo "tsnrecv test (3 sec):"
	sudo ./$(TSNRECV) lo --duration 3
