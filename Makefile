# Traffic Generator & Capture Tools
# High-performance packet TX/RX tools

CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -pthread -D_GNU_SOURCE
LDFLAGS = -lpthread

SRCDIR = src

# Targets
TXGEN = txgen
RXCAP = rxcap

.PHONY: all clean install uninstall debug

all: $(TXGEN) $(RXCAP)

$(TXGEN): $(SRCDIR)/txgen.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built: $(TXGEN)"

$(RXCAP): $(SRCDIR)/rxcap.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Built: $(RXCAP)"

debug: CFLAGS = -g -O0 -Wall -Wextra -pthread -D_GNU_SOURCE -DDEBUG
debug: all

clean:
	rm -f $(TXGEN) $(RXCAP)

install: all
	install -m 755 $(TXGEN) /usr/local/bin/
	install -m 755 $(RXCAP) /usr/local/bin/
	@echo "Installed to /usr/local/bin/"

uninstall:
	rm -f /usr/local/bin/$(TXGEN)
	rm -f /usr/local/bin/$(RXCAP)

# Quick test
test-tx: $(TXGEN)
	@echo "txgen dry run:"
	sudo ./$(TXGEN) lo -B 127.0.0.1 -b ff:ff:ff:ff:ff:ff -S

test-rx: $(RXCAP)
	@echo "rxcap test (3 sec):"
	sudo ./$(RXCAP) lo --duration 3
