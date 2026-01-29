# High-Performance Traffic Generator Makefile

CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -pthread
LDFLAGS = -lpthread

TARGET = traffic_gen
SOURCES = traffic_generator.c

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Build complete: $(TARGET)"
	@echo "Run with: sudo ./$(TARGET) -h"

debug: CFLAGS = -g -O0 -Wall -Wextra -pthread -DDEBUG
debug: $(TARGET)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	install -m 755 trafgen.sh /usr/local/bin/trafgen
	@echo "Installed to /usr/local/bin/"

uninstall:
	rm -f /usr/local/bin/$(TARGET)
	rm -f /usr/local/bin/trafgen
