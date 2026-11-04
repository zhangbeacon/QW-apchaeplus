# demo-vuln-app Makefile：CC/CFLAGS 由 builder 通过环境变量注入
include config.mk

CC ?= cc
CFLAGS ?= -O2
BIN := demo_app

all: $(BIN)

$(BIN): main.c
	$(CC) $(CFLAGS) -o $@ main.c

install: $(BIN)
	mkdir -p $(PREFIX)/bin
	install -m 755 $(BIN) $(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN) config.mk
