CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
LDFLAGS = -loqs -lssl -lcrypto

SRC_DIR = src
TEST_DIR = tests
BIN_DIR = .

# Targets
all: vault test_crypto test_roundtrip test_bench

vault: $(SRC_DIR)/main.c $(SRC_DIR)/vault.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_crypto: $(TEST_DIR)/test_crypto.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_roundtrip: $(TEST_DIR)/test_roundtrip.c $(SRC_DIR)/vault.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_bench: $(TEST_DIR)/bench.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f vault test_crypto test_roundtrip test_bench test_in.txt test.vault test_out.txt test.pk test.sk

.PHONY: all clean
