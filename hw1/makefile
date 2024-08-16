CC=gcc
CFLAGS=-Wall -Wextra
DLFLAGS=-fPIC -shared
TARGET_LOGGER=logger
TARGET_SO=logger.so

all: $(TARGET_LOGGER) $(TARGET_SO)

$(TARGET_LOGGER): logger.c 
	$(CC) $(CFLAGS) -o $(TARGET_LOGGER) logger.c

$(TARGET_SO): lib.c
	$(CC) $(CFLAGS) $(DLFLAGS) -o $(TARGET_SO) lib.c -ldl

clean:
	rm -f $(TARGET_LOGGER) $(TARGET_SO) 
	find . -type f -name '*.log' -exec rm -f {} +
	# rm file.txt
.PHONY: all clean
