# Makefile

TARGET = sdb

all: $(TARGET)

$(TARGET): sdb.c
	g++ -Wall -g -o sdbb sdb.cpp -lcapstone -lelf

clean:
	rm -f $(TARGET)
