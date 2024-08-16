CC=gcc
CFLAGS=-Wall -fPIC
LDFLAGS=-lm

all: maze libmaze.so libsolver.so

libmaze.so: localsolver.o libmaze_dummy.o
	$(CC) -shared -o $@ $^ -Wl,--allow-multiple-definition

libsolver.so: libsolver.o
	$(CC) -shared -o $@ $<


libmaze_dummy.o: libmaze_dummy.c libmaze.h
	$(CC) $(CFLAGS) -c $< -o $@

localsolver.o: localsolver.c libmaze.h
	$(CC) $(CFLAGS) -c $< -o $@

libsolver.o: libsolver.c libmaze.h
	$(CC) $(CFLAGS) -c $< -o $@


maze: maze.o libmaze.so
	$(CC) -o $@ $< -L. -lmaze -Wl,-rpath,'$ORIGIN' $(LDFLAGS)

# Rule to compile maze.c to an object file
maze.o: maze.c libmaze.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o libmaze.so libsolver.so maze

.PHONY: all clean
