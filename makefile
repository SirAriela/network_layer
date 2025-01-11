CC = gcc
CFLAGS = -Wall -g

all: ping traceroute

ping: ping.c network_util.h
	$(CC) $(CFLAGS) -o ping ping.c

traceroute: traceroute.c network_util.h
	$(CC) $(CFLAGS) -o traceroute traceroute.c

clean:
	rm -f ping traceroute
