# CFLAGS=-Wall -O3
CFLAGS=-g -Wall -DDEBUG
all: nbd-client-relay-notls nbd-client-relay
COMMON=main.o mounts.o kernel.o fileio.o nbdclient.o misc.o growbuff.o sigproc.o
nbd-client-relay: relay-tls.o unionio-tls.o nbdtlsclient.o ${COMMON}
	${CC} -o $@ $^ -lgnutls -lpthread
nbd-client-relay-notls: relay.o unionio.o ${COMMON}
	${CC} -o $@ $^ -lpthread
relay-tls.o: relay.c
	${CC} -o $@ -c $^ ${CFLAGS} -DHAVETLS
unionio-tls.o: unionio.c
	${CC} -o $@ -c $^ ${CFLAGS} -DHAVETLS
upload: clean
	scp -pr * monitor:src/squashfs/relay
upload2: clean
	scp -pr * tvroom:src/squashfs/relay
clean:
	rm -f core *.o nbd-client-relay nbd-client-relay-notls
backup: clean
	tar -jcf - . | jbackup src.nbdrelay.tar.bz2
