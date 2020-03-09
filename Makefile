CC=gcc
CFLAGS=-I. -Wunused-function  -Wunused-variable -g


SYS: mqttFilePublish mqttFileSubscribe
	touch SYS

mqttFilePublish: mqttFilePublish.o 
	$(CC) mqttFilePublish.o  -o mqttFilePublish $(CFLAGS)  -lm -ljson-c -lmosquitto 


mqttFilePublish.o: mqttFilePublish.c mqttFilePublish.h
	$(CC)  -c mqttFilePublish.c  $(CFLAGS) -I/usr/include/json-c/

mqttFileSubscribe: mqttFileSubscribe.o 
	$(CC) mqttFileSubscribe.o  -o mqttFileSubscribe $(CFLAGS)  -lm -ljson-c -lmosquitto 


mqttFileSubscribe.o: mqttFileSubscribe.c mqttFileSubscribe.h
	$(CC)  -c mqttFileSubscribe.c  $(CFLAGS) -I/usr/include/json-c/

clean:
	rm -f *.o 
