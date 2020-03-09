#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h> 
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <json.h>
#include <mosquitto.h>
#include <time.h>

static int mqtt_port=1883;
static char mqtt_host[256];
static char logDir[256]="logLocal";

int outputDebug=0;
#if 0
static char mqtt_topic[256];
static struct mosquitto *mosq;
#endif

extern char *optarg;
extern int optind, opterr, optopt;

static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

/*
** returnable errors
**
** Error codes returned to the operating system.
**
*/
#define B64_SYNTAX_ERROR        1
#define B64_FILE_ERROR          2
#define B64_FILE_IO_ERROR       3
#define B64_ERROR_OUT_CLOSE     4
#define B64_LINE_SIZE_TO_MIN    5
#define B64_SYNTAX_TOOMANYARGS  6

/*
** b64_message
**
** Gather text messages in one place.
**
*/
#define B64_MAX_MESSAGES 7
static char *b64_msgs[ B64_MAX_MESSAGES ] = {
            "b64:000:Invalid Message Code.",
            "b64:001:Syntax Error -- check help (-h) for usage.",
            "b64:002:File Error Opening/Creating Files.",
            "b64:003:File I/O Error -- Note: output file not removed.",
            "b64:004:Error on output file close.",
            "b64:005:linesize set to minimum.",
            "b64:006:Syntax: Too many arguments."
};

#define b64_message( ec ) ((ec > 0 && ec < B64_MAX_MESSAGES ) ? b64_msgs[ ec ] : b64_msgs[ 0 ])

/*
** decodeblock
**
** decode 4 '6-bit' characters into 3 8-bit binary bytes
*/
static void decodeblock( unsigned char *in, unsigned char *out )
{   
    out[ 0 ] = (unsigned char ) (in[0] << 2 | in[1] >> 4);
    out[ 1 ] = (unsigned char ) (in[1] << 4 | in[2] >> 2);
    out[ 2 ] = (unsigned char ) (((in[2] << 6) & 0xc0) | in[3]);
}

/*
** decode
**
** decode a base64 encoded stream discarding padding, line breaks and noise
*/
static int decode( FILE *infile, FILE *outfile )
{
	int retcode = 0;
    unsigned char in[4];
    unsigned char out[3];
    int v;
    int i, len;

	*in = (unsigned char) 0;
	*out = (unsigned char) 0;
    while( feof( infile ) == 0 ) {
        for( len = 0, i = 0; i < 4 && feof( infile ) == 0; i++ ) {
            v = 0;
            while( feof( infile ) == 0 && v == 0 ) {
                v = getc( infile );
                if( feof( infile ) == 0 ) {
	                v = ((v < 43 || v > 122) ? 0 : (int) cd64[ v - 43 ]);
					if( v != 0 ) {
						v = ((v == (int)'$') ? 0 : v - 61);
					}
                }
            }
            if( feof( infile ) == 0 ) {
                len++;
                if( v != 0 ) {
                    in[ i ] = (unsigned char) (v - 1);
                }
            }
            else {
                in[i] = (unsigned char) 0;
            }
        }
        if( len > 0 ) {
            decodeblock( in, out );
            for( i = 0; i < len - 1; i++ ) {
                if( putc( (int) out[i], outfile ) == EOF ){
	                if( ferror( outfile ) != 0 )      {
	                    perror( b64_message( B64_FILE_IO_ERROR ) );
	                    retcode = B64_FILE_IO_ERROR;
	                }
					break;
				}
            }
        }
    }
    return( retcode );
}


char	*strsave(char *s )
{
char	*ret_val = 0;

ret_val = malloc(strlen(s)+1);
if ( 0 != ret_val) strcpy(ret_val,s);
return ret_val;	
}
typedef struct topics {
	struct topics *left,*right;
	char	*topic;
	}	TOPICS;

TOPICS *topic_root = 0;

void add_topic(char *s ) {
	TOPICS *p,*q;
	int	cond;
	int	flag;

	if ( 0 == topic_root ) {
		topic_root = calloc(sizeof(TOPICS),1);
		topic_root->topic = strsave(s);
		return;
	}
	p = topic_root;
	for ( ;0 != p; ) {
		cond = strcmp(p->topic,s);
		q = p;
		if ( 0 == cond )	return;	// no reason to re-subscribe
		if ( 0 < cond ) {
			p = q->left;	flag = 1;
		}
		else {
			p = q->right;	flag = -1;
		}
	}
	/* if here then it is a new topic */
	p = calloc(sizeof(TOPICS),1);
	p->topic = strsave(s);
	if ( 1 == flag )
		q->left = p;
	else
		q->right = p;

}




uint64_t microtime() {
	struct timeval time;
	gettimeofday(&time, NULL); 
	return ((uint64_t)time.tv_sec * 1000000) + time.tv_usec;
}

static void signal_handler(int signum) {


	if ( SIGALRM == signum ) {
		fprintf(stderr,"\n# Timeout while waiting for NMEA data.\n");
		fprintf(stderr,"# Terminating.\n");
		exit(100);
	} else if ( SIGPIPE == signum ) {
		fprintf(stderr,"\n# Broken pipe.\n");
		fprintf(stderr,"# Terminating.\n");
		exit(101);
	} else if ( SIGUSR1 == signum ) {
		/* clear signal */
		signal(SIGUSR1, SIG_IGN);

		fprintf(stderr,"# SIGUSR1 triggered data_block dump:\n");
		
		/* re-install alarm handler */
		signal(SIGUSR1, signal_handler);
	} else {
		fprintf(stderr,"\n# Caught unexpected signal %d.\n",signum);
		fprintf(stderr,"# Terminating.\n");
		exit(102);
	}

}
#include <sys/time.h>

static int _enable_logging_dir(const char *s )
{
/* assumes that we are in the correct starting dir */
char	buffer[256+4];
char	path[256+4]  = {};
char	*p,*q = buffer;
struct stat buf;
int rc = 0;
int len;

umask(00);

strncpy(buffer,s,256+3);
len = strlen(buffer);
if ( '/' != buffer[len -1] )	buffer[len] = '/';




while ( p = strsep(&q,"/")) {	// assumes / is the FS separator 
	strcat(path,p);	strcat(path,"/");
	if ( 0 != stat(path,&buf)) {
		/* assume that it does not exist */
		if ( 0 != (rc = mkdir(path,0777)))
			break;
		}
	}
	

if ( 0 != rc ) 
	fprintf(stderr,"# %s %s\n",path,strerror(errno));


return	rc;
}
	

#define ALARM_SECONDS 600
static int run = 1;



void connect_callback(struct mosquitto *mosq, void *obj, int result) {
	printf("# connect_callback, rc=%d\n", result);
}
static int  _get_int(const char *tag,const char *packet,int *dest ) {
	char lookfor[64];
	char buffer[3000 + 512];
	char *p;
	int rc;
	strncpy(buffer,packet,sizeof(buffer));
	snprintf(lookfor,sizeof(lookfor),"\"%s\":",tag);
	p = strstr(buffer,tag);
	rc = ( 0 == p );
	if ( 0 != rc ) {
		goto exit_now;
	}
	p += strlen(lookfor) -1;
	/* p now points to the first character of the int */
	*dest = atoi(p);

	exit_now:
	return	rc;

}
static int  _get_string(const char *tag,const char *packet,char **dest ) {
	char lookfor[64];
	char buffer[3000 + 512];
	char *p,*q;
	char *d;
	int rc;
	strncpy(buffer,packet,sizeof(buffer));
	snprintf(lookfor,sizeof(lookfor),"\"%s\":\"",tag);
	p = strstr(buffer,tag);
	rc = ( 0 == p );
	if ( 0 != rc ) {
		goto exit_now;
	}
	p += strlen(lookfor) -1;
	/* p now points to the first character of the string */
	q = strchr(p,'"');
	rc = ( 0 == q );
	if ( 0 != rc ) {
		goto exit_now;
	}
	d = calloc ( 1 + (q - p ) ,1);
	rc = ( 0 == d );
	if ( 0 != rc ) {
		goto exit_now;
	}
	memcpy(d,p,(q - p));
	*dest = d;

	exit_now:
	return	rc;

}


int parse_the_packet(char *payload, int payloadlen, char **topic, char ** inputFileName, char**outputFileName,
	int *packetNumber, int *packetCount, char **packetData ) {
	int rc;

	// payload[payloadlen] = '\0';	/* make into string */

	rc = _get_string("topic",payload,topic);
	if ( 0 != rc ) {
		goto exit_now;
	}

	rc = _get_string("inputFileName",payload,inputFileName);
	if ( 0 != rc ) {
		goto exit_now;
	}

	rc = _get_string("outputFileName",payload,outputFileName);
	if ( 0 != rc ) {
		goto exit_now;
	}

	rc = _get_int("packetNumber",payload,packetNumber);
	if ( 0 != rc ) {
		goto exit_now;
	}

	rc = _get_int("packetCount",payload,packetCount);
	if ( 0 != rc ) {
		goto exit_now;
	}

	rc = _get_string("packetData",payload,packetData);
	if ( 0 != rc ) {
		goto exit_now;
	}

	exit_now:

	return	rc;
}
static char * _build_the_name(char *topic,char *outputFileName) {
	char buffer[256]  = {};
	char *d;

	snprintf(buffer,sizeof(buffer),"%s/%s/%s",logDir,topic,outputFileName);
	d = calloc(1 + strlen(buffer),1);
	if ( 0 != d ) {
		strcpy(d,buffer);
	}
	
	return	d;
}
void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message) {
	char *topic;
	char *inputFileName;
	char *outputFileName;
	int packetNumber;
	int packetCount;
	char *packetData;
	int rc;
	FILE *in,*out;
	char *b = 0,*b2 = 0;
	
	
	/* cancel pending alarm */
	alarm(0);
	/* set an alarm to send a SIGALARM if data not received within alarmSeconds */
 	alarm(ALARM_SECONDS);


	if ( outputDebug )
		fprintf(stderr,"got message '%.*s' for topic '%s'\n", message->payloadlen, (char*) message->payload, message->topic);
	rc = parse_the_packet((char*) message->payload, message->payloadlen, 
		&topic,&inputFileName,&outputFileName,&packetNumber,&packetCount,&packetData);

	if ( 0 != rc ) {
		fprintf(stderr,"# unable to parse mqttFileSubscribe packet\n");
		exit( 1);
	}
	/* okay if here we have the entire packet we can write it out */
	out = fopen(b = _build_the_name(topic,outputFileName),"a");
	if ( 0 == out ) {
		fprintf(stderr,"unable to fopen %s.  %s\n",b,strerror(errno));
		goto cleanup;
	}
	(void) fputs(packetData,out);
	(void) fclose(out);

	if ( packetCount == packetNumber ) {
		/* the whole file has been transferred and must be decoded  */
		in = fopen(b,"r");
		out = fopen(b2 = _build_the_name(topic,inputFileName),"w");
		
		rc = decode(in,out);
		
		if ( 0 != in ) {
			fclose(in);
		}
		if ( 0 != out ) {
			fclose(out);
		}
		if ( 0 != rc ) {
			unlink(b);
			unlink(b2);
		} else {
			unlink(b);
		}
	}
	
	cleanup:
	free(topic);
	free(inputFileName);
	free(outputFileName);
	free(packetData);
}
void topics_mosquitto_subscribe(TOPICS *p, struct mosquitto *mosq)
{
if ( 0 == p )	return;
topics_mosquitto_subscribe(p->left,mosq);
mosquitto_subscribe(mosq, NULL, p->topic, 0);
topics_mosquitto_subscribe(p->right,mosq);
}
static int startup_mosquitto(void) {
	char clientid[24];
	struct mosquitto *mosq;
	int rc = 0;

	fprintf(stderr,"# mqtt-modbus start-up\n");

	fprintf(stderr,"# installing signal handlers\n");
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGALRM, signal_handler);

	fprintf(stderr,"# initializing mosquitto MQTT library\n");
	mosquitto_lib_init();

	memset(clientid, 0, 24);
	snprintf(clientid, 23, "mqtt_modbus_%d", getpid());
	mosq = mosquitto_new(clientid, true, 0);

	if (mosq) {
		mosquitto_connect_callback_set(mosq, connect_callback);
		mosquitto_message_callback_set(mosq, message_callback);

		fprintf(stderr,"# connecting to MQTT server %s:%d\n",mqtt_host,mqtt_port);
		rc = mosquitto_connect(mosq, mqtt_host, mqtt_port, 60);

		topics_mosquitto_subscribe(topic_root,mosq);

		while (run) {
			rc = mosquitto_loop(mosq, -1, 1);

			if ( run && rc ) {
				printf("connection error!\n");
				sleep(10);
				mosquitto_reconnect(mosq);
			}
		}
		mosquitto_destroy(mosq);
	}

	fprintf(stderr,"# mosquitto_lib_cleanup()\n");
	mosquitto_lib_cleanup();

	return rc;
}

int topics_enable_logging_dir(TOPICS *p )
{
int	rc;
if ( 0 == p )	return	0;
rc = topics_enable_logging_dir(p->left);
if ( 0 == rc ) rc =	_enable_logging_dir(p->topic);
if ( 0 == rc ) topics_enable_logging_dir(p->right);
return	rc;
}

enum arguments {
	A_mqtt_host = 512,
	A_mqtt_topic,
	A_mqtt_port,
	A_log_dir,
	A_quiet,
	A_verbose,
	A_help,
};
int main(int argc, char **argv) {
	int n;
	int rc;
	char	cwd[256] = {};
	(void) getcwd(cwd,sizeof(cwd));

	/* command line arguments */
	while (1) {
		// int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		static struct option long_options[] = {
			/* normal program */
		        {"log-dir",                          1,                 0, A_log_dir },
		        {"mqtt-host",                        1,                 0, A_mqtt_host },
		        {"mqtt-topic",                       1,                 0, A_mqtt_topic },
		        {"mqtt-port",                        1,                 0, A_mqtt_port },
			{"quiet",                            no_argument,       0, A_quiet, },
			{"verbose",                          no_argument,       0, A_verbose, },
		        {"help",                             no_argument,       0, A_help, },
			{},
		};

		n = getopt_long(argc, argv, "", long_options, &option_index);

		if (n == -1) {
			break;
		}
		
		switch (n) {
			case A_mqtt_host:	
				strncpy(mqtt_host,optarg,sizeof(mqtt_host));
				break;
			case A_mqtt_topic:
				add_topic(optarg);
				break;
			case A_mqtt_port:
				mqtt_port = atoi(optarg);
				break;
			case A_log_dir:	
				strncpy(logDir,optarg,sizeof(logDir));
				break;
			case A_verbose:
				outputDebug=1;
				fprintf(stderr,"# verbose (debugging) output to stderr enabled\n");
				break;
			case A_help:
				fprintf(stdout,"# --mqtt-host\t\t\tmqtt-host is required\tREQUIRED\n");
				fprintf(stdout,"# --mqtt-topic\t\t\tmqtt topic must be used at least once\n");
				fprintf(stdout,"# --mqtt-port\t\t\tmqtt port\t\tOPTIONAL\n");
				fprintf(stdout,"# --log-dir\t\t\tlogging directory, default=logLocal\n");
				fprintf(stdout,"#\n");
				fprintf(stdout,"# --help\t\t\tThis help message then exit\n");
				fprintf(stdout,"#\n");
				exit(0);
		}
	}
	 if ( ' ' >=  mqtt_host[0] ) {
               fprintf(stderr, "# --mqtt-host <required>\n");
               exit(EXIT_FAILURE);
	}
	else
	if ( 0 == topic_root ) {
		fprintf(stderr,"# There must be at least one --mqtt-topic\n");
               exit(EXIT_FAILURE);
	}


	/* install signal handler */
	signal(SIGALRM, signal_handler); /* timeout */
	signal(SIGUSR1, signal_handler); /* user signal to do data block debug dump */
	signal(SIGPIPE, signal_handler); /* broken TCP connection */

	if ( _enable_logging_dir(logDir)) {
		return	1;
	}
	chdir(logDir);
	if ( topics_enable_logging_dir(topic_root))
		return	1;

	chdir(cwd);
	rc = startup_mosquitto();
	


	return	rc;
}
