
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

static struct mosquitto *mosq;
static int mqtt_port=1883;
static char mqtt_host[256];
static char mqtt_topic[256];
static char input_file_name[256];
static char output_file_name[256];
static char *mqtt_user_name,*mqtt_passwd;
static int quiet_flag;
static int outputDebug;
static int disable_mqtt;

/*
** Translation Table as described in RFC1113
*/
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
** encodeblock
**
** encode 3 8-bit binary bytes as 4 '6-bit' characters
*/
static void encodeblock( unsigned char *in, unsigned char *out, int len ) {
    out[0] = (unsigned char) cb64[ (int)(in[0] >> 2) ];
    out[1] = (unsigned char) cb64[ (int)(((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ (int)(((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ (int)(in[2] & 0x3f) ] : '=');
}

/*
** encode
**
** base64 encode a stream adding padding and line breaks as per spec.
*/
static int encode( FILE *infile, FILE *outfile, int linesize ) {
    unsigned char in[3];
	unsigned char out[4];
    int i, len, blocksout = 0;
    int retcode = 0;

	*in = (unsigned char) 0;
	*out = (unsigned char) 0;
    while( feof( infile ) == 0 ) {
        len = 0;
        for( i = 0; i < 3; i++ ) {
            in[i] = (unsigned char) getc( infile );

            if( feof( infile ) == 0 ) {
                len++;
            }
            else {
                in[i] = (unsigned char) 0;
            }
        }
        if( len > 0 ) {
            encodeblock( in, out, len );
            for( i = 0; i < 4; i++ ) {
                if( putc( (int)(out[i]), outfile ) == EOF ){
	                if( ferror( outfile ) != 0 )      {
	                    perror( b64_message( B64_FILE_IO_ERROR ) );
	                    retcode = B64_FILE_IO_ERROR;
	                }
					break;
				}
            }
            blocksout++;
        }
        if( blocksout >= (linesize/4) || feof( infile ) != 0 ) {
            if( blocksout > 0 ) {
                /* fprintf( outfile, "\n" ); */
            }
            blocksout = 0;
        }
    }
    return( retcode );
}

void connect_callback(struct mosquitto *mosq, void *obj, int result) {
	fprintf(stderr,"# connect_callback, rc=%d\n", result);
}

static struct mosquitto * _mosquitto_startup(void) {
	char clientid[24];
	int rc = 0;


	fprintf(stderr,"# initializing mosquitto MQTT library\n");
	mosquitto_lib_init();

	memset(clientid, 0, 24);
	snprintf(clientid, 23, "mqtt-send-example_%d", getpid());
	mosq = mosquitto_new(clientid, true, 0);

	if (mosq) {
		if ( 0 != mosq,mqtt_user_name && 0 != mqtt_passwd ) {
			mosquitto_username_pw_set(mosq,mqtt_user_name,mqtt_passwd);
		}
		mosquitto_connect_callback_set(mosq, connect_callback);

		fprintf(stderr,"# connecting to MQTT server %s:%d\n",mqtt_host,mqtt_port);
		rc = mosquitto_connect(mosq, mqtt_host, mqtt_port, 60);

		/* start mosquitto network handling loop */
		mosquitto_loop_start(mosq);
		}

return	mosq;
}

static void _mosquitto_shutdown(void) {

	if ( mosq ) {
		
		/* disconnect mosquitto so we can be done */
		mosquitto_disconnect(mosq);
		/* stop mosquitto network handling loop */
		mosquitto_loop_stop(mosq,0);


		mosquitto_destroy(mosq);
		}

	fprintf(stderr,"# mosquitto_lib_cleanup()\n");
	mosquitto_lib_cleanup();
}
int mqttFilePublish_pub(const char *message ) {
	int rc = 0;
	if ( 0 == quiet_flag ) {
		fputs(message,stdout);
		fflush(stdout);
	}
	
	if ( 0 == disable_mqtt ) {

		static int messageID;
		/* instance, message ID pointer, topic, data length, data, qos, retain */
		rc = mosquitto_publish(mosq, &messageID, mqtt_topic, strlen(message), message, 0, 0); 

		if (0 != outputDebug) fprintf(stderr,"# mosquitto_publish provided messageID=%d and return code=%d\n",messageID,rc);

		/* check return status of mosquitto_publish */ 
		/* this really just checks if mosquitto library accepted the message. Not that it was actually send on the network */
		if ( MOSQ_ERR_SUCCESS == rc ) {
			/* successful send */
		} else if ( MOSQ_ERR_INVAL == rc ) {
			fprintf(stderr,"# mosquitto error invalid parameters\n");
		} else if ( MOSQ_ERR_NOMEM == rc ) {
			fprintf(stderr,"# mosquitto error out of memory\n");
		} else if ( MOSQ_ERR_NO_CONN == rc ) {
			fprintf(stderr,"# mosquitto error no connection\n");
		} else if ( MOSQ_ERR_PROTOCOL == rc ) {
			fprintf(stderr,"# mosquitto error protocol\n");
		} else if ( MOSQ_ERR_PAYLOAD_SIZE == rc ) {
			fprintf(stderr,"# mosquitto error payload too large\n");
		} else if ( MOSQ_ERR_MALFORMED_UTF8 == rc ) {
			fprintf(stderr,"# mosquitto error topic is not valid UTF-8\n");
		} else {
			fprintf(stderr,"# mosquitto unknown error = %d\n",rc);
		}
	}


	return	rc;
}
static void signal_handler(int signum) {


	if ( SIGALRM == signum ) {
		fprintf(stderr,"\n# Timeout while waiting for NMEA data.\n");
		fprintf(stderr,"# Terminating.\n");
		_mosquitto_shutdown();
		exit(100);
	} else if ( SIGPIPE == signum ) {
		fprintf(stderr,"\n# Broken pipe.\n");
		fprintf(stderr,"# Terminating.\n");
		_mosquitto_shutdown();
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
		_mosquitto_shutdown();
		exit(102);
	}

}
enum arguments {
	A_input_file_name = 512,
	A_mqtt_host,
	A_mqtt_topic,
	A_mqtt_port,
	A_mqtt_user_name,
	A_mqtt_password,
	A_quiet,
	A_verbose,
	A_disable_mqtt,
	A_help,
};

char	*strsave(char *s )
{
char	*ret_val = 0;

ret_val = malloc(strlen(s)+1);
if ( 0 != ret_val) strcpy(ret_val,s);
return ret_val;	
}
static void publish_packet(int packet_number,int packet_count,char *packet,int packet_len) {
	struct json_object *jobj = json_object_new_object();
	json_object_object_add(jobj,"topic",json_object_new_string(mqtt_topic));
	json_object_object_add(jobj,"inputFileName",json_object_new_string(basename(input_file_name)));
	json_object_object_add(jobj,"outputFileName",json_object_new_string(basename(output_file_name)));
	json_object_object_add(jobj,"packetNumber",json_object_new_int(packet_number + 1));
	json_object_object_add(jobj,"packetCount",json_object_new_int(packet_count));
	packet[packet_len] = '\0';	/* make sure it is a string */
	json_object_object_add(jobj,"packetData",json_object_new_string(packet));

	const char *d = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY);
	mqttFilePublish_pub(d);
	json_object_put(jobj);

}
static int publish_file(void) {
	/* game plan is to pubhish the file in 3000 byte backets
		because that is what IBM was doing using python.
           wrapped around bytes will be json that will contain
	  out-of-band information so we can re-assemble the file */
	struct stat buf;
	int i,file_size,packet_count,output_size = 0;
	FILE *in;

	if ( 0 != stat(output_file_name,&buf)) {
		fprintf(stderr,"# unable to stat %s.  %s\n",output_file_name,strerror(errno));
		return	1;
	}
	file_size = buf.st_size;
	packet_count = (file_size / 3000) + (( 0 != (file_size % 3000)) ? 1 : 0);
	in = fopen(output_file_name,"r");
	if ( 0 == in ) {
		fprintf(stderr,"# cannot open %s.   %s\n",output_file_name,strerror(errno));
		return	1;
	}
	for ( i = 0 ; packet_count > i ; i++ ) {
		int rd;
		char	buffer[3000 + 16] = {};
		rd = fread(buffer,1,3000,in);
		if ( 0 == rd ) {
			break;
		}
		publish_packet(i,packet_count,buffer,rd);
		output_size += rd;
	}
	if ( output_size != file_size ) {
		fprintf(stderr,"# bytes output %d != bytes base64 encoded %d\n",output_size,file_size);
		return	1;
	}

	return	0;
}
int main(int argc, char **argv) {
	int n,rc;
	FILE *in,*out;

	while (1) {
		// int this_option_optind = optind ? optind : 1;
		int option_index = 0;
		static struct option long_options[] = {
			/* normal program */
		        {"input-file-name",                  1,                 0, A_input_file_name },
		        {"mqtt-host",                        1,                 0, A_mqtt_host },
		        {"mqtt-topic",                       1,                 0, A_mqtt_topic },
		        {"mqtt-port",                        1,                 0, A_mqtt_port },
		        {"mqtt-user-name",                   1,                 0, A_mqtt_user_name },
		        {"mqtt-passwd",                      1,                 0, A_mqtt_password },
			{"disable-mqtt",                     no_argument,       0, A_disable_mqtt },
			{"quiet",                            no_argument,       0, A_quiet },
			{"verbose",                          no_argument,       0, A_verbose },
		        {"help",                             no_argument,       0, A_help },
			{},
		};

		n = getopt_long(argc, argv, "", long_options, &option_index);

		if (n == -1) {
			break;
		}
		

	/* command line arguments */
		switch (n) {
			case A_input_file_name:	
				strncpy(input_file_name ,optarg,sizeof(input_file_name));
				break;
			case A_mqtt_topic:	
				strncpy(mqtt_topic,optarg,sizeof(mqtt_topic));
				break;
			case A_mqtt_host:	
				strncpy(mqtt_host,optarg,sizeof(mqtt_host));
				break;
			case A_mqtt_port:
				mqtt_port = atoi(optarg);
				break;
			case A_mqtt_user_name:
				mqtt_user_name = strsave(optarg);
				break;
			case A_mqtt_password:
				mqtt_passwd = strsave(optarg);
				break;
			case A_verbose:
				outputDebug=1;
				fprintf(stderr,"# verbose (debugging) output to stderr enabled\n");
				break;
			case A_quiet:
				quiet_flag = 1;
				fprintf(stderr,"# quiet no output packets to standard out\n");
				break;
			case A_disable_mqtt:
				disable_mqtt = 1;
				fprintf(stderr,"# no mqtt publisting \n");
				break;
			case A_help:
				fprintf(stdout,"# --input-file-name\t\tfile to be sent\n");
				fprintf(stdout,"# --disable-mqtt\t\tdisable mqtt output\n");
				fprintf(stdout,"# --mqtt-topic\t\t\tmqtt topic\n");
				fprintf(stdout,"# --mqtt-host\t\t\tmqtt host\n");
				fprintf(stdout,"# --mqtt-port\t\t\tmqtt port(optional)\n");
				fprintf(stdout,"# --mqtt-user-name\t\t\tmaybe required depending on system\n");
				fprintf(stdout,"# --mqtt-passwd\t\t\tmaybe required depending on system\n");
				fprintf(stdout,"# --verbose\t\t\tOutput verbose / debugging to stderr\n");
				fprintf(stdout,"#\n");
				fprintf(stdout,"# --help\t\t\tThis help message then exit\n");
				fprintf(stdout,"#\n");
				exit(0);
		}
	}
	if (  0 == disable_mqtt && ' ' >= mqtt_host[0] ) { 
		fputs("# <--mqtt-host is requied when outputting to mqtt>\n",stderr); 
		exit(1); 
	} else {
		fprintf(stderr,"# --mqtt-host=%s\n",mqtt_host);
	}
	if (  0 == disable_mqtt && ' ' >= mqtt_topic[0] ) { 
		fputs("# <--mqtt-topic> is required  when outputting to mqtt\n",stderr); 
		exit(1); 
	} else {
		fprintf(stderr,"# --mqtt-topic=%s\n",mqtt_topic);
	}
	if (  ' ' >= input_file_name[0] ) { 
		fputs("# <--input-file-name> is required \n",stderr); 
		exit(1); 
	} else {
		fprintf(stderr,"# --input-file-name=%s\n",input_file_name);
	}

	snprintf(output_file_name,sizeof(output_file_name),"%s.%d",input_file_name,getpid());

	in = fopen(input_file_name,"rb");
	if ( 0 == in ) {
		fprintf(stderr,"# unable to fopen %s. %s\n",input_file_name,strerror(errno));
		exit(0);
	}
	out = fopen(output_file_name,"wb");
	if ( 0 == in ) {
		fprintf(stderr,"# unable to fopen %s. %s\n",output_file_name,strerror(errno));
		exit(0);
	}
	rc = encode(in,out,100000000);	/* 100000000 means no newline in the first 100,000,000 bytes */

	fclose(in);
	fclose(out);

	if ( 0 != rc ) {
		fprintf(stderr,"# encode() returns %d\n",rc);
		return	1;
	}

	/* install signal handler */
	signal(SIGALRM, signal_handler); /* timeout */
	signal(SIGUSR1, signal_handler); /* user signal to do data block debug dump */
	signal(SIGPIPE, signal_handler); /* broken TCP connection */



	if ( 0 == disable_mqtt && 0 == _mosquitto_startup() ) {
		return	1;
	}

	sleep(1);	fflush(stderr);

	rc = publish_file();
	unlink(output_file_name);
	if ( 0 == disable_mqtt ) {
		_mosquitto_shutdown();
	}

	return	0;
}
