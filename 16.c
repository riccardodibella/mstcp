#define _DEFAULT_SOURCE
#define _GNU_SOURCE // strcasestr

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <net/if.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <time.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdarg.h>
#include <sys/stat.h>

/* DEFINE MACROS */

//#define NOLOGS
//#define SHORTLOGS

#define MIN(x,y) ( ((x) > (y)) ? (y) : (x) )
#define MAX(x,y) ( ((x) < (y)) ? (y) : (x) )


#define RESP_PAYLOAD_BYTES 100000

#define CL_MAIN_PARALLEL 1
#define CL_MAIN_SERIAL_BLOCKING 2
#define CL_MAIN_AGGREGATE 3
#define CL_MAIN_HTML 4

#define CL_MAIN CL_MAIN_AGGREGATE

#if CL_MAIN == CL_MAIN_PARALLEL
#define NUM_CLIENTS 10
#define NUM_CLIENT_REQUESTS 100
#endif

#if CL_MAIN == CL_MAIN_SERIAL_BLOCKING
#define NUM_CLIENT_REQUESTS 100
/*
int num_req_arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
int payload_size_arr[] = {10, 100, 1000, 10000, 100000};
*/
/*
int num_req_arr[] = {1, 2, 4, 6, 8, 10};
int payload_size_arr[] = {10, 100, 1000, 2000, 5000, 10000, 20000};
*/
int num_req_arr[] = {/*1, 2, 4, 6, 8, */10};
//int payload_size_arr[] = {/*200, 2000, 20000, 200000*/};
int payload_size_arr[] = {200};

//int num_req_arr[] = {1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
//int payload_size_arr[] = {2000};
#undef RESP_PAYLOAD_BYTES
#define RESP_PAYLOAD_BYTES 200000
#endif

#if CL_MAIN == CL_MAIN_AGGREGATE
#define NUM_CLIENTS_MAX 6
#define NUM_CLIENT_REQUESTS_MAX 6
int num_client_requests_test = 6;

#define MS_ENABLED false
// TCP: 1, 6
// MS: 1, 6, 32
int num_clients_arr[] = {6}; 
int payload_size_arr[] = {100};

#undef RESP_PAYLOAD_BYTES
#define RESP_PAYLOAD_BYTES 100 // This is the maximum

//#define DELAY_REQ_PROB 1E-1

#endif

#if CL_MAIN == CL_MAIN_HTML
#define MS_ENABLED false
#define NUM_CLIENTS 6
#endif

#define REQ_BUF_SIZE 100
#define RESP_BUF_SIZE 100+RESP_PAYLOAD_BYTES


#define UPLINK_DROP_PROB 0
#define DOWNLINK_DROP_PROB 0


//#define STREAM_DROP_ENABLED
#ifdef STREAM_DROP_ENABLED
const int DROP_TARGET_STREAMS[] = {1, 5};
#define UPLINK_STREAM_DROP_PROB 0
#define DOWNLINK_STREAM_DROP_PROB 1E-1
#endif

#define DELAY_DURATION_MS 1000

#define CLIENT 0
#define SERVER 1
#ifndef MAIN_MODE // Compile with -DMAIN_MODE=CLIENT or -DMAIN_MODE=SERVER
#define MAIN_MODE CLIENT
#endif

#ifndef MS_ENABLED
#define MS_ENABLED true
#endif

#if MAIN_MODE == SERVER
#undef MS_ENABLED
#define MS_ENABLED true
#endif

#define MYREAD_MODE_BLOCKING 1
#define MYREAD_MODE_NON_BLOCKING 2
#define MYWRITE_MODE_BLOCKING 1
#define MYWRITE_MODE_NON_BLOCKING 2
#define MYACCEPT_MODE_BLOCKING 1
#define MYACCEPT_MODE_NON_BLOCKING 2
#define MYCONNECT_MODE_BLOCKING 1
#define MYCONNECT_MODE_NON_BLOCKING 2

#ifdef LOCAL_SERVER
#define SERVER_IP_STR "127.0.0.1"
#else
#define SERVER_IP_STR "172.104.237.69"
#endif

#define INTERFACE_NAME "eth0" // load_ifconfig
#define TIMER_USECS 500
//#define TIMER_USECS 5000
#define MAX_ARP 200 // number of lines in the ARP cache


#ifdef NUM_CLIENTS

#define MAX_FD 4 + NUM_CLIENTS // File descriptors go from 3 (included) up to this value (excluded)

#else
#ifdef NUM_CLIENTS_MAX
#define MAX_FD 4 + NUM_CLIENTS_MAX // File descriptors go from 3 (included) up to this value (excluded)

#else
#if CL_MAIN == CL_MAIN_SERIAL_BLOCKING

#define MAX_FD 10 + NUM_CLIENT_REQUESTS

#else

#define MAX_FD 10 // File descriptors go from 3 (included) up to this value (excluded)

#endif
#endif
#endif

#define L2_RX_BUF_SIZE 30000
#define MIN_TIMEOUT_MSEC 300
#define MIN_TIMEOUT (MIN_TIMEOUT_MSEC * 1000 / TIMER_USECS)
#define INIT_TIMEOUT_SEC 1
#define INIT_TIMEOUT (INIT_TIMEOUT_SEC * 1000000 / TIMER_USECS)
#define MAX_TIMEOUT_SEC 10
#define MAX_TIMEOUT (MAX_TIMEOUT_SEC * 1000000 / TIMER_USECS)
//#define MAXTIMEOUT 10000
// #define TODO_BUFFER_SIZE 64000
#define RX_VIRTUAL_BUFFER_SIZE (1024*1024)
#define DEFAULT_WINDOW_SCALE 10 // Default parameter sent during the handshake

#define TX_BUFFER_SIZE (1024*1024)
#define STREAM_OPEN_TIMEOUT 2 // in ticks

#define MIN_PORT 19000
#define MAX_PORT 19999

#define TCP_PROTO 6 // protocol field inside IP header

#define TCP_MSS 1260
//#define TCP_MSS 1460 // MTU = 1500, MSS = MTU - 20 (IP Header) - 20 (TCP Header)
#define FIXED_OPTIONS_LENGTH 40
#define MAX_SEGMENT_PAYLOAD (TCP_MSS - FIXED_OPTIONS_LENGTH) // 1420, may be used for congestion control


// SID = Stream ID
#define SID_UNASSIGNED -1
#define TOT_SID 32
#define MAX_SID (TOT_SID - 1)

#define FDINFO_ST_FREE 0 // mytcp: FREE
#define FDINFO_ST_UNBOUND 1 // mytcp: TCP_UNBOUND
#define FDINFO_ST_BOUND 2 // mytcp: TCP_BOUND
#define FDINFO_ST_TCB_CREATED 3 // mytcp: TCB_CREATED

#define FSM_EVENT_APP_ACTIVE_OPEN 1
#define FSM_EVENT_APP_PASSIVE_OPEN 2
#define FSM_EVENT_PKT_RCV 3
#define FSM_EVENT_APP_CLOSE 4
#define FSM_EVENT_TIMEOUT 5 // Channel timeout (connection closing)
#define FSM_EVENT_STREAM_TIMEOUT 6 // Stream timeout (no data has been sent upon stream opening, so a dummy byte is sent on that stream to open it)

#define TCB_ST_CLOSED 10 // initial state
#define TCB_ST_LISTEN 11  // represents waiting for a connection request from any remote TCP and port.
#define TCB_ST_SYN_SENT 12 // represents waiting for a matching connection request after having sent a connection request.
#define TCB_ST_SYN_RECEIVED 13 // represents waiting for a confirming connection request acknowledgment after having both received and sent a connection request.
#define TCB_ST_ESTABLISHED 14 // represents an open connection, data received can be delivered to the user.  The normal state for the data transfer phase of the connection.
#define TCB_ST_FIN_WAIT_1 15 // waiting for a connection termination request from the remote TCP, or an acknowledgment of the conne
#define TCB_ST_FIN_WAIT_2 16 // waiting for a connection termination request from the remote TCP.
#define TCB_ST_CLOSE_WAIT 17 // waiting for a connection termination request from the local user.
#define TCB_ST_CLOSING 18  // waiting for a connection termination request acknowledgment from the remote TCP.
#define TCB_ST_LAST_ACK 19 // waiting for an acknowledgment of the connection termination request previously sent to the remote TCP
#define TCB_ST_TIME_WAIT 20 // waiting for enough time to pass to be sure the remote TCP received the acknowledgment of its connecti

#define STREAM_STATE_UNUSED 0
#define STREAM_STATE_READY 1 // only for passive open before accept
#define STREAM_STATE_OPENED 2


// The following is not true! State CLOSED is never used, instead it returns to UNUSED when these conditions are true
// Transitions to state CLOSED must be managed in 2 points: when write_side_close_state becomes LSS_ACKED, and where the flag lss_received is set, during myio
#define STREAM_STATE_CLOSED 3
// Transition back to state UNUSED may be done after a timeout, but this is TBD; After coming back to state unused, an endpoint must still discard segments with LSS flag set, because they are window updates of the old stream


// Values for write_side_close_state
#define WR_CLOSE_ST_OPEN 0 // close() has not been called
#define WR_CLOSE_ST_LSS_REQUESTED 1 // close() has been called, we are waiting for the scheduler to enqueue the LSS once all the data is in the TX queue
#define WR_CLOSE_ST_LSS_TXED 2 // the LSS has been enqueued in the TX queue (and TXed as soon as possible)
#define WR_CLOSE_ST_LSS_ACKED 3 // the LSS has been removed from the TX queue because it has been ACKed (with SACK or with cumulative ACK)
// If state > OPEN, we can no longer call close() or write()
// If state >= LSS_TXED, all the segments that will be added with prepare_tcp will have the LSS flag set automatically, to allow stream reuse detection at the other side

#define FIN 0x001
#define SYN 0x002
#define RST	0x004
#define PSH 0x008
#define ACK 0x010
#define URG 0x020
#define ECE 0x040
#define CWR 0x080
#define DMP 0x100 // Dummy Payload

#define OPT_KIND_END_OF_OPT 0
#define OPT_KIND_NO_OP 1
#define OPT_KIND_MSS 2
#define OPT_KIND_WIN_SCALE 3
#define OPT_KIND_SACK_PERM 4
#define OPT_KIND_SACK 5
#define OPT_KIND_TIMESTAMPS 8
#define OPT_KIND_MS_TCP 253

/* Congestion Control Parameters*/
#define ALPHA 1
#define BETA 4
#define KRTO 6
#define CONGCTRL_ST_SLOW_START 0
#define CONGCTRL_ST_CONG_AVOID 1
#define CONGCTRL_ST_FAST_RECOV 2
#define INIT_CGWIN 1 //in MSS
#define INIT_THRESH 8 //in MSS

/* STRUCT DEFINITIONS */

struct arpcacheline {
	unsigned int key; //IP address
	unsigned char mac[6]; //Mac address
};

struct ethernet_frame {
	unsigned char dstmac[6];
	unsigned char srcmac[6];
	unsigned short int type;
	unsigned char payload[10];
};

struct arp_packet {
	unsigned short int htype;
	unsigned short int ptype;
	unsigned char hlen;
	unsigned char plen;
	unsigned short op;
	unsigned char srcmac[6];
	unsigned char srcip[4];
	unsigned char dstmac[6];
	unsigned char dstip[4];
};

struct ip_datagram {
	unsigned char ver_ihl;
	unsigned char tos;
	unsigned short totlen;
	unsigned short id;
	unsigned short fl_offs;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned int srcaddr;
	unsigned int dstaddr;
	unsigned char payload[20];
};

struct pseudoheader {
	unsigned int s_addr, d_addr;
	unsigned char zero;
	unsigned char prot;
	unsigned short len;
};

struct tcp_segment {
	unsigned short s_port;
	unsigned short d_port;
	unsigned int seq;
	unsigned int ack;
	unsigned char d_offs_res; 
	unsigned char flags; 
	unsigned short window;
	unsigned short checksum;
	unsigned short urgp;
	unsigned char payload[TCP_MSS];
};

/*
struct txcontrolbuf{
	struct tcp_segment * segment;
	int totlen;
	int payloadlen;
	long long int txtime;
	struct txcontrolbuf * next;
	int retry;
};
*/
struct txcontrolbuf{ // mytcp: txcontrolbuf
	struct txcontrolbuf* next;
	uint32_t seq; // channel sequence
	int sid;
	int ssn;
	int payloadlen;
	bool dummy_payload;
	int totlen; // Includes IP header, TCP header, options and padding
	struct tcp_segment* segment;

	int64_t txtime;
	int retry;
};

struct channel_rx_queue_node{
	struct channel_rx_queue_node* next;
	struct channel_rx_queue_node* prev;
	uint32_t channel_offset; // sequence number - tcb->ack_offs
	int total_segment_length;
	int payload_length;
	int sid;
	bool lss;
	bool dummy_payload;
	struct tcp_segment* segment;
};
struct stream_rx_queue_node{
	struct stream_rx_queue_node* next;
	int sid;
	uint16_t ssn;
	bool lss; // LSS flag in MS option
	int total_segment_length;
	int payload_length;
	bool dummy_payload; // DMP flag

	/* This is the index at which the next byte will be read. 
	If this becomes equal to payload_length it can be removed from the stream RX queue */
	int consumed_bytes;
	struct tcp_segment* segment;
};



struct tcpctrlblk{
	int stream_state[TOT_SID];
	uint32_t adwin[TOT_SID];
	uint32_t radwin[TOT_SID];
	unsigned char* stream_tx_buffer[TOT_SID]; // not present in mytcp
	//unsigned char* stream_rx_buffer[TOT_SID]; // mytcp: rxbuffer
	//unsigned int rx_win_start[TOT_SID]; // Index at which we can read the next byte in the RX buffer
	unsigned int txfree[TOT_SID]; // Free space in the tx buffer
	unsigned int tx_buffer_occupied_region_start[TOT_SID]; // Index of the first occupied slot in the circular stream_tx_buffer
	unsigned int tx_buffer_occupied_region_end[TOT_SID]; // Index of the first empty slot in the circular stream_tx_buffer
	uint16_t next_ssn[TOT_SID]; // Next SSN that will be assigned for an outgoing segment on a stream
	uint16_t next_rx_ssn[TOT_SID]; // SSN of the next segment that has to be inserted in the buffer
	unsigned int stream_fsm_timer[TOT_SID]; // used for stream opening timeout; has to be set to 0 if a packet is sent on that stream
	struct stream_rx_queue_node* stream_rx_queue[TOT_SID]; // Contains only in-order segments for each stream, ready to be consumed by myread()
	struct stream_rx_queue_node* stream_rx_queue_tail[TOT_SID];

	// "write" direction
	int write_side_close_state[TOT_SID];

	// "read" direction
	bool lss_received[TOT_SID]; // LSS dequeued from channel queue and enqueued in stream queue
	bool lss_consumed[TOT_SID]; // LSS consumed from channel queue: subsequent read() calls must return 0

    int st; // Channel property

    /* 
    Channel TX queue pointers 
    They are a channel property, but they are filled differently between 
    standard TCP (new data is inserted in the queue as soon as it is available) 
    and MS-TCP (data to TX is consumed and inserted in this queue by a scheduler)
    */
	struct txcontrolbuf *txfirst, * txlast;

	unsigned short r_port; // Channel property
	unsigned int r_addr; // Channel property
	struct channel_rx_queue_node* unack; // mytcp: struct rxcontrol* unack ; Channel queue of RXed packets yet to be acked
	struct channel_rx_queue_node* unack_tail;
	unsigned int cumulativeack; // Channel property
	unsigned int ack_offs; // Channel property
    unsigned int seq_offs; // Channel property
	long long timeout; // Channel property
	unsigned int sequence; // Channel property 
	unsigned int mss; // Channel property
	unsigned int payload_mss; // mss - FIXED_OPTIONS_LENGTH (when ms-tcp is enabled, otherwise... I don't yet know)
	unsigned int stream_end; // Channel property (bad name)
	unsigned int fsm_timer; // Channel property
	uint32_t init_radwin; // Used in MS-TCP as a default value for radwin of new streams

	bool is_active_side; // Channel property
	int listening_fd; // If it is a passive TCB, this is the fd of the listening socket where streams have to be inserted
    /* 
    True if the MS option is inserted in the SYN. 
    This information is used in the fsm for the SYN+ACK reception to know if the MS option has to be considered or not
    */
	bool ms_option_requested; // Channel property
    bool ms_option_enabled; // Channel property
    /*
    Packets that are sent by the local node contain a window that is scaled down by this factor (2^factor)
    */
	uint8_t out_window_scale_factor; // Channel property
    /*
    The remote window is scaled up by this factor (2^factor)
    */
	uint8_t in_window_scale_factor; // Channel property
    /*
    https://www.ietf.org/rfc/rfc1323.txt pp. 15-16
    */
	uint32_t ts_recent; // Channel property
	uint32_t ts_offset; // Channel property, assumes the value of the 1st TS received from the peer

	/* CONGESTION CONTROL (channel properties) */
	unsigned int ssthreshold;
	unsigned int rtt_e;
	unsigned int Drtt_e;
	unsigned int cong_st;
	unsigned int last_ack;
	unsigned int repeated_acks;
	unsigned int flightsize;
	unsigned int cgwin;
	unsigned int lta;
};

/*
struct tcb_list_node {
	struct tcpctrlblk* tcb;
	struct tcb_list_node* next;
};
*/
struct stream_backlog_node{
	struct tcpctrlblk* tcb;
	int sid;
	struct stream_backlog_node* next;
};

struct socket_info {
	int st; 
	int sid; // stream id
	struct tcpctrlblk * tcb; // the TCB is created in the FSM during myconnect and mylisten (active and passive open events)
	unsigned short l_port;
	unsigned int l_addr;

	struct stream_backlog_node stream_backlog_head; 
	struct tcpctrlblk* channel_backlog; // Backlog listen queue (mytcp: tcblist)
	int ready_streams; // Number of streams ready to be consumed by accept()
	int ready_channels; // Number of TCBs currently in the backlog
	int backlog_length; // Maximum number of TCP connections that can be pending before starting to reset new connections (mytcp: bl)
};



/* GLOBAL VARIABLES */

int myread_mode = MYREAD_MODE_NON_BLOCKING;
int mywrite_mode = MYWRITE_MODE_NON_BLOCKING;
int myaccept_mode = MYACCEPT_MODE_NON_BLOCKING;
int myconnect_mode = MYCONNECT_MODE_NON_BLOCKING;

struct timespec short_sleep = {0, 1000}; // 0 seconds, 1000 nanoseconds (1 microsecond)

unsigned char myip[4];
unsigned char mymac[6];
unsigned char mask[4];
unsigned char gateway[4];

/* TXBUFSIZE and INIT_TIMEOUT may be modified at program startup */
//int TXBUFSIZE = 100000; // #define TXBUFSIZE    ((g_argc<3) ?100000:(atoi(g_argv[2])))  
// int INIT_TIMEOUT = 300*1000; // #define INIT_TIMEOUT (((g_argc<4) ?(300*1000):(atoi(g_argv[3])*1000))/TIMER_USECS)

int unique_raw_socket_fd = -1; // mytcp: unique_s

int last_port = MIN_PORT; // Last assigned port during bind()

int myerrno;

uint64_t tick; // global variable incremented by mytimer() every TIMER_USECS ms

/* 
	1: The lock is available (there is no handler running) 
	0: The lock is taken (there is already a handler running)

	Note that this behaviour is the opposite of what was done with the global variable fl in mytcp,
	but this is more aligned with a "mutex" semaphore interpretation.
*/
char global_handler_lock = 1; // acquire_handler_lock, release_handler_lock

sigset_t global_signal_mask; // mytcp: mymask

struct arpcacheline arpcache[MAX_ARP];

uint8_t l2_rx_buf[L2_RX_BUF_SIZE]; // mytcp: l2buf

struct socket_info fdinfo[MAX_FD]; // locations 0, 1 and 2 are left empty

uint8_t PAYLOAD_OPTIONS_TEMPLATE_MS[] = {
	OPT_KIND_MS_TCP, // If you change the position of the MS_TCP option, change also the update code (eg in fsm -> FSM_EVENT_STREAM_TIMEOUT)
	4,
	0,0,
	OPT_KIND_TIMESTAMPS,
	10,
	0,0,0,0,0,0,0,0,
	OPT_KIND_SACK,
	2
};
uint8_t PAYLOAD_OPTIONS_TEMPLATE[] = {
	OPT_KIND_TIMESTAMPS,
	10,
	0,0,0,0,0,0,0,0,
	OPT_KIND_SACK,
	2
};

FILE* log_file = NULL;
int log_array_items = 0;
int current_field_num = 0;

/* FUNCTION DEFINITIONS */

// In case you need to know the name of the caller function: https://stackoverflow.com/a/16100246
void ERROR(char* c, ...){
	#ifndef NO_DEBUG
	printf("ERROR %.6u: ", (uint32_t) tick);
	va_list args;
	va_start(args, c);
	vprintf(c, args);
	va_end(args);
	printf("\n");
	#endif
	exit(EXIT_FAILURE);
}

void DEBUG(char* c, ...){
	#ifndef NO_DEBUG
	printf("DEBUG %.6u: ", (uint32_t) tick);
	va_list args;
	va_start(args, c);
	vprintf(c, args);
	va_end(args);
	printf("\n");
	#endif
}

int64_t get_timestamp_ns(){
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
int64_t get_timestamp_us(){
	return get_timestamp_ns() / 1000;
}
int64_t get_timestamp_ms(){
	return get_timestamp_us() / 1000;
}

uint32_t get_tcp_timestamp_ms() {
	// https://claude.ai/share/111f2d20-c083-4748-88ea-7e8f8ab2e514
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// -1 if the option is not found, otherwise it returns the index for the "kind" field of the option
int search_tcp_option(struct tcp_segment* tcp, uint8_t kind){
	if(tcp == NULL){
		ERROR("search_tcp_option tcp NULL");
	}
	int to_return = -1;
	int optlen = ((tcp->d_offs_res)>>4)*4-20;
	int i;
	for(i=0; i<optlen; i++){
		if(tcp->payload[i] == OPT_KIND_END_OF_OPT){
			break;
		}
		if(tcp->payload[i] == OPT_KIND_NO_OP){
			continue;
		}

		if(tcp->payload[i] == kind){
			to_return = i;
			break;
		}
		
		int length = tcp->payload[i+1];
		i += length - 1; // with the i++ we go to the start of the next option
	}
	if(i>optlen){
		/* 
		This is probably not a problem of the local node (and it could be ignored), but if we are writing 
		the implementation at both sides of the connection this could allow to catch some bugs. We do not
		always check if the field is well formed, this check is useful only if the option is not found
		*/
		ERROR("search_tcp_option misaligned end of options (invalid last length)");
	}
	return to_return;
}
uint16_t update_next_ssn(uint16_t* ssn_field){
	uint16_t to_return = *ssn_field;
	*ssn_field = (to_return+1) % 1024; // 10 bits for ssn -> mod 1024
	return to_return;
}

uint32_t inflate_window_scale(uint16_t small_window, uint8_t factor){
	return ((uint32_t)small_window)<<factor;
}
uint16_t deflate_window_scale(uint32_t big_window, uint8_t factor){
	return (uint16_t)(big_window>>factor);
}

void LOG_TEXT(const char *text) {
	#ifdef NOLOGS
	return; // Disables logging
	#endif
    fwrite(text, 1, strlen(text), log_file);
}
void LOG_FIELD(char* field_name, char* c, ...){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	if(current_field_num > 0){
		LOG_TEXT(", ");
	}

	// Attribute name must be between double quotes
	LOG_TEXT("\"");
	LOG_TEXT(field_name);
	LOG_TEXT("\": ");
	va_list args;
	va_start(args, c);
	vfprintf(log_file, c, args);
	va_end(args);

	current_field_num++;
}
void LOG_OBJ_START(){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	if(log_array_items > 0){
		LOG_TEXT(",\n");
	}
	LOG_TEXT("{");
	log_array_items++;

	current_field_num = 0;

	LOG_FIELD("timestamp_us", "%"PRId64, get_timestamp_us());
}
void LOG_OBJ_END(){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	LOG_TEXT("}");
}

void LOG_TCP_SEGMENT(char* direction, uint8_t* segment_buf, int len){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	struct tcp_segment* tcp = (struct tcp_segment*) segment_buf;
	LOG_OBJ_START();
	LOG_FIELD("type", "\"PKT\"");
	LOG_FIELD("direction", "\"%s\"", direction);
	int payload_length = len - (4*(tcp->d_offs_res >> 4));
	LOG_FIELD("payload_length", "%d", payload_length);
	bool syn = tcp->flags & SYN;
	bool ack = tcp->flags & ACK;
	bool fin = tcp->flags & FIN;
	bool dmp = tcp->d_offs_res & (DMP >> 8);
	LOG_FIELD("SYN", "%s", syn?"true":"false");
	LOG_FIELD("ACK", "%s", ack?"true":"false");
	LOG_FIELD("FIN", "%s", fin?"true":"false");
	LOG_FIELD("DMP", "%s", dmp?"true":"false");
	
	LOG_FIELD("sequence_number", "%u", htonl(tcp->seq));
	if(ack){
		LOG_FIELD("ack_number", "%u", htonl(tcp->ack));
	}
	LOG_FIELD("window", "%u", htons(tcp->window));
	

	int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
	if(ms_index>=0){
		LOG_FIELD("lss", "%s", (tcp->payload[ms_index+2]>>7)?"true":"false");
		LOG_FIELD("sid", "%d", (tcp->payload[ms_index+2]>>2) & 0x1F);
		LOG_FIELD("ssn", "%d", (( tcp->payload[ms_index+2] & 0x3) << 8 ) | (tcp->payload[ms_index+3]));
	}
	#ifndef SHORTLOGS
	if(payload_length > 0 && !dmp){
		char* str = malloc(payload_length + 1);
		memcpy(str, ((uint8_t*)tcp->payload) + FIXED_OPTIONS_LENGTH, payload_length);
		str[payload_length] = 0;
		for(int i=0; i<payload_length; i++){
			if(( !(str[i] >= 'A' && str[i] <= 'Z') && !(str[i] >= 'a' && str[i] <= 'z') && !(str[i] >= '0' && str[i] <= '9') && !(str[i] == '/'||str[i] == '.'||str[i] == ':'))){
				str[i] = ' ';
			}
		}
		LOG_FIELD("payload_str", "\"%s\"", str);
		free(str);
	}
	#endif
	int ts_index = search_tcp_option(tcp, OPT_KIND_TIMESTAMPS);
	if(ts_index>=0){
		uint32_t ts_val = ntohl(*(uint32_t*) (tcp->payload+ts_index+2));
		uint32_t ts_recent = ntohl(*(uint32_t*) (tcp->payload+ts_index+6));
		LOG_FIELD("ts_val", "%"PRIu32, ts_val);
		LOG_FIELD("ts_recent", "%"PRIu32, ts_recent);
	}
	

	LOG_OBJ_END();
}
void LOG_RTT(double rtt_sec){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	LOG_OBJ_START();
	LOG_FIELD("type", "\"RTT\"");
	LOG_FIELD("value_s", "%f", rtt_sec);
	LOG_OBJ_END();
}
void LOG_RTO(long long rto_ticks){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	LOG_OBJ_START();
	LOG_FIELD("type", "\"RTO\"");
	LOG_FIELD("value_ticks", "%lld", rto_ticks);
	LOG_FIELD("value_s", "%f", ((double)rto_ticks)*TIMER_USECS/1000000);
	LOG_OBJ_END();
}
void LOG_CONGCTRL(struct tcpctrlblk* tcb){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	LOG_OBJ_START();
	LOG_FIELD("type", "\"CNG\"");
	LOG_FIELD("state", "%u", tcb->cong_st);
	LOG_FIELD("ssth", "%u", tcb->ssthreshold);
	LOG_FIELD("cgwin", "%u", tcb->cgwin+tcb->lta);
	LOG_FIELD("lta", "%u", tcb->lta);
	LOG_FIELD("p_mss", "%u", tcb->payload_mss);
	LOG_OBJ_END();
}
void LOG_SCHEDULER_BYTES(int sid, int available, int flow, int congestion){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	congestion = MAX(0, congestion);
	LOG_OBJ_START();
	LOG_FIELD("type", "\"SCB\"");
	LOG_FIELD("sid", "%d", sid);
	LOG_FIELD("av", "%d", available);
	LOG_FIELD("flow", "%d", flow);
	LOG_FIELD("cng", "%d", congestion);

	/*
	Limiting factor:	0 -> available (slow source)
						1 -> flow control (small window)
						2 -> congestion control
	*/
	int limiting = 0;
	int min = available;
	if(flow < min){
		limiting = 1;
		min = flow;
	}
	if(congestion < min){
		limiting = 2;
		min = congestion;
	}
	LOG_FIELD("min", "%d", min);
	LOG_FIELD("cause", "%d", limiting);
	LOG_OBJ_END();
}
void LOG_MESSAGE(char* msg){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	LOG_OBJ_START();
	LOG_FIELD("type", "\"MSG\"");
	LOG_FIELD("text", "\"%s\"", msg);
	LOG_OBJ_END();
}

void LOG_START(){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	char* filename;
	char* text;
	if(MAIN_MODE == CLIENT){
		filename = "log_client.json";
	}else{
		filename = "log_server.json";
	}

	log_file = fopen(filename, "w");
	if(log_file == NULL){
		perror("LOG_START fopen");
		ERROR("log_file not created");
	}
	text = "[\n";
	LOG_TEXT(text);
	LOG_MESSAGE("Program start");
}
void LOG_END(){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	if(log_file == NULL){
		// Prevents issues when the end function is called more than one time
		return;
	}
	LOG_MESSAGE("Program end");
	LOG_TEXT("\n]");
	fclose(log_file);
	log_file = NULL;
}

void exit_handler(int sig) {
    LOG_END();
    exit(0);
}

void print_tcp_segment(struct tcp_segment* tcp){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	#ifdef NODEBUG
	return;
	#endif
	printf("----TCP SEGMENT----\n");
	printf("PORTS: SRC %u DST %u\n", htons(tcp->s_port), htons(tcp->d_port));
	printf("SEQ %u ACK %u\n", htonl(tcp->seq), htonl(tcp->ack));
	printf("WINDOW: %u\n", htons(tcp->window));
	printf("FLAGS: ");
	/*
	#define FIN 0x001
	#define SYN 0x002
	#define RST	0x004
	#define PSH 0x008
	#define ACK 0x010
	#define URG 0x020
	#define ECE 0x040
	#define CWR 0x080
	#define DMP 0x100 // Dummy Payload
	*/
	if(tcp->flags & FIN){
		printf("FIN ");
	}
	if(tcp->flags & SYN){
		printf("SYN ");
	}
	if(tcp->flags & RST){
		printf("RST ");
	}
	if(tcp->flags & PSH){
		printf("PSH ");
	}
	if(tcp->flags & ACK){
		printf("ACK ");
	}
	if(tcp->flags & URG){
		printf("URG ");
	}
	if(tcp->flags & ECE){
		printf("ECE ");
	}
	if(tcp->flags & CWR){
		printf("CWR ");
	}
	if(tcp->d_offs_res & (DMP >> 8)){
		printf("DMP ");
	}
	printf("\n");
	int optlen = (tcp->d_offs_res >> 4)*4 - 20;
	printf("Option bytes: %d\n", optlen);
	for(int i=0; i<optlen; i++){
		printf("0x%.2x ", tcp->payload[i]);
		if(i>0 && ((i % 4)==3 || (i == optlen - 1))){
			printf("\n");
		}
	}
	int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
	if(ms_index>=0){
		printf("LSS %d SID %d SSN %d\n", tcp->payload[ms_index+2]>>7, (tcp->payload[ms_index+2]>>2) & 0x1F, (( tcp->payload[ms_index+2] & 0x3) << 8 ) | (tcp->payload[ms_index+3]));
	}

	printf("-------------------\n");
}
void print_mac(uint8_t* mac){
	#ifdef NODEBUG
	return;
	#endif
	for(int i=0; i<6; i++){
		printf("%.2X%s", mac[i],i!=5?":":"\n");
	}
}
void print_ip(uint8_t* ip){
	#ifdef NODEBUG
	return;
	#endif
	for(int i=0; i<4; i++){
		printf("%d%s", ip[i],i!=3?".":"\n");
	}
}
void print_ip_datagram(struct ip_datagram* ip){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	#ifdef NODEBUG
	return;
	#endif
	printf("----IP DATAGRAM----\n");
	printf("VER_IHL: 0x%.2x\n", ip->ver_ihl);
	printf("Source IP: ");
	print_ip((uint8_t*)&(ip->srcaddr));
	printf("Destination IP: ");
	print_ip((uint8_t*)&(ip->dstaddr));
	printf("L4 protocol: %d\n", ip->proto);
	printf("Total IP packet length: %d\n", htons(ip->totlen));
	printf("Total L4 packet length: %d\n", htons(ip->totlen) - (ip->ver_ihl&0xF)*4);
	if(ip->proto == TCP_PROTO){
		print_tcp_segment((struct tcp_segment*) ip->payload + (((ip->ver_ihl & 0x0F) * 4) - 20));
	}
	printf("-------------------\n");
}
void print_arp_packet(struct arp_packet* arp){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	#ifdef NODEBUG
	return;
	#endif
	/*
	struct arp_packet {
		unsigned short int htype;
		unsigned short int ptype;
		unsigned char hlen;
		unsigned char plen;
		unsigned short op;
		unsigned char srcmac[6];
		unsigned char srcip[4];
		unsigned char dstmac[6];
		unsigned char dstip[4];
	};
	*/
	printf("----ARP  PACKET----\n");
	printf("HTYPE: %d PTYPE: 0x%.4x\n", htons(arp->htype), htons(arp->ptype));
	printf("HLEN: %d PLEN: %d\n", arp->hlen, arp->plen);
	printf("OP: %d\n", arp->op);
	printf("Source MAC:");
	print_mac(arp->srcmac);
	printf("Destination MAC:");
	print_mac(arp->dstmac);
	printf("Source IP:");
	print_ip(arp->srcip);
	printf("Destination IP:");
	print_ip(arp->dstip);
	printf("-------------------\n");
}
void print_l2_packet(uint8_t* packet){
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	#ifdef NODEBUG
	return;
	#endif
	printf("---- L2 PACKET ----\n");
	printf("SRC MAC: ");
	print_mac(packet + 8);
	printf("DST MAC: ");
	print_mac(packet);
	struct ethernet_frame* eth = (struct ethernet_frame*) packet;
	printf("L3 Protocol: 0x%.4x\n", htons(eth->type));
	if(htons(eth->type) == 0x0800){
		print_ip_datagram((struct ip_datagram*) (packet+14));
	} else if(htons(eth->type) == 0x0806){
		print_arp_packet((struct arp_packet*) (packet+14));
	}
	printf("-------------------\n");
}

void myperror(char* message) {
	#ifdef NOLOGS
	return; // Disables logging
	#endif
	printf("MYPERROR %s: %s\n", message, strerror(myerrno));
}

void acquire_handler_lock(){
	if(global_handler_lock != 1){
		ERROR("acquire_handler_lock global_handler_lock %d != 1", global_handler_lock);
	}
	global_handler_lock--;
}

void release_handler_lock(){
	if(global_handler_lock != 0){
		ERROR("release_handler_lock global_handler_lock %d != 0", global_handler_lock);
	}
	global_handler_lock++;
}

void assert_handler_lock_acquired(char* error_string){
	if(global_handler_lock != 0){
		ERROR("assert_handler_lock_acquired fail %s", error_string);
	}
}

void enable_signal_reception(bool handler){
	release_handler_lock();
	if(!handler){
		if(-1 == sigprocmask(SIG_UNBLOCK, &global_signal_mask, NULL)){
			perror("sigprocmask"); 
			exit(EXIT_FAILURE);
		}
	}
}
void disable_signal_reception(bool handler){
	if(!handler){
		if(-1 == sigprocmask(SIG_BLOCK, &global_signal_mask, NULL)){
			perror("sigprocmask"); 
			exit(EXIT_FAILURE);
		}
	}
	acquire_handler_lock();
}

/* 
	nanosleep is restarted upon signal reception, 
	until the specified time elapses 
*/
void persistent_nanosleep(int sec, int nsec){
	struct timespec req = {sec, nsec}, rem;
	while(nanosleep(&req, &rem)){
		if(errno == EINTR){
			req = rem;
		}else if(errno == EAGAIN){
			continue;
		}else{
			perror("nanosleep persistent_nanosleep");
			exit(EXIT_FAILURE);
		}
	}
}



#pragma region STARTUP_FUNCTIONS
void raw_socket_setup(){
	unique_raw_socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (-1 == unique_raw_socket_fd) { 
		perror("Socket raw failed"); 
		exit(EXIT_FAILURE);
	}

	if (-1 == fcntl(unique_raw_socket_fd, F_SETOWN, getpid())){ 
		perror("fcntl setown"); 
		exit(EXIT_FAILURE);
	}
	int fdfl = fcntl(unique_raw_socket_fd, F_GETFL, NULL); 
	if(fdfl == -1) { 
		perror("fcntl f_getfl"); 
		exit(EXIT_FAILURE);
	}
	fdfl = fcntl(unique_raw_socket_fd, F_SETFL,fdfl|O_ASYNC|O_NONBLOCK); 
	if(fdfl == -1) { 
		perror("fcntl f_setfl"); 
		exit(EXIT_FAILURE);
	}
}

void load_ifconfig(){
	int temp_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(-1 == temp_socket){
		ERROR("load_ifconfig fd -1");
	}

	// https://www.ibm.com/docs/en/aix/7.2?topic=i-ioctl-socket-control-operations#ioctl_socket_control_operations__commtrf2-gen400__title__1
	struct ifreq ifr;
	struct sockaddr_in* addr_ptr;
	strcpy(ifr.ifr_name, INTERFACE_NAME);

	// ifr.ifr_addr is of type "struct sockaddr"
	addr_ptr = (struct sockaddr_in*) &ifr.ifr_addr;

	if(ioctl(temp_socket, SIOCGIFADDR, &ifr) == -1){
		perror("ioctl SIOCGIFADDR");
		exit(EXIT_FAILURE);
	}
	memcpy(myip, &(addr_ptr->sin_addr.s_addr), sizeof(myip));

	if(ioctl(temp_socket, SIOCGIFNETMASK, &ifr) == -1){
		perror("ioctl SIOCGIFNETMASK");
		exit(EXIT_FAILURE);
	}
	memcpy(mask, &(addr_ptr->sin_addr.s_addr), sizeof(mask));

	if(ioctl(temp_socket, SIOCGIFHWADDR, &ifr) == -1){
		perror("ioctl SIOCGIFHWADDR");
		exit(EXIT_FAILURE);
	}
	memcpy(mymac, ifr.ifr_hwaddr.sa_data, sizeof(mymac));

	FILE* gw_file = popen("ip route show default | awk '{print $3}'", "r");
	if(gw_file == NULL){
		perror("popen");
		exit(EXIT_FAILURE);
	}
	
	char* gw_str = malloc(1024);
	if (fgets(gw_str, 1024, gw_file) != NULL) {
		// Remove possible newline at the end of the string
		for(int i=0; i<strlen(gw_str); i++){
			if(gw_str[i] == '\n' || gw_str[i] == '\r'){
				gw_str[i] = 0;
				break;
			}
		}

		*((unsigned int*)gateway) = inet_addr(gw_str);
	}else{
		perror("fgets gateway load_ifconfig");
		exit(EXIT_FAILURE);
	}
	free(gw_str);
	pclose(gw_file);

	if(close(temp_socket) == -1){
		perror("temp_socket close\n");
		exit(EXIT_FAILURE);
	}
}
#pragma endregion STARTUP_FUNCTIONS





#pragma region RAW_SOCKET_ACCESS
int resolve_mac(unsigned int destip, unsigned char * destmac){
	int len,n,i;
	struct sockaddr_ll sll;
	clock_t start;
	unsigned char pkt[1500];
	struct ethernet_frame *eth;
	struct arp_packet *arp;
	for(i=0;i<MAX_ARP && (arpcache[i].key!=0);i++){
		if(!memcmp(&arpcache[i].key,&destip,4)) 
			break;
	}
	if(arpcache[i].key){ //If found return 
		memcpy(destmac,arpcache[i].mac,6); 
		return 0; 
	}
	eth = (struct ethernet_frame *) pkt;
	arp = (struct arp_packet *) eth->payload; 
	for(i=0;i<6;i++) eth->dstmac[i]=0xff;
	for(i=0;i<6;i++) eth->srcmac[i]=mymac[i];
	eth->type=htons(0x0806);
	arp->htype=htons(1);
	arp->ptype=htons(0x0800);
	arp->hlen=6;
	arp->plen=4;
	arp->op=htons(1);
	for(i=0;i<6;i++) arp->srcmac[i]=mymac[i];
	for(i=0;i<4;i++) arp->srcip[i]=myip[i];
	for(i=0;i<6;i++) arp->dstmac[i]=0;
	for(i=0;i<4;i++) arp->dstip[i]=((unsigned char*) &destip)[i];

	len = sizeof(sll);
	bzero(&sll, len);
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(INTERFACE_NAME);

	n=sendto(unique_raw_socket_fd,pkt,14+sizeof(struct arp_packet), 0,(struct sockaddr *)&sll,len);
	if(n < 0){
		perror("resolve_mac sento failed");
		exit(EXIT_FAILURE);
	}
	release_handler_lock();

	sigset_t tmpmask=global_signal_mask;
	if( -1 == sigdelset(&tmpmask, SIGALRM)){
		perror("sigdelset resolve_mac");
		exit(EXIT_FAILURE);
	} 
	sigprocmask(SIG_UNBLOCK, &tmpmask,NULL);
	start=clock();

	while(pause()){ //wake up only upon signals (only I/O)
		for(i=0;(i<MAX_ARP) && (arpcache[i].key!=0);i++){
			if(!memcmp(&arpcache[i].key,&destip,4)) 
				break;
		}
		if(arpcache[i].key){ 
			// found in cache
			memcpy(destmac,arpcache[i].mac,6);
			sigprocmask(SIG_BLOCK,&tmpmask,NULL);
			acquire_handler_lock();
			
			return 0;
		}
		if((clock()-start) > CLOCKS_PER_SEC/100){
			break;
		}
	}
	sigprocmask(SIG_BLOCK,&tmpmask,NULL);
	
	acquire_handler_lock();
	
	ERROR("resolve_mac not resolved");
	return -1; //Not resolved
}

unsigned short int ip_checksum(char * b, int len){
	unsigned short total = 0;
	unsigned short prev = 0;
	unsigned short *p = (unsigned short * ) b;
	int i;
	for(i=0; i < len/2 ; i++){
		total += ntohs(p[i]);
		if (total < prev ) total++;
		prev = total;
		} 
	if ( i*2 != len){
		//total += htons(b[len-1]<<8); 
		total += htons(p[len/2])&0xFF00;
		if (total < prev ) total++;
		prev = total;
	}
	return (0xFFFF-total);
}

void forge_ip(struct ip_datagram * ip, int payloadsize, char proto, unsigned int target){
	static uint16_t id_counter = 0;
	ip->ver_ihl=0x45;
	ip->tos=0;
	ip->totlen=htons(20+payloadsize);
	ip->id = htons(id_counter);
	id_counter++;
	ip->fl_offs=htons(0);
	ip->ttl=128;
	ip->proto = proto;
	ip->checksum=htons(0);
	ip->srcaddr= *(unsigned int*)myip;
	ip->dstaddr= target;
	ip->checksum = htons(ip_checksum((unsigned char *)ip,20));
}

void forge_ethernet(struct ethernet_frame* eth, unsigned char * dest, unsigned short type){
	memcpy(eth->dstmac,dest,6);
	memcpy(eth->srcmac,mymac,6);
	eth->type=htons(type);
};


/* https://claude.ai/share/f7371349-a8ae-4f55-be35-ee61579db202 */

// 0 value is not acceptable, so we know that the PRNG has not been initialized
uint32_t prng_state = 0;

// Optional: seed the generator
void seed_prng(uint32_t seed) {
    prng_state = seed ? seed : 1;  // Ensure non-zero
}

// Doesn't really sample the whole space of uint32_t because 0 is missing AFAIK
uint32_t sample_uint32(){
	if(prng_state == 0){
		seed_prng(time(NULL));
	}
	// LCG: next = (a * current + c) mod m
	// Using constants from Numerical Recipes
	prng_state = prng_state * 1664525U + 1013904223U;
	return htonl(prng_state);
}

// Returns a double drawn uniformly in the range [0,1)
double sample_uniform_0_1(){
	if(prng_state == 0){
		seed_prng(time(NULL));
	}
	// LCG: next = (a * current + c) mod m
	// Using constants from Numerical Recipes
	prng_state = prng_state * 1664525U + 1013904223U;

	// Convert to [0,1] range
	// Divide by 2^32 to get [0,1)
	return (double)prng_state / 4294967296.0;
}
bool drop_packet(struct tcp_segment* tcp){
	#if defined(UPLINK_DROP_PROB) || defined(DOWNLINK_DROP_PROB)
	double relevant_drop_prob = (MAIN_MODE == CLIENT)? UPLINK_DROP_PROB : DOWNLINK_DROP_PROB;
	double sample = sample_uniform_0_1();
	if(sample < relevant_drop_prob){
		return true;
	}
	#endif

	#ifdef STREAM_DROP_ENABLED
	if(sizeof(DROP_TARGET_STREAMS) > 0){
		int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
		if(ms_index>=0){
			int sid = (tcp->payload[ms_index+2]>>2) & 0x1F;
			for(int i=0; i<sizeof(DROP_TARGET_STREAMS)/sizeof(DROP_TARGET_STREAMS[0]);i++){
				if(sid == DROP_TARGET_STREAMS[i]){
					relevant_drop_prob = (MAIN_MODE == CLIENT)? UPLINK_STREAM_DROP_PROB : DOWNLINK_STREAM_DROP_PROB;
					sample = sample_uniform_0_1();
					if(sample < relevant_drop_prob){
						DEBUG("drop sid %d", sid);
						return true;
					}
					// We do not break here! we could have the same sid multiple times, to increase its drop probability
				}
			}
		}
	}
	#endif

	return false;
}

void send_ip(unsigned char * payload, unsigned char * targetip, int payloadlen, unsigned char proto){
	int i,t,len ;
	struct sockaddr_ll sll;
	unsigned char destmac[6];
	unsigned char packet[2000];
	struct ethernet_frame * eth = (struct ethernet_frame *) packet;
	struct ip_datagram * ip = (struct ip_datagram *) eth->payload; 

	if(proto == TCP_PROTO){
		if(drop_packet((struct tcp_segment*)payload)){
			DEBUG("Packet dropped! <======================");
			LOG_TCP_SEGMENT("DROP", payload, payloadlen);
			return;
		}
	}

	/**** HOST ROUTING */
	if( ((*(unsigned int*)targetip) & (*(unsigned int*) mask)) == ((*(unsigned int*)myip) & (*(unsigned int*) mask)))
		t = resolve_mac(*(unsigned int *)targetip, destmac); // if yes
	else
		t = resolve_mac(*(unsigned int *)gateway, destmac); // if not
	if(t==-1){
		ERROR("send_ip resolve_mac failed");
	}

	if(proto == TCP_PROTO){
		LOG_TCP_SEGMENT("OUT", payload, payloadlen);
	}
	forge_ethernet(eth,destmac,0x0800);
	forge_ip(ip,payloadlen,proto,*(unsigned int *)targetip); 
	memcpy(ip->payload,payload,payloadlen);

	len=sizeof(sll);
	bzero(&sll,len);
	sll.sll_family=AF_PACKET;
	sll.sll_ifindex = if_nametoindex(INTERFACE_NAME);

	const int num_bytes_sendto = 14+20+payloadlen;
	int attempts = 0;
	st:
	;
	t=sendto(unique_raw_socket_fd, packet,num_bytes_sendto, 0, (struct sockaddr *)&sll,len);
	/*
	if (t == -1) {
		if(errno == EMSGSIZE){
			ERROR("EMSGSIZE");
		}
		perror("send_ip sendto failed");
		DEBUG("ERRNO %d%s", errno, errno==EAGAIN?" (EAGAIN)":"");
		print_l2_packet(packet);
		DEBUG("attempts %d", attempts);
		if(attempts < 1000){
			attempts++;
			goto st;
		}
		exit(EXIT_FAILURE);
	}
	if(t != num_bytes_sendto){
		DEBUG("sendto result %d != num_bytes_sendto %d", t, num_bytes_sendto);
	}

	if(attempts > 0){
		DEBUG("sendto ok after EAGAIN!");
	}
	*/
}
#pragma endregion RAW_SOCKET_ACCESS







int prepare_tcp(int s, uint16_t flags /*Host order*/, uint8_t* payload, int payloadlen, uint8_t* options, int optlen){
	assert_handler_lock_acquired("prepare_tcp");
	struct tcpctrlblk* tcb = fdinfo[s].tcb;
	struct txcontrolbuf * txcb = (struct txcontrolbuf*) malloc(sizeof(struct txcontrolbuf));
	if(fdinfo[s].l_port == 0 || tcb->r_port == 0){
		ERROR("prepare_tcp invalid port l %u r %u\n", htons(fdinfo[s].l_port), htons(tcb->r_port));
	}

	txcb->txtime = -MAX_TIMEOUT;
	txcb->payloadlen = payloadlen;
	txcb->dummy_payload = flags & DMP;
	txcb->totlen = payloadlen + 20 + FIXED_OPTIONS_LENGTH;
	txcb->retry = 0;
	struct tcp_segment * tcp = txcb->segment = (struct tcp_segment *) malloc(sizeof(struct tcp_segment));
	tcp->s_port = fdinfo[s].l_port;
	tcp->d_port = tcb->r_port;
	tcp->seq = htonl(tcb->seq_offs+tcb->sequence);
	tcp->d_offs_res=((5+FIXED_OPTIONS_LENGTH/4) << 4) | ((flags >> 8)&0b1111);
	tcp->flags = flags & 0xFF;
	tcp->urgp=0;
	for(int i=0; i<FIXED_OPTIONS_LENGTH; i++){
		tcp->payload[i] = (i<optlen) ? options[i] : OPT_KIND_END_OF_OPT;
	}
	if((payload != NULL) != (payloadlen != 0)){
		// probably there is an error in the code, if this behaviour is intended it is weird
		ERROR("prepare_tcp payload is not null and payloadlen = 0, or vice versa");
	}
	if(payloadlen != 0){
		memcpy(tcp->payload+FIXED_OPTIONS_LENGTH, payload, payloadlen);
	}

	// Insertion in the TX queue
	txcb->next=NULL;
	if(tcb->txfirst == NULL) { 
		tcb->txlast = tcb->txfirst = txcb;
	}
	else {
		tcb->txlast->next = txcb; 
		tcb->txlast = tcb->txlast->next; // tcb->txlast = txcb;
	}
	tcb->sequence += payloadlen;

	/* Calculation of new txcb fields */
	txcb->seq = ntohl(tcp->seq);
	int multi_stream_opt_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
	if(multi_stream_opt_index<0){
		txcb->sid = -1;
		txcb->ssn = -1;
	}else{
		txcb->sid = (tcp->payload[multi_stream_opt_index+2]>>2) & 0x1F;
		txcb->ssn = ((tcp->payload[multi_stream_opt_index+2]&0x3) << 8) | tcp->payload[multi_stream_opt_index+3];
		
		// Deactivate the FSM timer for this stream (we are sending a segment, so we don't need to wait for the timeout to open the new stream)
		tcb->stream_fsm_timer[txcb->sid] = 0;
	}

	int sid = -1;
	int lss = false;
	int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
	if(ms_index>=0){
		sid = (tcp->payload[ms_index+2]>>2) & 0x1F;
		lss = tcp->payload[ms_index+2]>>7;
	}
	if(sid >= 0){
		if(tcb->write_side_close_state[sid] >= WR_CLOSE_ST_LSS_TXED){
			if(!lss){
				tcp->payload[ms_index+2] |= 0x80; // set the 1st bit
			}
		}
	}
	/*
	DEFERRED FIELDS
	tcp->ack;
	tcp->window;
	tcp->checksum;

	DEFERRED OPTIONS
	Timestamps (Fill TS Echo Reply if not SYN packet)
	SACK (Add up to 3 records and change length accordingly)
	*/
}


void update_SACK_option(struct tcpctrlblk* tcb, uint8_t* opt_bytes){
	if(tcb == NULL || opt_bytes == NULL){
		ERROR("update_SACK_option NULL param");
	}
	if(opt_bytes[0] != OPT_KIND_SACK){
		ERROR("update_SACK_option non-sack pointer");
	}
	if(tcb->unack_tail == NULL){
		return;
	}

	const int max_blocks = 3;
	int used_blocks = 0;

	uint32_t sack_blocks[max_blocks][2];


	// Fill sack_blocks and incease used_blocks accordingly, up to max_blocks
	// Loop powered by Gemini
	struct channel_rx_queue_node* cursor = tcb->unack_tail;
	while (cursor != NULL && used_blocks < max_blocks) {
		// This cursor is the highest-sequence segment of a new block.
		// The Right Edge of the block is the sequence number AFTER this segment.
		uint32_t right_edge = cursor->channel_offset + cursor->payload_length;
		uint32_t left_edge = cursor->channel_offset;

		// Now, walk backwards from the cursor to find the start of this contiguous block.
		while (cursor->prev != NULL && (cursor->prev->channel_offset + cursor->prev->payload_length == left_edge)) {
			cursor = cursor->prev;
			left_edge = cursor->channel_offset;
		}

		// We have found the full block. Store it.
		sack_blocks[used_blocks][0] = left_edge;
		sack_blocks[used_blocks][1] = right_edge;
		used_blocks++;

		// Move the cursor to the start of the next potential block.
		cursor = cursor->prev;
	}


	opt_bytes[1] = 2 + used_blocks*8;

	if(used_blocks > 0){
		//DEBUG("%d used_blocks! offs=%u", used_blocks, tcb->ack_offs);
	}

	for(int num_block = 0; num_block < used_blocks; num_block++){
		uint8_t* start_ptr = opt_bytes + 2 + num_block*8;
		//DEBUG("%u - %u", sack_blocks[num_block][0], sack_blocks[num_block][1]);
		*((uint32_t*)(start_ptr + 0)) = htonl(sack_blocks[num_block][0]+tcb->ack_offs);
		*((uint32_t*)(start_ptr + 4)) = htonl(sack_blocks[num_block][1]+tcb->ack_offs);
	}
}


/*
// Original version
uint16_t compl1(uint8_t* b, int len){
	uint16_t total = 0;
	uint16_t prev = 0;
	uint16_t *p = (uint16_t* ) b;
	int i;
	for(i=0; i < len/2 ; i++){
		total += ntohs(p[i]);
		if (total < prev ) total++;
		prev = total;
	} 
	if (i*2 != len){
		//total += htons(b[len-1]<<8); 
		total += htons(p[len/2])&0xFF00;
		if (total < prev ) total++;
		prev = total;
	} 
	return total;
}
*/
// https://claude.ai/share/b75539fb-d961-49ea-8ac8-b84ba0bac2fe
// Optimization 4: Combined optimizations with alignment check
uint16_t compl1(uint8_t* b, int len) {
    uint32_t total = 0;
    
    // Check if buffer is aligned for 16-bit access
    if ((uintptr_t)b & 1) {
        // Unaligned - process byte by byte
        for (int i = 0; i < len - 1; i += 2) {
            total += (b[i] << 8) + b[i+1];
        }
        if (len & 1) {
            total += b[len-1] << 8;
        }
    } else {
        // Aligned - can safely cast to uint16_t*
        uint16_t *p = (uint16_t*)b;
        int words = len / 2;
        
        // Unrolled loop for better performance
        int i;
        for (i = 0; i < words - 3; i += 4) {
            total += ntohs(p[i]);
            total += ntohs(p[i+1]);
            total += ntohs(p[i+2]);
            total += ntohs(p[i+3]);
        }
        
        for (; i < words; i++) {
            total += ntohs(p[i]);
        }
        
        // Handle odd byte
        if (len & 1) {
            total += b[len-1] << 8;
        }
    }
    
    // Fold all carries
    while (total >> 16) {
        total = (total & 0xFFFF) + (total >> 16);
    }
    
    return (uint16_t)total;
}

unsigned short int tcp_checksum(uint8_t* b1, int len1, uint8_t* b2, int len2){
	uint16_t prev, total;
	prev = compl1(b1,len1); 
	total = (prev + compl1(b2,len2));
	if (total < prev ) total++;
	return (0xFFFF - total);
}

void update_tcp_header(int s, struct txcontrolbuf *txctrl){
	assert_handler_lock_acquired("update_tcp_header");
	static bool ssn_wrap_warning[32] = {false};
	if(txctrl == NULL){
		ERROR("update_tcp_header NULL txctrl");
	}
	/*
	DEFERRED FIELDS
	tcp->ack;
	tcp->window;
	tcp->checksum;

	DEFERRED OPTIONS
	Timestamps (Fill TS Echo Reply if not SYN packet)
	SACK (Add up to 3 records and change length accordingly)
	*/

	struct tcpctrlblk* tcb = fdinfo[s].tcb;

	struct tcp_segment* tcp = txctrl->segment;

	int optlen = ((tcp->d_offs_res)>>4)*4-20;
	for(int i=0; i<optlen; i++){
		if(tcp->payload[i] == OPT_KIND_END_OF_OPT){
			break;
		}
		if(tcp->payload[i] == OPT_KIND_NO_OP){
			continue;
		}
		if(tcp->payload[i] == OPT_KIND_TIMESTAMPS){
			// https://www.ietf.org/rfc/rfc1323.txt pp. 15-16

			// bytes i+2, i+3, i+4 and i+5 are for the current tick value (current Timestamp)
			*(uint32_t*) (tcp->payload+i+2) = htonl(get_tcp_timestamp_ms());

			// bytes i+6, i+7, i+8 and i+9 are for the most recent TS value to echo
			*(uint32_t*) (tcp->payload+i+6) = htonl(tcb->ts_recent); // ts_recent is 0 if this is a SYN (not SYN+ACK) packet
		}
		if(tcp->payload[i] == OPT_KIND_SACK){
			update_SACK_option(tcb, tcp->payload + i);
		}
		int length = tcp->payload[i+1];
		i += length - 1; // with the i++ we go to the start of the next option
	}
	

	struct pseudoheader pseudo;
	pseudo.s_addr = fdinfo[s].l_addr;
	pseudo.d_addr = tcb->r_addr;
	pseudo.zero = 0;
	pseudo.prot = TCP_PROTO;
	pseudo.len = htons(txctrl->totlen);

	tcp->checksum = htons(0);
	tcp->ack = htonl(tcb->ack_offs + tcb->cumulativeack);
	if(tcb->ms_option_enabled){
		if(txctrl->sid >= 0){
			//DEBUG("A %d f %d B %d", tcb->adwin[txctrl->sid], tcb->out_window_scale_factor, deflate_window_scale(tcb->adwin[txctrl->sid], tcb->out_window_scale_factor));
			tcp->window = htons(deflate_window_scale(tcb->adwin[txctrl->sid], tcb->out_window_scale_factor));
			if(txctrl->ssn == 512){
				if(!ssn_wrap_warning[txctrl->sid]){
					//DEBUG("\n\n\n#######################\nnupdate_tcp_header enabling wrap warning sid %d\n#######################\n", txctrl->sid);
				}
				ssn_wrap_warning[txctrl->sid] = true;
			}
			if(txctrl->ssn == 0 && ssn_wrap_warning[txctrl->sid]){
				//DEBUG("update_tcp_header sid %d wrapped\n", txctrl->sid);
				ssn_wrap_warning[txctrl->sid] = false;
			}
		}else{
			tcp->window = htons(0);
		}
	}else{
		tcp->window = htons(deflate_window_scale(tcb->adwin[0], tcb->out_window_scale_factor));
	}
	tcp->checksum = htons(tcp_checksum((uint8_t*) &pseudo, sizeof(pseudo), (uint8_t*) tcp, txctrl->totlen));
}

// Just send it! Used for ACKs (in particular dupACKs)
// Same signature as prepare_tcp but without the payload
void fast_send_tcp(int s, uint16_t flags /*Host order*/, uint8_t* options, int optlen){
	assert_handler_lock_acquired("send_tcp");
	struct tcpctrlblk*tcb = fdinfo[s].tcb;
	//struct txcontrolbuf * txcb = (struct txcontrolbuf*) malloc(sizeof( struct txcontrolbuf));
	if(fdinfo[s].l_port == 0 || tcb->r_port == 0){
		ERROR("prepare_tcp invalid port l %u r %u\n", htons(fdinfo[s].l_port), htons(tcb->r_port));
	}

	/*
	txcb->txtime = -MAX_TIMEOUT ; 
	txcb->payloadlen = payloadlen;
	txcb->dummy_payload = flags & DMP;
	txcb->totlen = payloadlen + 20 + FIXED_OPTIONS_LENGTH;
	txcb->retry = 0;
	*/
	uint16_t tcp_totlen = 20 + FIXED_OPTIONS_LENGTH;
	if(flags & DMP){
		ERROR("cannot use DMP with fast_send_tcp");
	}
	
	struct tcp_segment * tcp = /*txcb->segment =*/ (struct tcp_segment *) malloc(sizeof(struct tcp_segment));
	tcp->s_port = fdinfo[s].l_port;
	tcp->d_port = tcb->r_port;
	tcp->seq = htonl(tcb->seq_offs+tcb->sequence);
	tcp->d_offs_res=((5+FIXED_OPTIONS_LENGTH/4) << 4) | ((flags >> 8)&0b1111);
	tcp->flags = flags & 0xFF;
	tcp->urgp=0;
	for(int i=0; i<FIXED_OPTIONS_LENGTH; i++){
		tcp->payload[i] = (i<optlen) ? options[i] : OPT_KIND_END_OF_OPT;
	}
	/*
	if((payload != NULL) != (payloadlen != 0)){
		// probably there is an error in the code, if this behaviour is intended it is weird
		ERROR("prepare_tcp payload is not null and payloadlen = 0, or vice versa");
	}
	if(payloadlen != 0){
		memcpy(tcp->payload+FIXED_OPTIONS_LENGTH, payload, payloadlen);
	}
	*/

	/*
	// Insertion in the TX queue
	txcb->next=NULL;
	if(tcb->txfirst == NULL) { 
		tcb->txlast = tcb->txfirst = txcb;
	}
	else {
		tcb->txlast->next = txcb; 
		tcb->txlast = tcb->txlast->next; // tcb->txlast = txcb;
	}
	*/
	//tcb->sequence += payloadlen;

	/* Calculation of new txcb fields */
	/*
	txcb->seq = ntohl(tcp->seq);
	int multi_stream_opt_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
	if(multi_stream_opt_index<0){
		txcb->sid = -1;
		txcb->ssn = -1;
	}else{
		txcb->sid = (tcp->payload[multi_stream_opt_index+2]>>2) & 0x1F;
		txcb->ssn = ((tcp->payload[multi_stream_opt_index+2]&0x3) << 8) | tcp->payload[multi_stream_opt_index+3];
		
		// Deactivate the FSM timer for this stream (we are sending a segment, so we don't need to wait for the timeout to open the new stream)
		tcb->stream_fsm_timer[txcb->sid] = 0;
	}
	*/


	/*
	DEFERRED FIELDS
	tcp->ack;
	tcp->window;
	tcp->checksum;

	DEFERRED OPTIONS
	Timestamps (Fill TS Echo Reply if not SYN packet)
	SACK (Add up to 3 records and change length accordingly)
	*/

	for(int i=0; i<optlen; i++){
		if(tcp->payload[i] == OPT_KIND_END_OF_OPT){
			break;
		}
		if(tcp->payload[i] == OPT_KIND_NO_OP){
			continue;
		}
		if(tcp->payload[i] == OPT_KIND_TIMESTAMPS){
			// https://www.ietf.org/rfc/rfc1323.txt pp. 15-16

			// bytes i+2, i+3, i+4 and i+5 are for the current tick value (current Timestamp)
			*(uint32_t*) (tcp->payload+i+2) = htonl(get_tcp_timestamp_ms());

			// bytes i+6, i+7, i+8 and i+9 are for the most recent TS value to echo
			*(uint32_t*) (tcp->payload+i+6) = htonl(tcb->ts_recent); // ts_recent is 0 if this is a SYN (not SYN+ACK) packet
		}
		if(tcp->payload[i] == OPT_KIND_SACK){
			update_SACK_option(tcb, tcp->payload + i);
		}
		int length = tcp->payload[i+1];
		i += length - 1; // with the i++ we go to the start of the next option
	}

	struct pseudoheader pseudo;
	pseudo.s_addr = fdinfo[s].l_addr;
	pseudo.d_addr = tcb->r_addr;
	pseudo.zero = 0;
	pseudo.prot = TCP_PROTO;
	pseudo.len = htons(tcp_totlen);

	tcp->checksum = htons(0);
	tcp->ack = htonl(tcb->ack_offs + tcb->cumulativeack);
	tcp->window = htons(0);
	tcp->checksum = htons(tcp_checksum((uint8_t*) &pseudo, sizeof(pseudo), (uint8_t*) tcp, tcp_totlen));

	send_ip((unsigned char*) tcp, (unsigned char*) &(tcb->r_addr), tcp_totlen, TCP_PROTO);
}






void congctrl_fsm(struct tcpctrlblk * tcb, int event, struct tcp_segment * tcp, int streamsegmentsize){
	if(event == FSM_EVENT_PKT_RCV){
		bool dmp = tcp->d_offs_res & (DMP >> 8);
		if(streamsegmentsize > 0 && !dmp){
			return;
		}
		if(streamsegmentsize == 0 && dmp){
			ERROR("congctrl_fsm invalid dmp segment (len 0)");
		}
		int sid = -1;
		// We don't care about ssn
		int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
		if(ms_index >= 0){
			sid = (tcp->payload[ms_index+2]>>2) & 0x1F;
		}
		if(dmp && sid == -1){
			ERROR("congctrl_fsm invalid dmp segment (no sid)");
		}
		//DEBUG(" ACK: %d last ACK: %d",htonl(tcp->ack)-tcb->seq_offs, htonl(tcb->last_ack)-tcb->seq_offs);
		switch( tcb->cong_st ){
			case CONGCTRL_ST_SLOW_START: 
				// when GRO is active tcb->cgwin += (htonl(tcp->ack)-htonl(tcb->last_ack));
				tcb->cgwin += tcb->payload_mss;
				if(tcb->cgwin > tcb->ssthreshold) {
					tcb->cong_st = CONGCTRL_ST_CONG_AVOID;
					//  DEBUG("SLOW START->CONG AVOID");	
					tcb->repeated_acks = 0;
				}
				break;
			case CONGCTRL_ST_CONG_AVOID: 
				/* 
				RFC 5681 page 9: 
				1.   On the first and second duplicate ACKs received at a sender, a
					TCP SHOULD send a segment of previously unsent data per [RFC3042] provided that the receiver's advertised window allows, the total
					FlightSize would remain less than or equal to cwnd plus 2*SMSS, and that new data is available for transmission.  Further, the
					TCP sender MUST NOT change cwnd to reflect these two segments [RFC3042].
				*/
				tcb->lta = 0;
				if((((tcp->flags)&(SYN|FIN))==0) && (streamsegmentsize==0) && (tcp->ack == tcb->last_ack) && tcb->txfirst != NULL){
					tcb->repeated_acks++;
				}else{
					tcb->repeated_acks = 0;
				}
				//DEBUG(" REPEATED ACKS = %d (flags=0x%.2x streamsgmsize=%d, tcp->win=%d radwin=%d tcp->ack=%d tcb->lastack=%d)",tcb->repeated_acks,tcp->flags,streamsegmentsize,htons(tcp->window), tcb->radwin,htonl(tcp->ack),htonl(tcb->last_ack));
				if((tcb->repeated_acks == 1 ) || ( tcb->repeated_acks == 2)){
					/*
					Ho modificato questa sezione perchè:
					- A quanto ho capito, la condizione dell'if è sulla adwin, non sulla cgwin, e la adwin (dell'altro peer) viene gestita già altrove quindi non ce ne preoccupiamo qui
					- Non ha senso sommare repeated_acks (che è un intero che vale 1 o 2) e 2*payload_mss che è molto grande; a quanto ho capito, dovrebbe esserci repeated_acks invece di 2
					if (tcb->flightsize<=tcb->cgwin + 2* (tcb->payload_mss)){
						tcb->lta = tcb->repeated_acks+2*tcb->payload_mss; //RFC 3042 Limited Transmit Extra-TX-win;
					}
					*/
					tcb->lta = tcb->repeated_acks * tcb->payload_mss;
				}
				/*
				2.  When the third duplicate ACK is received, a TCP MUST set ssthresh to no more than the value given in equation (4).  When [RFC3042]
					is in use, additional data sent in limited transmit MUST NOT be included in this calculation.
													ssthresh = max (FlightSize / 2, 2*SMSS)            (4)
				*/
				else if (tcb->repeated_acks == 3){
					//DEBUG(" THIRD ACK...");
					if(tcb->txfirst!= NULL){
						struct txcontrolbuf * txcb;
						tcb->ssthreshold = MAX(tcb->flightsize/2,2*tcb->payload_mss);
						// tcb->cgwin = tcb->ssthreshold + 2*tcb->payload_mss; /* The third increment is in the FAST_RECOV state*/
						tcb->cgwin = tcb->ssthreshold;
						tcb->lta = tcb->repeated_acks * tcb->payload_mss;

						/*
						3.  The lost segment starting at SND.UNA MUST be retransmitted and cwnd set to ssthresh plus 3*SMSS.  This artificially "inflates"
						the congestion window by the number of segments (three) that have left the network and which the receiver has buffered. 
						*/
						unsigned int shifter = MIN(htonl(tcb->txfirst->segment->seq),htonl(tcb->txfirst->segment->ack));
						if(htonl(tcb->txfirst->segment->seq)-shifter <= (htonl(tcp->ack)-shifter)){
							tcb->txfirst->txtime = 0; //immediate retransmission

							// We avoid having timeouts for segments that are not retransmitted
							struct txcontrolbuf* cursor = tcb->txfirst->next;
							while(cursor != NULL){
								cursor->txtime = tick;
								cursor = cursor->next;
							}
						}
						//DEBUG(" FAST RETRANSMIT....");
						tcb->cong_st=CONGCTRL_ST_FAST_RECOV;
						//  DEBUG("CONG AVOID-> FAST_RECOVERY");
					}
				}
				else {// normal CONG AVOID 
					//if( streamsegmentsize > 0 && !dmp){
					tcb->cgwin += (tcb->payload_mss)*(tcb->payload_mss)/tcb->cgwin;
					if (tcb->cgwin<tcb->payload_mss){
						tcb->cgwin = tcb->payload_mss;
					}
					//}
				}
				break;

			case CONGCTRL_ST_FAST_RECOV:
				/*
				4.  For each additional duplicate ACK received (after the third), cwnd MUST be incremented by SMSS.  This artificially inflates the
					congestion window in order to reflect the additional segment that has left the network.
				*/
				if(tcb->last_ack==tcp->ack) {
					tcb->lta += tcb->payload_mss;
					//DEBUG(" Increasing congestion window to : %d", tcb->cgwin);
				} else {
					/*
					6.  When the next ACK arrives that acknowledges previously unacknowledged data, a TCP MUST set cwnd to ssthresh (the value
						set in step 2).  This is termed "deflating" the window.
					*/
					tcb->cgwin = tcb->ssthreshold;
					tcb->lta = 0;
					tcb->cong_st=CONGCTRL_ST_CONG_AVOID;
					//  DEBUG("FAST_RECOVERY ---> CONG_AVOID");
					tcb->repeated_acks=0;
				}
				break;
        }

		tcb->last_ack = tcp->ack; //in network order

	} else if (event == FSM_EVENT_TIMEOUT) {
		if(tcb->cong_st == CONGCTRL_ST_CONG_AVOID) tcb->ssthreshold = MAX(tcb->flightsize/2,2*tcb->payload_mss);
		if(tcb->cong_st == CONGCTRL_ST_FAST_RECOV) tcb->ssthreshold = MAX(tcb->payload_mss,tcb->ssthreshold/=2);
		if(tcb->cong_st == CONGCTRL_ST_SLOW_START) tcb->ssthreshold = MAX(tcb->payload_mss,tcb->ssthreshold/=2);
		tcb->cgwin = INIT_CGWIN* tcb->payload_mss;
		tcb->timeout = MIN( MAX_TIMEOUT , tcb->timeout*2 );
		tcb->rtt_e = 0; /* RFC 6298 Note 2 page 6 */
		//  DEBUG("TIMEOUT: --->SLOW_START");
		tcb->cong_st = CONGCTRL_ST_SLOW_START;
	}
	LOG_CONGCTRL(tcb);
}

















struct channel_rx_queue_node* create_channel_rx_queue_node(uint32_t channel_offset, struct ip_datagram* ip, struct tcp_segment* tcp, struct channel_rx_queue_node* prev, struct channel_rx_queue_node* next){
	// IP datagram is needed for segment and payload lengths
	// Instead of channel_offset we could pass the tcb as a parameter and calculate the channel_offset again here
	/*
	struct channel_rx_queue_node{
		struct channel_rx_queue_node* next;
		struct channel_rx_queue_node* prev;
		uint32_t channel_offset; // sequence number - tcb->ack_offs
		int total_segment_length;
		int payload_length;
		int sid;
		bool lss;
		bool dummy_payload;
		struct tcp_segment* segment;
	};
	*/
	if(ip == NULL || tcp == NULL){
		ERROR("create_channel_rx_queue_node unexpected NULL parameter");
	}
	int sid = 0;
	bool lss = false;
	int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
	if(ms_index >= 0){
		sid = (tcp->payload[ms_index+2]>>2) & 0x1F;
		lss = (tcp->payload[ms_index+2]>>7);
	}

	struct channel_rx_queue_node* to_return = malloc(sizeof(struct channel_rx_queue_node));
	to_return->prev = prev;
	to_return->next = next;
	to_return->channel_offset = channel_offset;
	to_return->total_segment_length = htons(ip->totlen) - (ip->ver_ihl&0xF)*4;
	to_return->sid = sid;
	to_return->lss = sid;
	to_return->payload_length = to_return->total_segment_length - (tcp->d_offs_res>>4)*4;
	to_return->dummy_payload = tcp->d_offs_res & 0x01;
	if(to_return->payload_length <= 0 || to_return->total_segment_length <= 0){
		/* 
		The case == 0 is used to ensure that we are not inserting a segment with no payload (like a DupACK) in the queue. This should be avoided
		in the caller function, and we should never get here.
		The case < 0 is used to try to catch errors related to invalid pointers passed to this function. 
		*/
		ERROR("create_channel_rx_queue_node invalid length payload %d segment %d", to_return->payload_length, to_return->total_segment_length);
	}
	to_return->segment = malloc(to_return->total_segment_length);
	memcpy(to_return->segment, tcp, to_return->total_segment_length);
	return to_return;
}

/* The segment is unlinked from the channel node and linked to the new stream node */
struct stream_rx_queue_node* create_stream_rx_queue_node(struct channel_rx_queue_node* ch_node){
	/*
	struct stream_rx_queue_node{
		struct stream_rx_queue_node* next;
		int sid;
		uint16_t ssn;
		int total_segment_length;
		int payload_length;
		bool dummy_payload; // DMP flag
		int consumed_bytes;
		struct tcp_segment* segment;
	};
	*/
	if(ch_node == NULL){
		ERROR("create_stream_rx_queue_node param NULL");
	}
	if(ch_node->segment == NULL){
		ERROR("create_stream_rx_queue_node segment NULL");
	}
	
	struct stream_rx_queue_node* to_return = (struct stream_rx_queue_node*) malloc(sizeof(struct stream_rx_queue_node));
	to_return->next = NULL; // Always inserted at the end of the stream queue

	int ms_index = search_tcp_option(ch_node->segment, OPT_KIND_MS_TCP);
	if(ms_index >= 0){
		int sid = (ch_node->segment->payload[ms_index+2]>>2) & 0x1F;
		int ssn = ((ch_node->segment->payload[ms_index+2]&0x3) << 8) | ch_node->segment->payload[ms_index+3];
		bool lss  = ch_node->segment->payload[ms_index+2]>>7;
		to_return->sid = sid;
		to_return->ssn = ssn;
		to_return->lss = lss;
	}else{
		to_return->sid = 0;
		to_return->ssn = -1;
		to_return->lss = false;
	}

	to_return->total_segment_length = ch_node->total_segment_length;
	to_return->payload_length = ch_node->payload_length;
	to_return->dummy_payload = (ch_node->segment->d_offs_res & 0x01);
	to_return->consumed_bytes = 0;
	to_return->segment = ch_node->segment;

	ch_node->segment = NULL;

	return to_return;
}


int circular_starting_sid = 0;
void circular_start_scheduler(int s){
	if(s < 3 || s >= MAX_FD){
		ERROR("unfair_congestion_scheduler invalid fd %d", s);
	}
	struct tcpctrlblk* tcb = fdinfo[s].tcb;
	if(tcb == NULL){
		ERROR("unfair_congestion_scheduler tcb NULL");
	}
	const int max_payload_length = TCP_MSS - FIXED_OPTIONS_LENGTH;
	uint8_t* temp_payload_buf = malloc(max_payload_length);
	for(int sid_counter = 0; sid_counter < TOT_SID; sid_counter++){
		int sid = (sid_counter + circular_starting_sid) % TOT_SID;
		if(tcb->stream_state[sid] == STREAM_STATE_OPENED){
			// We can transmit some more data on the stream
			int available_bytes = TX_BUFFER_SIZE-tcb->txfree[sid];

			int cong_control_allowed_bytes = MAX(tcb->cgwin+tcb->lta - tcb->flightsize, 0);
			if((available_bytes == 0 || cong_control_allowed_bytes == 0) && tcb->write_side_close_state[sid] != WR_CLOSE_ST_LSS_REQUESTED){
				// We can do nothing for this stream
				// we cannot send data, and we cannot enqueue the LSS(/FIN), so we skip it
				continue;
			}

			/* FLOW CONTROL START */
			int in_flight_bytes = 0; // Note: this is not equal to tcb->flightsize, because that is for all the streams, this is for only one stream
			bool small_in_flight = false;
			struct txcontrolbuf* tx_cursor = tcb->txfirst;
			while(tx_cursor != NULL){
				if(tx_cursor->sid == sid && !(tx_cursor->dummy_payload)){
					if(tx_cursor->payloadlen > 0 && tx_cursor->payloadlen != max_payload_length){
						small_in_flight = true;
					}
					in_flight_bytes += tx_cursor->payloadlen;
				}
				tx_cursor = tx_cursor->next;
			}
			int flow_control_allowed_bytes = tcb->radwin[sid] - in_flight_bytes; // Must always be >= 0
			if(flow_control_allowed_bytes < 0){
				ERROR("flow_control_allowed_bytes %d < 0 (tcb->radwin[%d] %u in_flight_bytes %d)", flow_control_allowed_bytes, sid, tcb->radwin[sid], in_flight_bytes);
			}

			int allowed_bytes = MIN(flow_control_allowed_bytes, cong_control_allowed_bytes);
			int current_transfer_bytes = MIN(available_bytes, allowed_bytes);
			LOG_SCHEDULER_BYTES(sid, available_bytes, flow_control_allowed_bytes, cong_control_allowed_bytes);
			/* FLOW CONTROL END */

			while(current_transfer_bytes > 0){
				int payload_length = MIN(current_transfer_bytes, max_payload_length);
				if(payload_length < max_payload_length && small_in_flight){
					break;
				}

				/*
				for(int i=0; i<payload_length; i++){
					temp_payload_buf[i] = tcb->stream_tx_buffer[sid][tcb->tx_buffer_occupied_region_start[sid]];
					tcb->tx_buffer_occupied_region_start[sid] = (tcb->tx_buffer_occupied_region_start[sid]+1)%TX_BUFFER_SIZE;
					tcb->txfree[sid]++;
					current_transfer_bytes--;
				}
				*/
				int first_chunk = payload_length, second_chunk = 0;
				if(first_chunk > (TX_BUFFER_SIZE - tcb->tx_buffer_occupied_region_start[sid])){
					second_chunk = first_chunk -(TX_BUFFER_SIZE - tcb->tx_buffer_occupied_region_start[sid]);
					first_chunk -= second_chunk;
				}
				memcpy(temp_payload_buf, tcb->stream_tx_buffer[sid] + tcb->tx_buffer_occupied_region_start[sid], first_chunk);
				memcpy(temp_payload_buf + first_chunk, tcb->stream_tx_buffer[sid], second_chunk);
				tcb->tx_buffer_occupied_region_start[sid] = (tcb->tx_buffer_occupied_region_start[sid] + payload_length) % TX_BUFFER_SIZE;
				tcb->txfree[sid] += payload_length;
				current_transfer_bytes -= payload_length;

				if(!tcb->ms_option_enabled){
					prepare_tcp(s, ACK, temp_payload_buf, payload_length, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
				}else{
					int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
					uint8_t* opt = malloc(optlen);
					memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
					
					// Stream update
					opt[2] = sid<<2 | (((tcb->next_ssn[sid])>>8) & 0x03);
					opt[3] = (tcb->next_ssn[sid]) & 0xFF;
					update_next_ssn(&(tcb->next_ssn[sid]));

					prepare_tcp(s, ACK, temp_payload_buf, payload_length, opt, optlen);
					free(opt);
				}
			}

			if(tcb->write_side_close_state[sid] == WR_CLOSE_ST_LSS_REQUESTED){
				if(tcb->txfree[sid] == TX_BUFFER_SIZE){
					if(!tcb->ms_option_enabled){
						prepare_tcp(s, ACK | FIN, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
					}else{
						// Enqueue LSS segment
						int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
						uint8_t* opt = malloc(optlen);
						memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
						
						// Stream update
						opt[2] = (0b1 << 7) | sid<<2 | ((tcb->next_ssn[sid] >> 8)&0x3);
						opt[3] = (tcb->next_ssn[sid])&0xFF;
						update_next_ssn(&(tcb->next_ssn[sid]));

						uint8_t* dummy_payload = malloc(1); // value doesn't matter

						prepare_tcp(s, ACK | DMP, dummy_payload, 1, opt, optlen);
						free(dummy_payload);
						free(opt);
					}

					tcb->write_side_close_state[sid] = WR_CLOSE_ST_LSS_TXED;
				}
			}
		}
	}
	free(temp_payload_buf);
	circular_starting_sid = (circular_starting_sid+1) % TOT_SID;
}


// Abstract scheduler stub to call one of the different scheduler implementations
void scheduler(int s /* socket fd */){
	assert_handler_lock_acquired("scheduler");
	circular_start_scheduler(s);
}





bool port_in_use(unsigned short port){
	int s;
	for (s=3; s<MAX_FD; s++){
		if(fdinfo[s].st != FDINFO_ST_FREE && fdinfo[s].st != FDINFO_ST_UNBOUND){
			if(fdinfo[s].l_port == htons(port)){
				return true;
			}
		}
	}
	return false;
}

/*
unsigned short get_free_port(){
	unsigned short p;
	for(p = last_port; p<MAX_PORT && port_in_use(p); p++);
	if(p<MAX_PORT){
		//DEBUG("get_free_port %d", p);
		return last_port=p;
	}
	for( p = MIN_PORT; p<last_port && port_in_use(p); p++);
	if (p<last_port){
		//DEBUG("get_free_port %d", p);
		return last_port=p;
	}
	return 0;
}
*/

// https://claude.ai/share/a071ff4c-b4ba-4443-9a5b-5bf0a334de18
unsigned short get_free_port(){
    unsigned short p;
    FILE *file;
    
    // Try to read from last_port.txt
    file = fopen("last_port.txt", "r");
    if (file != NULL) {
        // File exists, read the value
        if (fscanf(file, "%hu", &p) == 1) {
            fclose(file);
            
            // Increment the port number
			if(p < MIN_PORT){
				p = MIN_PORT + sample_uint32() % (MAX_PORT - MIN_PORT);
			}
            p++;
			if(p >= MAX_PORT){
				p = MIN_PORT;
			}
            
            // Write the incremented value back to the file
            file = fopen("last_port.txt", "w");
            if (file != NULL) {
                fprintf(file, "%hu", p);
                fclose(file);
				//DEBUG("file %d", p);
                return p;
            }
            // If we can't write back, fall through to legacy behavior
        } else {
            fclose(file);
            // File exists but couldn't read valid data, fall through to legacy
        }
    }
    
    // File doesn't exist or couldn't be read/written - use legacy behavior
    for(p = last_port; p < MAX_PORT && port_in_use(p); p++);
    if(p < MAX_PORT){
        //DEBUG("global %d", p);
        return last_port = p;
    }
    for(p = MIN_PORT; p < last_port && port_in_use(p); p++);
    if (p < last_port){
        //DEBUG("global %d", p);
        return last_port = p;
    }
    return 0;
}

int mybind(int s, struct sockaddr * addr, int addrlen){
	if (addrlen < sizeof(struct sockaddr_in)) {
		myerrno = EINVAL;
		return -1;
	}
	if(addr->sa_family != AF_INET){
		myerrno = EINVAL;
		return -1;
	}
	if(s < 3 || s >= MAX_FD){
		myerrno = EBADF; 
		return -1;
	}
	if(fdinfo[s].st != FDINFO_ST_UNBOUND){
		myerrno = EINVAL; 
		return -1;
	}
	struct sockaddr_in * a = (struct sockaddr_in*) addr;
	if(a->sin_port != 0 && port_in_use(a->sin_port)){
		myerrno = EADDRINUSE; 
		return -1;
	}
	fdinfo[s].l_port = (a->sin_port != 0) ? a->sin_port : htons(get_free_port());   
	if(fdinfo[s].l_port == 0) {
		myerrno = EADDRINUSE; // mytcp: ENOMEM 
		return -1;
	}
	memcpy(&fdinfo[s].l_addr, myip, sizeof(fdinfo[s].l_addr));
	fdinfo[s].st = FDINFO_ST_BOUND;
	myerrno = 0;
	return 0;
}

int mysocket(int family, int type, int proto){
	int i;
	if(family != AF_INET ||  type != SOCK_STREAM || proto != 0){
		myerrno = EINVAL; 
		return -1;
	}
	for(i=3; i<MAX_FD && fdinfo[i].st!=FDINFO_ST_FREE;i++){}
	if(i==MAX_FD) {
		myerrno = ENFILE; 
		return -1;
	}
	else {
		bzero(fdinfo+i, sizeof(struct socket_info));
		fdinfo[i].st = FDINFO_ST_UNBOUND;
		fdinfo[i].sid = SID_UNASSIGNED;
		myerrno = 0;
		return i;
	}
}

uint32_t gen_sequence_offset(){
	// Should be random...
	return 0;
}

int64_t hs_time_start;
int64_t hs_time_tot = 0;

int fsm(int s, int event, struct ip_datagram * ip, struct sockaddr_in* active_open_remote_addr){
	assert_handler_lock_acquired("fsm");
	if(s < 3 || s >= MAX_FD){
		ERROR("FSM invalid s %d", s);
	}
	if(event == FSM_EVENT_APP_ACTIVE_OPEN){
		if(fdinfo[s].st != FDINFO_ST_UNBOUND && fdinfo[s].st != FDINFO_ST_BOUND){
			ERROR("FSM active open invalid fdinfo state %d", fdinfo[s].st);
		}

		/*
		We have different cases for MS enabled and not. For MS disabled, we do the automatic bind if the socket
		is not already bound, then we create the TCB, and we send the SYN packet without the MS-TCP option.
		If the MS is enabled, TODO spiegare
		*/
		if(!MS_ENABLED){
			if(fdinfo[s].st == FDINFO_ST_UNBOUND){
				struct sockaddr_in local = {0};
				local.sin_port=htons(0);
				local.sin_addr.s_addr = htonl(0);
				local.sin_family = AF_INET;
				if(-1 == mybind(s,(struct sockaddr *) &local, sizeof(struct sockaddr_in)))	{
					myperror("implicit binding failed"); 
					return -1;
				}
			}
			if(fdinfo[s].st != FDINFO_ST_BOUND){
				myerrno = EBADF; 
				return -1;
			}

			struct tcpctrlblk* tcb = fdinfo[s].tcb = (struct tcpctrlblk*) malloc(sizeof(struct tcpctrlblk));
			bzero(tcb, sizeof(struct tcpctrlblk));
			fdinfo[s].st = FDINFO_ST_TCB_CREATED;
			fdinfo[s].sid = 0;
			tcb->st = TCB_ST_CLOSED;

			tcb->seq_offs=gen_sequence_offset();
			tcb->ack_offs=0;
			tcb->stream_end=0xFFFFFFFF; //Max file
			tcb->mss = TCP_MSS;
			tcb->payload_mss = tcb->mss - FIXED_OPTIONS_LENGTH;
			tcb->sequence=0;
			tcb->cumulativeack = 0;
			tcb->timeout = INIT_TIMEOUT;
			tcb->fsm_timer = 0;
			tcb->ms_option_requested = false;
			tcb->ms_option_enabled = false;
			tcb->is_active_side = true;
			tcb->listening_fd = -1;
			tcb->out_window_scale_factor = DEFAULT_WINDOW_SCALE;
			tcb->in_window_scale_factor = 0;
			tcb->ts_recent = 0;
			tcb->ts_offset = 0;

			tcb->ssthreshold = INIT_THRESH * tcb->payload_mss;
			tcb->cgwin = INIT_CGWIN* tcb->payload_mss;
			tcb->rtt_e = 0;
			tcb->Drtt_e = 0;
			tcb->cong_st = CONGCTRL_ST_SLOW_START;

			tcb->r_port = active_open_remote_addr->sin_port;
			tcb->r_addr = active_open_remote_addr->sin_addr.s_addr;

			tcb->unack = tcb->unack_tail = NULL;

			// Initialization of stream-specific fields
			for(int i=0; i<TOT_SID; i++){
				/*
					bool stream_state[TOT_SID];
					unsigned short adwin[TOT_SID];
					unsigned short radwin[TOT_SID];
					unsigned char* stream_tx_buffer[TOT_SID];
					unsigned int txfree[TOT_SID];
					uint16_t next_ssn[TOT_SID];
					uint16_t next_rx_ssn[TOT_SID];
					unsigned int stream_fsm_timer[TOT_SID];
					struct stream_rx_queue_node* stream_rx_queue[TOT_SID];
				*/
				tcb->stream_state[i] = STREAM_STATE_UNUSED;
				tcb->adwin[i] = RX_VIRTUAL_BUFFER_SIZE; // RX Buffer Size
				tcb->radwin[i] = 0; // This will be initialized with the reception of the SYN+ACK
				tcb->stream_tx_buffer[i] = NULL;
				tcb->txfree[i] = 0;
				tcb->tx_buffer_occupied_region_start[i] = tcb->tx_buffer_occupied_region_end[i] = 0;
				tcb->next_ssn[i] = 0;
				tcb->next_rx_ssn[i] = 0;
				tcb->stream_fsm_timer[i] = 0;
				tcb->stream_rx_queue[i] = tcb->stream_rx_queue_tail[i] = NULL;

				tcb->write_side_close_state[i] = WR_CLOSE_ST_OPEN;
				tcb->lss_received[i] = tcb->lss_consumed[i] = false;
			}


			// send SYN without MS option
			uint8_t* opt_ptr = NULL;
			int opt_len;

			opt_len = 19;
			opt_ptr = malloc(opt_len);

			opt_ptr[0] = OPT_KIND_MSS; // MSS Kind
			opt_ptr[1] = 4; // MSS Length
			opt_ptr[2] = TCP_MSS >> 8;
			opt_ptr[3] = TCP_MSS & 0xFF;
			opt_ptr[4] = OPT_KIND_TIMESTAMPS; // Timestamps Kind
			opt_ptr[5] = 10; // Timestamps Length
			opt_ptr[6] = 0;
			opt_ptr[7] = 0;
			opt_ptr[8] = 0;
			opt_ptr[9] = 0;
			opt_ptr[10] = 0;
			opt_ptr[11] = 0;
			opt_ptr[12] = 0;
			opt_ptr[13] = 0; 
			opt_ptr[14] = OPT_KIND_SACK_PERM; // SACK permitted Kind
			opt_ptr[15] = 2; // SACK permitted Length
			opt_ptr[16] = OPT_KIND_WIN_SCALE; // Window Scale Kind
			opt_ptr[17] = 3; // Window Scale Length
			opt_ptr[18] = DEFAULT_WINDOW_SCALE;

			hs_time_start = get_timestamp_ms();
			prepare_tcp(s,SYN,NULL,0,opt_ptr,opt_len);
			free(opt_ptr);

			tcb->st = TCB_ST_SYN_SENT;
			
			return 0;
		}else{
			if(fdinfo[s].st == FDINFO_ST_UNBOUND){
				// Search if there is an already opened MS connection to the same destination with available streams
				for(int other_s = 0; other_s < MAX_FD; other_s++){
					if(fdinfo[other_s].st != FDINFO_ST_TCB_CREATED){ // this also handles the case other_s == s
						continue;
					}
					struct tcpctrlblk* tcb = fdinfo[other_s].tcb;
					if(!tcb->is_active_side){
						continue;
					}
					if(tcb->st != TCB_ST_ESTABLISHED){
						/* 
						NOTE: we do wait for a SYN_SENT connection to be established to see if it will have MS-TCP enabled and add streams to it. We
						consider only already established connections to for opening new streams. This can be a problem if several non-blocking connects 
						are called back to back to a server that supports MS-TCP: in this case, if MS-TCP is enabled at the client, many new connections 
						will be created and MS-TCP will be useless, creating only a small overhead without any benefits. The scenario of multiple connect
						calls back to back is not unrealistic, since this is probably what is done in modern browsers that have 6 TCP connections opened
						at the same time towards a server. However, this is not a problem if the browser opens only one connection at the beginning, and
						only after the first page has been fetched the other 5 connections are created to retreive the other resources. It may be a good
						idea to verify this assumption on modern browser behaviour with Wireshark. 
						*/
						continue;
					}
					if(tcb->r_port != active_open_remote_addr->sin_port || tcb->r_addr != active_open_remote_addr->sin_addr.s_addr){
						continue;
					}
					if(!tcb->ms_option_enabled){
						/*
						NOTE: if MS-TCP has not been enabled (but it has been requested) on a connection towards the same server, we could deduce that
						MS is not supported or enabled at that server, and consequently avoid requesting the MS option for our new connection. However,
						it does not seem very useful to impose a guarantee that MS-TCP support cannot vary in time at a server, or that the configuration
						should be uniform between multiple servers that accept connections at a certain address and port. Since MS-TCP does not add a
						large overhead on the SYN, and it does not delay the opening of other connections (because of "tcb->st != TCB_ST_ESTABLISHED"),
						there is no reason to make such assumptions at the client.
						*/
						continue;
					}
					
					// At this point the connection is a good candidate: search for a free stream
					for(int stream = 0; stream < TOT_SID; stream++){
						if(tcb->stream_state[stream] == STREAM_STATE_UNUSED){
							// Free stream found
							fdinfo[s].st = FDINFO_ST_TCB_CREATED;
							fdinfo[s].tcb = tcb;
							fdinfo[s].sid = stream;
							fdinfo[s].l_addr = fdinfo[other_s].l_addr;
							fdinfo[s].l_port = fdinfo[other_s].l_port;
							fdinfo[s].tcb->stream_state[stream] = STREAM_STATE_OPENED;
							fdinfo[s].tcb->radwin[stream] = fdinfo[s].tcb->init_radwin;
							fdinfo[s].tcb->txfree[stream] = TX_BUFFER_SIZE;
							fdinfo[s].tcb->tx_buffer_occupied_region_start[stream] = fdinfo[s].tcb->tx_buffer_occupied_region_end[stream] = 0;
							if(fdinfo[s].tcb->stream_tx_buffer[stream] != NULL){
								ERROR("stream_tx_buffer != NULL before malloc");
							}
							fdinfo[s].tcb->stream_tx_buffer[stream] = malloc(TX_BUFFER_SIZE);
							fdinfo[s].tcb->adwin[stream] = RX_VIRTUAL_BUFFER_SIZE;
							fdinfo[s].tcb->stream_fsm_timer[stream] = tick + STREAM_OPEN_TIMEOUT;
							fdinfo[s].tcb->write_side_close_state[stream] = WR_CLOSE_ST_OPEN;
							fdinfo[s].tcb->lss_received[stream] = fdinfo[s].tcb->lss_consumed[stream] = false;

							while(tcb->stream_rx_queue[stream] != NULL){
								struct stream_rx_queue_node* tmp = tcb->stream_rx_queue[stream];
								tcb->stream_rx_queue[stream] = tcb->stream_rx_queue[stream]->next;
								if(!tmp->dummy_payload){
									ERROR("non-DMP remaining segment during fsm flush");
								}
								if(tmp->segment != NULL){
									free(tmp->segment);
								}
								free(tmp);
							}
							
							fdinfo[s].tcb->stream_rx_queue[stream] = fdinfo[s].tcb->stream_rx_queue_tail[stream] = NULL;

							return 0;
						}
					}
				}

				// No such connection exists: bind to a new port and open a new connection
				struct sockaddr_in local = {0};
				local.sin_port=htons(0);
				local.sin_addr.s_addr = htonl(0);
				local.sin_family = AF_INET;
				if(-1 == mybind(s,(struct sockaddr *) &local, sizeof(struct sockaddr_in)))	{
					myperror("implicit binding failed"); 
					return -1;
				}
			}

			if(fdinfo[s].st != FDINFO_ST_BOUND){
				myerrno = EBADF; 
				return -1;
			}

			// Open a new connection, requesting MS option
			struct tcpctrlblk* tcb = fdinfo[s].tcb = (struct tcpctrlblk*) malloc(sizeof(struct tcpctrlblk));
			bzero(tcb, sizeof(struct tcpctrlblk));
			fdinfo[s].st = FDINFO_ST_TCB_CREATED;
			fdinfo[s].sid = 0;
			tcb->st = TCB_ST_CLOSED;

			tcb->seq_offs=gen_sequence_offset();
			tcb->ack_offs=0;
			tcb->stream_end=0xFFFFFFFF;
			tcb->mss = TCP_MSS;
			tcb->payload_mss = tcb->mss - FIXED_OPTIONS_LENGTH;
			tcb->sequence=0;
			tcb->cumulativeack = 0;
			tcb->timeout = INIT_TIMEOUT;
			tcb->fsm_timer = 0;
			tcb->ms_option_requested = true; // modified wrt non-ms
			tcb->ms_option_enabled = false;
			tcb->is_active_side = true;
			tcb->listening_fd = -1;
			tcb->out_window_scale_factor = DEFAULT_WINDOW_SCALE;
			tcb->in_window_scale_factor = 0;
			tcb->ts_recent = 0;
			tcb->ts_offset = 0;

			tcb->ssthreshold = INIT_THRESH * tcb->payload_mss;
			tcb->cgwin = INIT_CGWIN* tcb->payload_mss;
			tcb->rtt_e = 0;
			tcb->Drtt_e = 0;
			tcb->cong_st = CONGCTRL_ST_SLOW_START;

			tcb->r_port = active_open_remote_addr->sin_port;
			tcb->r_addr = active_open_remote_addr->sin_addr.s_addr;

			tcb->unack = tcb->unack_tail = NULL;

			// Initialization of stream-specific fields
			for(int i=0; i<TOT_SID; i++){
				/*
					bool stream_state[TOT_SID];
					unsigned short adwin[TOT_SID];
					unsigned short radwin[TOT_SID];
					unsigned char* stream_tx_buffer[TOT_SID]; // not present in mytcp
					unsigned char* stream_rx_buffer[TOT_SID]; // mytcp: rxbuffer
					unsigned int rx_win_start[TOT_SID];
					unsigned int txfree[TOT_SID];
					uint16_t next_ssn[TOT_SID];
				*/
				tcb->stream_state[i] = STREAM_STATE_UNUSED;
				tcb->stream_tx_buffer[i] = NULL;
				tcb->stream_rx_queue[i] = tcb->stream_rx_queue_tail[i] = NULL;
				tcb->adwin[i] = RX_VIRTUAL_BUFFER_SIZE; // RX Buffer Size
				tcb->radwin[i] = 0; // This will be initialized with the reception of the SYN+ACK
				tcb->txfree[i] = 0;
				tcb->tx_buffer_occupied_region_start[i] = tcb->tx_buffer_occupied_region_end[i] = 0;
				tcb->next_ssn[i] = 0;
				tcb->next_rx_ssn[i] = 0;
				tcb->stream_fsm_timer[i] = 0;
				tcb->write_side_close_state[i] = WR_CLOSE_ST_OPEN;
				tcb->lss_received[i] = tcb->lss_consumed[i] = false;
			}


			// send SYN with MS option
			uint8_t* opt_ptr = NULL;
			int opt_len;

			opt_len = 23;
			opt_ptr = malloc(opt_len);

			opt_ptr[0] = OPT_KIND_MSS; // MSS Kind
			opt_ptr[1] = 4; // MSS Length
			opt_ptr[2] = TCP_MSS >> 8;
			opt_ptr[3] = TCP_MSS & 0xFF;
			opt_ptr[4] = OPT_KIND_MS_TCP; // MS-TCP Kind
			opt_ptr[5] = 4; // MS-TCP Length
			opt_ptr[6] = 0;
			opt_ptr[7] = 0;
			opt_ptr[8] = OPT_KIND_TIMESTAMPS; // Timestamps Kind
			opt_ptr[9] = 10; // Timestamps Length
			opt_ptr[10] = 0;
			opt_ptr[11] = 0;
			opt_ptr[12] = 0;
			opt_ptr[13] = 0;
			opt_ptr[14] = 0;
			opt_ptr[15] = 0;
			opt_ptr[16] = 0;
			opt_ptr[17] = 0; 
			opt_ptr[18] = OPT_KIND_SACK_PERM; // SACK permitted Kind
			opt_ptr[19] = 2; // SACK permitted Length
			opt_ptr[20] = OPT_KIND_WIN_SCALE; // Window Scale Kind
			opt_ptr[21] = 3; // Window Scale Length
			opt_ptr[22] = DEFAULT_WINDOW_SCALE;

			hs_time_start = get_timestamp_ms();
			prepare_tcp(s,SYN,NULL,0,opt_ptr,opt_len);
			free(opt_ptr);

			tcb->st = TCB_ST_SYN_SENT;

			return 0;
		}
	}

	if(fdinfo[s].st != FDINFO_ST_TCB_CREATED){
		ERROR("FSM invalid fdinfo state %d", fdinfo[s].st);
	}

	struct tcpctrlblk* tcb = fdinfo[s].tcb;
	struct tcp_segment * tcp = NULL;
	if(ip != NULL){
		tcp = (struct tcp_segment*)((uint8_t*)ip+((ip->ver_ihl&0xF)*4));
	}
	switch(tcb->st){
		case TCB_ST_SYN_SENT:
			if(event == FSM_EVENT_PKT_RCV){
				if((tcp->flags&SYN) && (tcp->flags&ACK) && (htonl(tcp->ack)==tcb->seq_offs + 1)){
					tcb->seq_offs++;
					tcb->ack_offs = htonl(tcp->seq) + 1;	
					free(tcb->txfirst->segment);
					free(tcb->txfirst);
					tcb->txfirst = tcb->txlast = NULL;
					
					bool ms_received = false;
					bool sack_perm_received = false;
					bool timestamps_received = false;
					uint32_t received_remote_timestamp;
					// uint32_t tick_diff_timestamp; Not used (calculated again in rtt_estimate called from myio after the FSM returns)
					uint8_t win_scale_factor_received = 0;
					uint16_t mss_received = TCP_MSS;

					int optlen = ((tcp->d_offs_res)>>4)*4-20;
					for(int i=0; i<optlen; i++){
						if(tcp->payload[i] == OPT_KIND_END_OF_OPT){
							break;
						}
						if(tcp->payload[i] == OPT_KIND_NO_OP){
							continue;
						}
						if(tcp->payload[i] == OPT_KIND_TIMESTAMPS){
							timestamps_received = true;

							received_remote_timestamp = ntohl(*(uint32_t*) (tcp->payload+i+2));
							// tick_diff_timestamp = tick - ntohl(*(uint32_t*) (tcp->payload+i+6));
						}
						if(tcp->payload[i] == OPT_KIND_SACK_PERM){
							sack_perm_received = true;
						}
						if(tcp->payload[i] == OPT_KIND_MSS){
							mss_received = tcp->payload[i+2] << 8 | tcp->payload[i+3];
						}
						if(tcp->payload[i] == OPT_KIND_WIN_SCALE){
							win_scale_factor_received = tcp->payload[i+2];
						}
						if(tcp->payload[i] == OPT_KIND_MS_TCP){
							ms_received = true;
						}
						int length = tcp->payload[i+1];
						i += length - 1; // with the i++ we go to the start of the next option
						if(i>=optlen){
							ERROR("FSM TCB_ST_SYN_SENT FSM_EVENT_PKT_RCV misaligned end of options (invalid last length)");
						}
					}

					if(!timestamps_received){
						ERROR("Timestamps not enabled with the SYN+ACK");
					}
					if(!sack_perm_received){
						ERROR("SACK not enabled with the SYN+ACK");
					}

					tcb->in_window_scale_factor = win_scale_factor_received;
					if(mss_received < tcb->mss){
						tcb->mss = mss_received;
						tcb->payload_mss = tcb->mss - FIXED_OPTIONS_LENGTH;
					}
					tcb->ts_offset = tcb->ts_recent = received_remote_timestamp;

					if(!tcb->ms_option_requested && ms_received){
						ERROR("Received MS-TCP option without request");
					}

					/* 
					equivalent to just doing tcb->ms_option_enabled = ms_received , but in this way we keep the correct semantic that enables the option
					only if it was requested, so it remains correct even if the check for unrequested MS-TCP option is removed
					*/
					tcb->ms_option_enabled = tcb->ms_option_requested && ms_received; 

					if(tcb->ms_option_enabled){
						tcb->next_rx_ssn[0] = 1; // SSN 0 received in the SYN+ACK
						/*
						Incremented here (instead of in the ACTIVE_OPEN event fsm) to avoid having SSN=1 for disabled MS-TCP in stream 0. Probably this is 
						not important, and it can be moved there if it simplifies something.
						*/
						tcb->next_ssn[0] = 1;
					}


					fdinfo[s].sid = 0; // The first opened stream is always stream 0
					tcb->stream_state[0] = STREAM_STATE_OPENED;

					tcb->init_radwin = tcb->radwin[0] = inflate_window_scale(ntohs(tcp->window), tcb->in_window_scale_factor);
					tcb->txfree[0] = TX_BUFFER_SIZE;
					tcb->tx_buffer_occupied_region_start[0] = tcb->tx_buffer_occupied_region_end[0] = 0;
					if(tcb->stream_tx_buffer[0] != NULL){
						ERROR("stream_tx_buffer != NULL before malloc");
					}
					tcb->stream_tx_buffer[0] = malloc(TX_BUFFER_SIZE);
					if(tcb->stream_rx_queue[0] != NULL){
						// This should never happen, it is just to check that this field is reset correctly
						ERROR("TCB_ST_SYN_SENT FSM_EVENT_PKT_RCV tcb->stream_rx_queue[0]!=NULL");
					}
					// We don't need to do anything with stream_rx_queue as it is already empty
					tcb->adwin[0] = RX_VIRTUAL_BUFFER_SIZE;

					tcb->write_side_close_state[0] = WR_CLOSE_ST_OPEN;
					tcb->lss_received[0] = tcb->lss_consumed[0] = false;

					/*
					We include all the usual payload options in this ACK
					(we could avoid inserting the SACK, but it is simpler to do like this)
					*/
					prepare_tcp(s, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));

					tcb->st = TCB_ST_ESTABLISHED;
					hs_time_tot  += get_timestamp_ms() - hs_time_start;
				}
			}
			break;
		case TCB_ST_LISTEN:
			if(event == FSM_EVENT_PKT_RCV){
				if(!(tcp->flags & SYN)){
					break;
				}

				bool ms_received = false;
				bool sack_perm_received = false;
				bool timestamps_received = false;
				uint32_t received_remote_timestamp;
				// uint32_t tick_diff_timestamp; Not used (calculated again in rtt_estimate called from myio after the FSM returns)
				uint8_t win_scale_factor_received = 0;
				uint16_t mss_received = TCP_MSS;

				int optlen = ((tcp->d_offs_res)>>4)*4-20;
				for(int i=0; i<optlen; i++){
					if(tcp->payload[i] == OPT_KIND_END_OF_OPT){
						break;
					}
					if(tcp->payload[i] == OPT_KIND_NO_OP){
						continue;
					}
					if(tcp->payload[i] == OPT_KIND_TIMESTAMPS){
						timestamps_received = true;

						received_remote_timestamp = ntohl(*(uint32_t*) (tcp->payload+i+2));
						// tick_diff_timestamp = tick - ntohl(*(uint32_t*) (tcp->payload+i+6));
					}
					if(tcp->payload[i] == OPT_KIND_SACK_PERM){
						sack_perm_received = true;
					}
					if(tcp->payload[i] == OPT_KIND_MSS){
						mss_received = tcp->payload[i+2] << 8 | tcp->payload[i+3];
					}
					if(tcp->payload[i] == OPT_KIND_WIN_SCALE){
						win_scale_factor_received = tcp->payload[i+2];
					}
					if(tcp->payload[i] == OPT_KIND_MS_TCP){
						ms_received = true;
					}
					int length = tcp->payload[i+1];
					i += length - 1; // with the i++ we go to the start of the next option
					if(i>=optlen){
						ERROR("FSM TCB_ST_LISTEN FSM_EVENT_PKT_RCV misaligned end of options (invalid last length)");
					}
				}

				if(!timestamps_received){
					ERROR("Timestamps not enabled with the SYN");
				}
				if(!sack_perm_received){
					ERROR("SACK not enabled with the SYN");
				}

				tcb->in_window_scale_factor = win_scale_factor_received;
				tcb->out_window_scale_factor = DEFAULT_WINDOW_SCALE;
				tcb->mss = MIN(mss_received, TCP_MSS);
				tcb->payload_mss = tcb->mss - FIXED_OPTIONS_LENGTH;
				tcb->ts_offset = tcb->ts_recent = received_remote_timestamp;

				tcb->ms_option_enabled = ms_received && MS_ENABLED;

				tcb->ssthreshold = INIT_THRESH * tcb->payload_mss;
				tcb->cgwin = INIT_CGWIN* tcb->payload_mss;
				tcb->rtt_e = 0;
				tcb->Drtt_e = 0;
				tcb->cong_st = CONGCTRL_ST_SLOW_START;

				tcb->r_port = tcp->s_port;
				tcb->r_addr = memcmp((uint8_t*) &ip->srcaddr, myip, 4) ? ip->srcaddr : inet_addr("127.0.0.1");
				

				tcb->seq_offs=gen_sequence_offset();
				tcb->ack_offs=htonl(tcp->seq)+1;
				tcb->cumulativeack=0;

				tcb->timeout = INIT_TIMEOUT;
				tcb->txfirst = tcb->txlast = NULL;

				tcb->adwin[0] = RX_VIRTUAL_BUFFER_SIZE;

				fdinfo[s].sid = 0; // We use stream 0 to open the connection

				uint8_t* opt_ptr = NULL;
				int opt_len;
				if(tcb->ms_option_enabled){
					opt_len = 23;
					opt_ptr = malloc(opt_len);

					opt_ptr[0] = OPT_KIND_MSS; // MSS Kind
					opt_ptr[1] = 4; // MSS Length
					opt_ptr[2] = TCP_MSS >> 8;
					opt_ptr[3] = TCP_MSS & 0xFF;
					opt_ptr[4] = OPT_KIND_MS_TCP; // MSS Kind
					opt_ptr[5] = 4; // MSS Length
					opt_ptr[6] = 0;
					opt_ptr[7] = 0;
					opt_ptr[8] = OPT_KIND_TIMESTAMPS; // Timestamps Kind
					opt_ptr[9] = 10; // Timestamps Length
					opt_ptr[10] = 0;
					opt_ptr[11] = 0;
					opt_ptr[12] = 0;
					opt_ptr[13] = 0;
					opt_ptr[14] = 0;
					opt_ptr[15] = 0;
					opt_ptr[16] = 0;
					opt_ptr[17] = 0; 
					opt_ptr[18] = OPT_KIND_SACK_PERM; // SACK permitted Kind
					opt_ptr[19] = 2; // SACK permitted Length
					opt_ptr[20] = OPT_KIND_WIN_SCALE; // Window Scale Kind
					opt_ptr[21] = 3; // Window Scale Length
					opt_ptr[22] = DEFAULT_WINDOW_SCALE;

					tcb->next_rx_ssn[0] = 1; // SSN 0 was received in the SYN
				}else{
					opt_len = 19;
					opt_ptr = malloc(opt_len);

					opt_ptr[0] = OPT_KIND_MSS; // MSS Kind
					opt_ptr[1] = 4; // MSS Length
					opt_ptr[2] = TCP_MSS >> 8;
					opt_ptr[3] = TCP_MSS & 0xFF;
					opt_ptr[4] = OPT_KIND_TIMESTAMPS; // Timestamps Kind
					opt_ptr[5] = 10; // Timestamps Length
					opt_ptr[6] = 0;
					opt_ptr[7] = 0;
					opt_ptr[8] = 0;
					opt_ptr[9] = 0;
					opt_ptr[10] = 0;
					opt_ptr[11] = 0;
					opt_ptr[12] = 0;
					opt_ptr[13] = 0; 
					opt_ptr[14] = OPT_KIND_SACK_PERM; // SACK permitted Kind
					opt_ptr[15] = 2; // SACK permitted Length
					opt_ptr[16] = OPT_KIND_WIN_SCALE; // Window Scale Kind
					opt_ptr[17] = 3; // Window Scale Length
					opt_ptr[18] = DEFAULT_WINDOW_SCALE;
				}

				assert_handler_lock_acquired("SYN|ACK");
				prepare_tcp(s, SYN|ACK, NULL, 0, opt_ptr, opt_len);
				free(opt_ptr);
    			tcb->st = TCB_ST_SYN_RECEIVED;
			}
			break;
		case TCB_ST_SYN_RECEIVED:
			if(event == FSM_EVENT_PKT_RCV && !(tcp->flags & SYN) && (tcp->flags & ACK)){
				// It is an ACK (and it is not a SYN, that may be RETXed)
				if(htonl(tcp->ack) == tcb->seq_offs + 1){
					// Passive open connection establishment
					free(tcb->txfirst->segment);
					free(tcb->txfirst);
					tcb->txfirst = tcb->txlast = NULL;
					tcb->seq_offs++;
					tcb->ack_offs=htonl(tcp->seq);
					tcb->st = TCB_ST_ESTABLISHED;
					
					if(fdinfo[s].backlog_length == fdinfo[s].ready_channels){
						// The incoming connection (MS or not) cannot be accepted
						prepare_tcp(s,RST,NULL,0,NULL,0);
						ERROR("TODO reset TCB");
					}
					fdinfo[s].ready_channels++;
					fdinfo[s].ready_streams++; // Stream 0 is counted but is not inserted in the stream backlog


					/* Duplication of the current TCB and insertion in the backlog */

					int cursor_index;
					for(cursor_index = 0;cursor_index < fdinfo[s].backlog_length && fdinfo[s].channel_backlog[cursor_index].st != 0; cursor_index++); // Empty entries are bzero-ed, so they will have state 0
					struct tcpctrlblk* backlog_tcb = fdinfo[s].channel_backlog + cursor_index; // free tcb in the backlog
					memcpy(backlog_tcb, tcb, sizeof(struct tcpctrlblk));


					/* Initialization of the stream-specific fields and buffers */

					backlog_tcb->stream_state[0] = STREAM_STATE_READY;
					backlog_tcb->stream_tx_buffer[0] = malloc(TX_BUFFER_SIZE);
					backlog_tcb->stream_rx_queue[0] = backlog_tcb->stream_rx_queue_tail[0] = NULL;
					//backlog_tcb->adwin[0] = RX_VIRTUAL_BUFFER_SIZE; // For stream 0 this is initialized when the SYN is received
					backlog_tcb->radwin[0] = inflate_window_scale(ntohs(tcp->window), tcb->in_window_scale_factor);
					backlog_tcb->txfree[0] = TX_BUFFER_SIZE;
					backlog_tcb->tx_buffer_occupied_region_start[0] = backlog_tcb->tx_buffer_occupied_region_end[0] = 0;
					backlog_tcb->next_ssn[0] = 1; // SSN 0 already sent (SYN)

					backlog_tcb->next_rx_ssn[0] = 1; // SSN 0 already received (SYN+ACK)
					backlog_tcb->stream_fsm_timer[0] = 0;
					for(int i = 1; i<TOT_SID; i++){ // Initialize as unused all the streams after SID 0
						backlog_tcb->stream_state[i] = STREAM_STATE_UNUSED;
						backlog_tcb->stream_tx_buffer[i] = NULL;
						backlog_tcb->stream_rx_queue[i] = backlog_tcb->stream_rx_queue_tail[i] = NULL;
						backlog_tcb->adwin[i] = RX_VIRTUAL_BUFFER_SIZE; // RX buffer size
						backlog_tcb->radwin[i] = 0; // Initialized when the stream is created, based on the remote window for that stream
						backlog_tcb->txfree[i] = 0;
						backlog_tcb->tx_buffer_occupied_region_start[i] = backlog_tcb->tx_buffer_occupied_region_end[i] = 0;
						backlog_tcb->next_ssn[i] = 0;
						backlog_tcb->next_rx_ssn[i] = 0;
						backlog_tcb->stream_fsm_timer[i] = 0;
						backlog_tcb->write_side_close_state[i] = WR_CLOSE_ST_OPEN;
						backlog_tcb->lss_received[i] = backlog_tcb->lss_consumed[i] = false;
					}
					backlog_tcb->listening_fd = s;


					// Listening TCB re-initialization (same as mylisten)
					bzero(tcb,sizeof(struct tcpctrlblk));
					tcb->st = TCB_ST_LISTEN;
					fdinfo[s].tcb->is_active_side = false;
					fdinfo[s].tcb->listening_fd = s;
					fdinfo[s].sid = SID_UNASSIGNED; // Go back from stream 0 (used to open the incoming connection) to unassigned
				}
			}else if(event == FSM_EVENT_PKT_RCV && (tcp->flags & SYN) && !(tcp->flags & ACK)){
				LOG_MESSAGE("Dropped SYN packet");
			}
			break;
		case TCB_ST_ESTABLISHED:
			if(event ==FSM_EVENT_PKT_RCV && (tcp->flags & SYN)){
				// The SYN+ACK has been retransmitted (ignored)
				break;
			}
			if(event == FSM_EVENT_STREAM_TIMEOUT){
				int sid = fdinfo[s].sid;
				int ssn = fdinfo[s].tcb->next_ssn[sid];
				int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
				uint8_t* opt = malloc(optlen);
				memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
				
				// Stream update
				opt[2] = sid<<2 | ssn >> 8;
				opt[3] = ssn & 0xFF;

				update_next_ssn(&(fdinfo[s].tcb->next_ssn[sid]));

				uint8_t* dummy_payload = malloc(1); // value doesn't matter

				prepare_tcp(s, ACK | DMP, dummy_payload, 1, opt, optlen);

				free(dummy_payload);
				free(opt);
				break;
			}
			if(event == FSM_EVENT_PKT_RCV){
				int sid = 0;
				int ssn = 0;
				bool lss = false;
				if(tcb->ms_option_enabled){
					int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
					if(ms_index >= 0){
						lss = tcp->payload[ms_index+2]>>7;
						sid = (tcp->payload[ms_index+2]>>2) & 0x1F;
						ssn = ((tcp->payload[ms_index+2]&0x3) << 8) | tcp->payload[ms_index+3];
						if(!lss && tcb->stream_state[sid] == STREAM_STATE_UNUSED){ // LSS segments are leftovers from the previous use of the same stream
							tcb->stream_state[sid] = STREAM_STATE_READY;

							tcb->radwin[sid] = inflate_window_scale(ntohs(tcp->window), tcb->in_window_scale_factor);
							tcb->txfree[sid] = TX_BUFFER_SIZE;
							tcb->tx_buffer_occupied_region_start[sid] = tcb->tx_buffer_occupied_region_end[sid] = 0;
							if(tcb->stream_tx_buffer[sid] != NULL){
								ERROR("stream_tx_buffer != NULL before malloc");
							}
							tcb->stream_tx_buffer[sid] = malloc(TX_BUFFER_SIZE);
							tcb->stream_rx_queue[sid] = tcb->stream_rx_queue_tail[sid] = NULL;
							tcb->adwin[sid] = RX_VIRTUAL_BUFFER_SIZE;
							// tcb->next_rx_ssn[sid] not incremented because it will be incremented in myio when the packet is inserted in stream RX queue

							tcb->write_side_close_state[sid] = WR_CLOSE_ST_OPEN;
							tcb->lss_received[sid] = tcb->lss_consumed[sid] = false;

							// Insertion in the listening socket backlog
							struct stream_backlog_node* cursor = &fdinfo[tcb->listening_fd].stream_backlog_head;
							while(cursor->next != NULL){
								cursor = cursor->next;
							}
							cursor->next = (struct stream_backlog_node*) malloc(sizeof(struct stream_backlog_node));
							cursor->next->sid = sid;
							cursor->next->tcb = tcb;
							cursor->next->next = NULL;
							fdinfo[tcb->listening_fd].ready_streams++;
						}
					}
				}
			}
			break;
		default:
			ERROR("FSM unknown tcb->st %d", tcb->st);
	}
	return 0;
};




int myconnect(int s, struct sockaddr * addr, int addrlen){
	if((addr->sa_family != AF_INET)){
		myerrno = EINVAL; 
		return -1;
	}
	if ( s < 3 || s >= MAX_FD){
		myerrno = EBADF; 
		return -1;
	}

	if(myconnect_mode == MYCONNECT_MODE_BLOCKING){
		DEBUG("myconnect blocking socket %d", s);
		struct sockaddr_in * remote_addr = (struct sockaddr_in*) addr; //mytcp: a
		disable_signal_reception(false);
		int res = fsm(s, FSM_EVENT_APP_ACTIVE_OPEN, NULL, remote_addr); 
		enable_signal_reception(false);
		if(res < 0){
			// Bind may fail, or other errors
			return res;
		}
		//DEBUG("myconnect sid %d", fdinfo[s].sid);
		struct tcpctrlblk* tcb = fdinfo[s].tcb;
		if(tcb->st != TCB_ST_ESTABLISHED){
			while(sleep(10)){
				// This connect call is opening a new connection (Multi-Stream or not); wait until the SYN+ACK arrives
				if(tcb->st == TCB_ST_ESTABLISHED){
					return 0;
				}
				if(tcb->st == TCB_ST_CLOSED){ 
					myerrno = ECONNREFUSED; 
					return -1;
				}
			}
			// If the connection is not established within the timeout
			myerrno=ETIMEDOUT;
			return -1;
		}else{
			/*
			This connect call is opening a new stream in an existing connection. A segment that opens this new stream
			will be sent with the first chunk of data, or after STREAM_OPEN_TIMEOUT ticks if no data needs to be sent.
			*/
			return 0; // Do nothing and return
		}
	}else{ // myconnect_mode == MYCONNECT_MODE_NON_BLOCKING
		if(fdinfo[s].st == FDINFO_ST_UNBOUND || fdinfo[s].st == FDINFO_ST_BOUND){
			struct sockaddr_in * remote_addr = (struct sockaddr_in*) addr; //mytcp: a
			DEBUG("Active open FSM socket %d", s);
			disable_signal_reception(false);
			int res = fsm(s, FSM_EVENT_APP_ACTIVE_OPEN, NULL, remote_addr); 
			enable_signal_reception(false);
			if(res < 0){
				// Bind may fail, or other errors
				return res;
			}
		}
		struct tcpctrlblk* tcb = fdinfo[s].tcb;
		if(fdinfo[s].sid == 0){
			if(tcb->st == TCB_ST_ESTABLISHED){
				return 0;
			}
			if(tcb->st == TCB_ST_CLOSED){ 
				myerrno = ECONNREFUSED; 
				return -1;
			}
			myerrno = EAGAIN; 
			return -1;
		}else{
			/* 
			This connect call is opening a new stream in an existing connection. A segment that opens this new stream
			will be sent with the first chunk of data, or after STREAM_OPEN_TIMEOUT ticks if no data needs to be sent.
			*/
			return 0; // Do nothing and return
		}
	}


}

int mylisten(int s, int bl){
	if(fdinfo[s].st!=FDINFO_ST_BOUND){
		myerrno=EBADF; 
		return -1;
	}
	fdinfo[s].tcb = (struct tcpctrlblk *) malloc (sizeof(struct tcpctrlblk));
	bzero(fdinfo[s].tcb,sizeof(struct tcpctrlblk));
	fdinfo[s].st = FDINFO_ST_TCB_CREATED;
	fdinfo[s].tcb->st = TCB_ST_LISTEN;
	fdinfo[s].tcb->is_active_side = false;
	fdinfo[s].tcb->listening_fd = s;
	fdinfo[s].channel_backlog = (struct tcpctrlblk*) malloc(bl * sizeof(struct tcpctrlblk));
	bzero(fdinfo[s].channel_backlog, bl * sizeof(struct tcpctrlblk));
	fdinfo[s].ready_streams = 0;
	fdinfo[s].ready_channels = 0;
	fdinfo[s].backlog_length = bl;
	fdinfo[s].stream_backlog_head.tcb = NULL;
	fdinfo[s].stream_backlog_head.sid = -1;
	fdinfo[s].stream_backlog_head.next = NULL;
	myerrno = 0;
	return 0;
}

int myaccept(int s, struct sockaddr* addr, int * len){
	if (addr->sa_family != AF_INET){
		ERROR("myaccept addr->sa_family != AF_INET");
		myerrno=EINVAL; 
		return -1;
	}
	if(fdinfo[s].st != FDINFO_ST_TCB_CREATED || fdinfo[s].tcb == NULL){
		ERROR("myaccept fdinfo[s] without TCB");
	}
	if (fdinfo[s].tcb->st!=TCB_ST_LISTEN && fdinfo[s].tcb->st!=TCB_ST_SYN_RECEIVED) {
		ERROR("myaccept invalid fdinfo[s].tcb->st %d", fdinfo[s].tcb->st);
		myerrno=EBADF; 
		return -1;
	}
	struct sockaddr_in * a = (struct sockaddr_in *) addr;
  	*len = sizeof(struct sockaddr_in);
	if(myaccept_mode == MYACCEPT_MODE_NON_BLOCKING && fdinfo[s].ready_streams == 0){
		// Early return to avoid useless signal lock in while(true) polling loop
		// Hopefully this doesn't cause race condition issues...
		myerrno = EAGAIN;
		return -1;
	}
	do{
		disable_signal_reception(false);
	
		if(fdinfo[s].ready_streams == 0){
			enable_signal_reception(false);

			if(myaccept_mode == MYACCEPT_MODE_NON_BLOCKING){
				myerrno = EAGAIN;
				return -1;
			}

			/*
			"Within a do or a while statement, the next iteration starts by reevaluating the expression of the do or while statement."
			https://learn.microsoft.com/en-us/cpp/c-language/continue-statement-c?view=msvc-170
			*/
			continue;
		}
		



		// At this point we are sure that there is something that can be returned
		int free_fd; // mytcp: j
		for(free_fd=3; free_fd<MAX_FD && fdinfo[free_fd].st!=FDINFO_ST_FREE; free_fd++); // Searching for free fd
		if(free_fd == MAX_FD){
			myerrno=ENFILE; 
			enable_signal_reception(false);
			return -1;
		}
		if(fdinfo[s].ready_channels > 0){
			int cursor_index;
			/* The condition st != TCB_ST_ESTABLISHED will be valid also if the passive open connection establishment behaviour 
			is changed, and not only the listening socket is used to open one connection at a time */
			for(cursor_index = 0; cursor_index < fdinfo[s].backlog_length && fdinfo[s].channel_backlog[cursor_index].st != TCB_ST_ESTABLISHED; cursor_index++);
			if(cursor_index == fdinfo[s].backlog_length){
				ERROR("myaccept ready_channels > 0 but no TCB found in the backlog");
			}
			struct tcpctrlblk* tcb = (struct tcpctrlblk*) malloc(sizeof(struct tcpctrlblk));
			memcpy(tcb, fdinfo[s].channel_backlog + cursor_index, sizeof(struct tcpctrlblk));
			bzero(fdinfo[s].channel_backlog + cursor_index, sizeof(struct tcpctrlblk));

			tcb->stream_state[0] = STREAM_STATE_OPENED;

			fdinfo[free_fd].st = FDINFO_ST_TCB_CREATED;
			fdinfo[free_fd].tcb = tcb;
			fdinfo[free_fd].sid = 0;
			fdinfo[free_fd].l_port = fdinfo[s].l_port;
			fdinfo[free_fd].l_addr = fdinfo[s].l_addr;

			// There is no entry for stream 0 in the backlog
			fdinfo[s].ready_streams--;
			fdinfo[s].ready_channels--;

			prepare_tcp(free_fd, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
			enable_signal_reception(false);
			return free_fd;
		}

		// There are no ready channels: consume an entry of the stream backlog
		struct stream_backlog_node* first = fdinfo[s].stream_backlog_head.next;
		if(first == NULL){
			ERROR("myaccept ready_streams %d > 0 but first is NULL", fdinfo[s].ready_channels);
		}
		if(first->tcb == NULL){
			ERROR("myaccept first tcb NULL");
		}

		fdinfo[free_fd].st = FDINFO_ST_TCB_CREATED;
		fdinfo[free_fd].tcb = first->tcb;
		fdinfo[free_fd].sid = first->sid;
		fdinfo[free_fd].tcb->stream_state[fdinfo[free_fd].sid] = STREAM_STATE_OPENED;
		fdinfo[free_fd].l_port = fdinfo[s].l_port;
		fdinfo[free_fd].l_addr = fdinfo[s].l_addr;

		// Remove the entry from the stream backlog
		fdinfo[s].ready_streams--;
		fdinfo[s].stream_backlog_head.next = first->next;

		prepare_tcp(free_fd, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
		enable_signal_reception(false);
		return free_fd;
	}while(pause());
	ERROR("myaccept something went very wrong, you should never reach after the do while in myaccept"); // pause always returns -1
}

int mywrite(int s, uint8_t * buffer, int maxlen){
	if(fdinfo[s].st != FDINFO_ST_TCB_CREATED || fdinfo[s].tcb == NULL || fdinfo[s].tcb->st != TCB_ST_ESTABLISHED){
		ERROR("mywrite invalid socket %d %d", fdinfo[s].st, FDINFO_ST_TCB_CREATED);
	}
	if(fdinfo[s].st != FDINFO_ST_TCB_CREATED || fdinfo[s].tcb->st != TCB_ST_ESTABLISHED){
		myerrno = EINVAL;
		return -1;
	}
	int sid = fdinfo[s].sid;
	if(fdinfo[s].tcb->write_side_close_state[sid] > WR_CLOSE_ST_OPEN){
		// This should never happen, because after close() the fdinfo entry should be unlinked from the TCB
		ERROR("mywrite fd %d sid %d invalid stream state %d", s, sid, fdinfo[s].tcb->write_side_close_state[sid]);
	}
	if(maxlen < 0){
		ERROR("mywrite invalid maxlen %d");
	}
	if(maxlen == 0){
		return 0;
	}
	
	int actual_len;
	if(mywrite_mode == MYWRITE_MODE_NON_BLOCKING){
		if(fdinfo[s].tcb->txfree[sid] == 0){
			myerrno = EAGAIN;
			return -1;
		}
		actual_len = MIN(maxlen,fdinfo[s].tcb->txfree[sid]);
	}else{
		do{
			actual_len = MIN(maxlen,fdinfo[s].tcb->txfree[sid]);
			if ((actual_len !=0) || (fdinfo[s].tcb->st == TCB_ST_CLOSED)) break;
		}while(pause());
	}
	
	disable_signal_reception(false);

	/*
	for(int byte_num = 0; byte_num < actual_len; byte_num++){
		fdinfo[s].tcb->stream_tx_buffer[sid][fdinfo[s].tcb->tx_buffer_occupied_region_end[sid]] = buffer[byte_num];
		fdinfo[s].tcb->tx_buffer_occupied_region_end[sid] = (fdinfo[s].tcb->tx_buffer_occupied_region_end[sid] + 1) % TX_BUFFER_SIZE;
		fdinfo[s].tcb->txfree[sid]--;
	}
	*/
	struct tcpctrlblk* tcb = fdinfo[s].tcb;
	int write_pos = tcb->tx_buffer_occupied_region_end[sid];
	unsigned int bytes_to_end = TX_BUFFER_SIZE - write_pos;
	int first_chunk = actual_len;
	int second_chunk = 0;
	if(first_chunk > bytes_to_end){
		second_chunk = first_chunk - bytes_to_end;
		first_chunk -= second_chunk;
	}
	memcpy(tcb->stream_tx_buffer[sid] + write_pos, buffer, first_chunk);
	memcpy(tcb->stream_tx_buffer[sid], buffer + first_chunk, second_chunk);
	tcb->tx_buffer_occupied_region_end[sid] = (write_pos + actual_len) % TX_BUFFER_SIZE;
	fdinfo[s].tcb->txfree[sid] -= actual_len;

	scheduler(s);
	enable_signal_reception(false);
	return actual_len;
}

int myread(int s, unsigned char *buffer, int maxlen){
	bool adwin_increased = false;
	if((fdinfo[s].st != FDINFO_ST_TCB_CREATED) || (fdinfo[s].tcb->st < TCB_ST_ESTABLISHED )){ 
		ERROR("Invalid socket myread");
		myerrno = EINVAL; 
		return -1; 
	}
	if (maxlen==0){
		DEBUG("myread maxlen == 0");
		return 0;
	}
	/*
	if(!fdinfo[s].tcb->ms_option_enabled){
		ERROR("ms option not enabled myread");
	}
	*/
	int sid = fdinfo[s].sid;
	if(sid == SID_UNASSIGNED){
		if(!fdinfo[s].tcb->ms_option_enabled){
			sid = 0;
		}else{
			ERROR("sid unassigned myread");
		}
	}
	struct tcpctrlblk* tcb = fdinfo[s].tcb;
	if(tcb->stream_state[sid] < STREAM_STATE_OPENED){
		ERROR("myread fd %d sid %d invalid stream state %d ", s, sid, tcb->stream_state[sid]);
	}
	if(tcb->lss_consumed[sid]){
		DEBUG("LSS already consumed, return 0");
		return 0;
	}
	if(myread_mode == MYREAD_MODE_NON_BLOCKING && tcb->stream_rx_queue[sid] == NULL){
		// Early return to avoid the signal locks
		// Hopefully this doesn't cause any race condition issues...
		myerrno = EAGAIN;
		return -1;
	}
	disable_signal_reception(false);
	while(tcb->stream_rx_queue[sid] == NULL || (tcb->stream_rx_queue[sid]->dummy_payload && !tcb->stream_rx_queue[sid]->lss)){
		if(tcb->stream_rx_queue[sid] != NULL){
			assert_handler_lock_acquired("dmp removal myread");
			// condition "tcb->stream_rx_queue[sid]->dummy_payload" is true
			struct stream_rx_queue_node* dmp_node = tcb->stream_rx_queue[sid];
			tcb->stream_rx_queue[sid] = tcb->stream_rx_queue[sid]->next;
			if(tcb->stream_rx_queue[sid] == NULL){
				tcb->stream_rx_queue_tail[sid] = NULL;
			}
			// tcb->adwin[sid] does not account for dmp segments
			free(dmp_node->segment);
			free(dmp_node);
			continue;
		}
		switch(myread_mode){
			case MYREAD_MODE_BLOCKING:
				enable_signal_reception(false);
				pause();
				disable_signal_reception(false);
				break;
			case MYREAD_MODE_NON_BLOCKING:
				enable_signal_reception(false);
				myerrno = EAGAIN;
				return -1;
				break;
			default:
				ERROR("myread invalid myread_mode %d", myread_mode);
		}
	}

	// At this point there is something to consume
	assert_handler_lock_acquired("myread consumption start");
	int read_consumed_bytes = 0;
	while(tcb->stream_rx_queue[sid] != NULL && read_consumed_bytes < maxlen){
		bool lss = tcb->stream_rx_queue[sid]->lss;
		if(!tcb->ms_option_enabled){
			lss = tcb->stream_rx_queue[0]->segment->flags & FIN;
		}
		if(lss && (tcb->stream_rx_queue[sid]->dummy_payload || (tcb->stream_rx_queue[sid]->consumed_bytes == tcb->stream_rx_queue[sid]->payload_length) || (!tcb->ms_option_enabled))){
			if(read_consumed_bytes != 0){
				// Do not consume this segment at this time: it will be consumed at the next call of myread, that will return 0
				break;
			}else{
				// Received the LSS!

				if(!tcb->ms_option_enabled && tcb->stream_rx_queue[sid]->dummy_payload){
					ERROR("DMP LSS with non-MS in myread");
				}

				// Remove the LSS segment from the queue
				struct stream_rx_queue_node* dmp_node = tcb->stream_rx_queue[sid];
				tcb->stream_rx_queue[sid] = tcb->stream_rx_queue[sid]->next;
				if(tcb->stream_rx_queue[sid] == NULL){
					tcb->stream_rx_queue_tail[sid] = NULL;
				}
				free(dmp_node->segment);
				free(dmp_node);

				tcb->lss_consumed[sid] = true;

				// Nota: potrebbero esserci altri segmenti rimasti in coda: non dovrebbero avere payload, ma potrebbero essere DMP usati per ACK o window update
				// In realtà, se in myio si scartano tutti i segmenti con flag LSS dopo aver attivato lss_received (dopo aver considerato la loro adwin), non dovrebbero esserci più segmenti in coda dopo questo LSS
				enable_signal_reception(false);
				return 0;
			}
			
		}
		if(tcb->stream_rx_queue[sid]->dummy_payload){
			if(!tcb->ms_option_enabled){
				ERROR("DMP segment in myread non-MS");
			}
			struct stream_rx_queue_node* dmp_node = tcb->stream_rx_queue[sid];
			tcb->stream_rx_queue[sid] = tcb->stream_rx_queue[sid]->next;
			if(tcb->stream_rx_queue[sid] == NULL){
				tcb->stream_rx_queue_tail[sid] = NULL;
			}
			// tcb->adwin[sid] does not account for dmp segments
			// free dmp_node and its segment
			free(dmp_node->segment);
			free(dmp_node);

			continue;
		}
		int missing_read_bytes = maxlen - read_consumed_bytes;
		int remaining_segment_bytes = tcb->stream_rx_queue[sid]->payload_length - tcb->stream_rx_queue[sid]->consumed_bytes;

		int current_segment_read_bytes = MIN(missing_read_bytes, remaining_segment_bytes);
		memcpy(buffer + read_consumed_bytes, tcb->stream_rx_queue[sid]->segment->payload + ((tcb->stream_rx_queue[sid]->segment->d_offs_res>>4)*4-20) + tcb->stream_rx_queue[sid]->consumed_bytes, current_segment_read_bytes);

		read_consumed_bytes += current_segment_read_bytes;
		tcb->stream_rx_queue[sid]->consumed_bytes += current_segment_read_bytes;
		tcb->adwin[sid] += current_segment_read_bytes;
		adwin_increased = true;
		if(!lss && tcb->stream_rx_queue[sid]->consumed_bytes == tcb->stream_rx_queue[sid]->payload_length){
			// Segment fully consumed: remove it from the stream rx queue
			struct stream_rx_queue_node* dmp_node = tcb->stream_rx_queue[sid];
			tcb->stream_rx_queue[sid] = tcb->stream_rx_queue[sid]->next;

			if(tcb->stream_rx_queue[sid] == NULL){
				tcb->stream_rx_queue_tail[sid] = NULL;
			}

			// free dmp_node and its segment
			free(dmp_node->segment);
			free(dmp_node);
		}
	}
	if(adwin_increased){
		if(!tcb->ms_option_enabled){
			fast_send_tcp(s, ACK, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
		}else{
			int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
			uint8_t* opt = malloc(optlen);
			memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
			
			// Stream update
			opt[2] = sid<<2 | (tcb->next_ssn[sid] >> 8)&0x3;
			opt[3] = (tcb->next_ssn[sid])&0xFF;
			update_next_ssn(&(tcb->next_ssn[sid]));

			uint8_t* dummy_payload = malloc(1); // value doesn't matter

			prepare_tcp(s, ACK | DMP, dummy_payload, 1, opt, optlen);
			free(dummy_payload);
			free(opt);
		}
	}else{
		ERROR("adwin not increased during myread consumption");
	}
	assert_handler_lock_acquired("myread consumption end");
	enable_signal_reception(false);
	return read_consumed_bytes;
}

int myclose(int s){
	int sid = fdinfo[s].sid;
	//DEBUG("myclose sid %d", sid);
	struct tcpctrlblk* tcb = fdinfo[s].tcb;
	disable_signal_reception(false);
	if(tcb->write_side_close_state[sid] > WR_CLOSE_ST_OPEN){
		// This should never happen, because with close you should unlink the tcb from fdinfo
		ERROR("myclose close_state %d > OPEN", tcb->write_side_close_state[sid]);
	}
	
	tcb->write_side_close_state[sid] = WR_CLOSE_ST_LSS_REQUESTED;
	scheduler(s);
	enable_signal_reception(false);
	return 0;
}

void stream_close_handler(struct tcpctrlblk* tcb, int sid){
	if(tcb == NULL){
		ERROR("stream_close_handler tcb NULL");
	}
	if(sid < 0){
		ERROR("stream_close_handler invalid sid");
	}
	if(tcb->write_side_close_state[sid] == WR_CLOSE_ST_LSS_ACKED && tcb->lss_received[sid]){
		/*
		We do not go throught STREAM_STATE_CLOSED. Another solution could be to go to state STREAM_STATE_UNUSED here, set a timer, and after that timer
		elapses reset the stream and prepare it for reuse. With the current version of the program there is only the close() operation, so there is no risk
		that if the LSS has been received the other peer is still reading or using the structures for this stream.
		*/
		while(tcb->stream_rx_queue[sid] != NULL){
			struct stream_rx_queue_node* tmp = tcb->stream_rx_queue[sid];
			tcb->stream_rx_queue[sid] = tcb->stream_rx_queue[sid]->next;
			if(!tmp->dummy_payload){
				ERROR("non-DMP remaining segment during stream_close_handler flush");
			}
			if(tmp->segment != NULL){
				free(tmp->segment);
			}
			free(tmp);
		}

		tcb->stream_state[sid] = STREAM_STATE_UNUSED;
		tcb->adwin[sid] = RX_VIRTUAL_BUFFER_SIZE; // RX Buffer Size
		tcb->radwin[sid] = tcb->init_radwin; 
		if(tcb->stream_tx_buffer[sid] != NULL){
			free(tcb->stream_tx_buffer[sid]);
			tcb->stream_tx_buffer[sid] = NULL;
		}
		tcb->txfree[sid] = TX_BUFFER_SIZE;
		tcb->tx_buffer_occupied_region_start[sid] = tcb->tx_buffer_occupied_region_end[sid] = 0;
		tcb->stream_fsm_timer[sid] = 0;

		//DEBUG("Stream %d ready for reuse", sid);
	}
	return;
}


// Called only in myio, for every received packet, if after the FSM the connection is at least established
void rtt_estimate(struct tcpctrlblk* tcb, struct tcp_segment* tcp){
	if(tcb == NULL || tcp == NULL){
		ERROR("rtt_estimate NULL param");
	}
	int ts_index = search_tcp_option(tcp, OPT_KIND_TIMESTAMPS);
	if(ts_index == -1){
		ERROR("rtt_estimate segment without Timestamps option");
	}
	uint32_t now = get_tcp_timestamp_ms();
	uint32_t rtt_ms = now - ntohl(*(uint32_t*) (tcp->payload+ts_index+6));
	double rtt_sec = ((double)rtt_ms)/1000; 
	LOG_RTT(rtt_sec);
	uint32_t rtt_ticks = rtt_ms * 1000 / TIMER_USECS;
	if(tcb->rtt_e == 0) {
		tcb->rtt_e = rtt_ticks; 
		tcb->Drtt_e = rtt_ticks/2; 
	}
	else{
		tcb->Drtt_e = ((8-BETA)*tcb->Drtt_e + BETA*abs(rtt_ticks-tcb->rtt_e))>>3;
		tcb->rtt_e = ((8-ALPHA)*tcb->rtt_e + ALPHA*rtt_ticks)>>3;
	}
	tcb->timeout = MIN(MAX(tcb->rtt_e + KRTO*tcb->Drtt_e,MIN_TIMEOUT), MAX_TIMEOUT);
	LOG_RTO(tcb->timeout);
}
void print_rx_queue(struct tcpctrlblk* tcb){
	struct channel_rx_queue_node *cursor = tcb->unack;
	printf("Channel RX queue: unack=");
	while(cursor != NULL){
		int sid = -1, ssn = -1;
		bool ms_option_included = false;
		if(tcb->ms_option_enabled && cursor->segment != NULL){
			int ms_index = search_tcp_option(cursor->segment, OPT_KIND_MS_TCP);
			if(ms_index >= 0){
				sid = (cursor->segment->payload[ms_index+2]>>2) & 0x1F;
				ssn = ((cursor->segment->payload[ms_index+2]&0x3) << 8) | cursor->segment->payload[ms_index+3];
			}
		}

		printf("{%u, %d [%s] (%d|%d)}->", cursor->channel_offset, cursor->payload_length, cursor->segment!=NULL?"X":" ", sid, ssn);
		cursor = cursor->next;
	}
	printf("NULL\n");
}
void myio(int ignored){
	disable_signal_reception(true);
	struct timespec start, end;
	clock_gettime(CLOCK_REALTIME, &start);
	assert_handler_lock_acquired("myio start");

	struct pollfd fds[1];
	fds[0].fd = unique_raw_socket_fd;
	fds[0].events = POLLIN;
	fds[0].revents=0;
	if(poll(fds,1,0) == -1) { 
		perror("Poll myio failed"); 
		exit(EXIT_FAILURE);
	}

	if(!(fds[0].revents & POLLIN)){
		// There is nothing to read
		
		enable_signal_reception(true);
		return;
	}

	int received_packet_size; // mytcp: size
	while((received_packet_size = recvfrom(unique_raw_socket_fd,l2_rx_buf,L2_RX_BUF_SIZE,0,NULL,NULL))>=0){
		if(received_packet_size < 0){
			perror("recvfrom");
			ERROR("recvfrom errno %d", errno);
		}
		if(received_packet_size < sizeof(struct ethernet_frame)){
			DEBUG("low received_packet_size %d < %lu", received_packet_size, sizeof(struct ethernet_frame));
			continue;
		}
		struct timespec start2, end2;
		clock_gettime(CLOCK_REALTIME, &start2);
		struct ethernet_frame* eth=(struct ethernet_frame *)l2_rx_buf;
		if(eth->type == htons(0x0806)){
			// ARP
			struct arp_packet * arp = (struct arp_packet *) eth->payload;
			if(htons(arp->op) == 2){// It is ARP response
				int i;
				for(i=0;(i<MAX_ARP) && (arpcache[i].key!=0);i++){
					if(!memcmp(&arpcache[i].key,arp->srcip,4)){
						memcpy(arpcache[i].mac,arp->srcmac,6); // Update
						break;
					}
				}
				if(i < MAX_ARP && arpcache[i].key==0){
					memcpy(arpcache[i].mac,arp->srcmac,6); //new insert
					memcpy(&arpcache[i].key,arp->srcip,4); // Update
				}
			}
		}else if(eth->type == htons(0x0800)){
			// IP
			struct ip_datagram * ip = (struct ip_datagram *) eth->payload;
			if(ip->proto != TCP_PROTO){
				continue;
			}

			// TCP
			struct tcp_segment * tcp = (struct tcp_segment *) ((char*)ip + (ip->ver_ihl&0x0F)*4);

			int i;
			for(i=0;i<MAX_FD;i++){
				if((fdinfo[i].st == FDINFO_ST_TCB_CREATED) && (tcp->d_port == fdinfo[i].l_port) && (tcp->s_port == fdinfo[i].tcb->r_port) && (ip->srcaddr == fdinfo[i].tcb->r_addr)){
					break;
				}
				if(
					(fdinfo[i].st == FDINFO_ST_TCB_CREATED) && (fdinfo[i].l_port == tcp->d_port) && (tcp->s_port == fdinfo[i].tcb->r_port) 
					&& 
					(ip->srcaddr == *(uint32_t*)myip) && (inet_addr("127.0.0.1") == fdinfo[i].tcb->r_addr)
				){
					break;
				}
			}
			if(i == MAX_FD){
				for(i=0;i<MAX_FD;i++){
					if( (fdinfo[i].st == FDINFO_ST_TCB_CREATED) &&(fdinfo[i].tcb->st == TCB_ST_LISTEN || fdinfo[i].tcb->st == TCB_ST_SYN_RECEIVED) && (tcp->d_port == fdinfo[i].l_port) ){
						break;
					}
				}
			}
			if(i == MAX_FD){
				// The packet is not for me
				continue; // go to the processing of the next received packet, if any
			}

			LOG_TCP_SEGMENT("IN", (uint8_t*) tcp, htons(ip->totlen) - (ip->ver_ihl&0xF)*4);

			struct tcpctrlblk * tcb = fdinfo[i].tcb;
			assert_handler_lock_acquired("myio FSM_EVENT_PKT_RCV");
			fsm(i, FSM_EVENT_PKT_RCV, ip, NULL);

			if(tcb->st < TCB_ST_ESTABLISHED){
				continue;
			}


			if(tcp->flags & SYN){
				if(tcp->flags & ACK){
					// RTT estimate for SYN - SYN+ACK exchange
					rtt_estimate(tcb, tcp);
				}
				// SYN or SYN+ACK packets don't need to remove anything from the queue and don't generate any ack after the FSM (everything is done in there)
				continue;
			}

			int payload_length = htons(ip->totlen) - (ip->ver_ihl&0xF)*4 - (tcp->d_offs_res>>4)*4;

			if(tcb->txfirst !=NULL){
				// Removal from TX queue for the cumulative ACK

				uint32_t shifter = tcb->seq_offs;

				int sid = -1;
				int ssn = 0;
				bool ms_option_included = false;
				if(tcb->ms_option_enabled){
					int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
					if(ms_index >= 0){
						sid = (tcp->payload[ms_index+2]>>2) & 0x1F;
						ssn = ((tcp->payload[ms_index+2]&0x3) << 8) | tcp->payload[ms_index+3];
						ms_option_included = true;
					}
				}

				// TODO ho tolto il controllo per il FIN, va rimesso se si sistema la chiusura delle connessioni
				if((htonl(tcp->ack) >= shifter) && (htonl(tcp->ack)-shifter <= htonl(tcb->txlast->segment->seq) + ((uint32_t)tcb->txlast->payloadlen) - shifter)){
					bool send_window_advanced = false;
					while((tcb->txfirst!=NULL) && ((htonl(tcp->ack)-shifter) >= (htonl(tcb->txfirst->segment->seq)-shifter + tcb->txfirst->payloadlen))){ //Ack>=Seq+payloadlen						
						struct txcontrolbuf * temp = tcb->txfirst;
						tcb->txfirst = tcb->txfirst->next;
						
						/* 
						14/01/2025 Ho tolto la modifica di txfree da questo punto perchè lo spazio nel buffer di trasmissione viene liberato quando i dati
						vengono consumati per creare i segmenti da trasmettere (secondo quanto deciso dallo scheduler, per MS-TCP), quindi una volta che sono
						nella coda di trasmissione non occupano più spazio nel TX buffer e quindi non devono avere nessun impatto su txfree
						// fdinfo[i].tcb->txfree[fdinfo[i].sid]+=temp->payloadlen;
						*/

						// RTT calculation removed

						if(!temp->dummy_payload && temp->payloadlen > 0){
							fdinfo[i].tcb->flightsize-=temp->payloadlen;

							int sid = temp->sid;
							if(!tcb->ms_option_enabled){
								sid = 0;
							}

							if(tcb->radwin[sid] < temp->payloadlen){
								ERROR("tcb->radwin[%d] would become < 0", sid);
							}
							tcb->radwin[sid] -= temp->payloadlen;
						}

						int sid = -1;
						bool lss = false;
						int ms_index = search_tcp_option(temp->segment, OPT_KIND_MS_TCP);
						if(ms_index>=0){
							sid = (temp->segment->payload[ms_index+2]>>2) & 0x1F;
							lss = temp->segment->payload[ms_index+2]>>7;
						}
						if(sid >= 0){
							// MS option is present
							if(tcb->write_side_close_state[sid] == WR_CLOSE_ST_LSS_TXED && lss){
								tcb->write_side_close_state[sid] = WR_CLOSE_ST_LSS_ACKED;
								stream_close_handler(tcb, sid);
							}
						}

						free(temp->segment);
						free(temp);
						if(tcb->txfirst	== NULL){
							tcb->txlast = NULL;
						}

						send_window_advanced = true;
					}//While


					if(send_window_advanced){
						/*
						Here we know that the received segment made an update to the "incoming" cumulativeack (it changed the left side of the send window).
						According to RFC 7323, Section 4:
						RTTM Rule:	A TSecr value received in a segment MAY be used to update
									the averaged RTT measurement only if the segment advances
									the left edge of the send window, i.e., SND.UNA is
									increased.
						// https://www.rfc-editor.org/rfc/rfc7323#section-4
						*/
						rtt_estimate(tcb, tcp);
					}

					congctrl_fsm(tcb,FSM_EVENT_PKT_RCV,tcp,payload_length);
				}
			}

			if(tcb->txfirst != NULL){
				// Removal from TX queue for SACK option

				int sack_opt_index = search_tcp_option(tcp, OPT_KIND_SACK);
				if(sack_opt_index > 0){

					uint32_t shifter = tcb->seq_offs;

					int sack_entries_count = (tcp->payload[sack_opt_index+1] - 2) / 8;
					if(sack_entries_count > 0){
						//DEBUG("%d SACK entries! shifter=%u", sack_entries_count, shifter);
					}
					for(int entry = 0; entry < sack_entries_count; entry++){
						int block_left_edge_seq = ntohl(*((uint32_t*) (tcp->payload + sack_opt_index + 2 + entry*8)));
						int block_right_edge_seq = ntohl(*((uint32_t*) (tcp->payload + sack_opt_index + 2 + entry*8 + 4)));

						uint32_t left_shifted_seq = block_left_edge_seq - shifter;
						uint32_t right_shifted_seq = block_right_edge_seq - shifter;

						//DEBUG("%u - %u (src %u - %u)", left_shifted_seq, right_shifted_seq, block_left_edge_seq,block_right_edge_seq);

						struct txcontrolbuf *cursor = tcb->txfirst, *prev = NULL;
						while(cursor != NULL){
							uint32_t cursor_shifted_seq = cursor->seq - shifter;
							uint32_t cursor_shifted_end = cursor_shifted_seq + cursor->payloadlen;

							if(left_shifted_seq <= cursor_shifted_seq && cursor_shifted_end <= right_shifted_seq){
								//DEBUG("Something removed");
								// Remove the node from the tx queue

								if(!cursor->dummy_payload && cursor->payloadlen > 0){
									// Sono abbastanza sicuro della modifica della flightsize, ma non di quella della radwin
									fdinfo[i].tcb->flightsize-=cursor->payloadlen;

									/*
									if(tcb->radwin[cursor->sid] < cursor->payloadlen){
										ERROR("tcb->radwin[%d] would become < 0 (SACK)", cursor->sid);
									}
									tcb->radwin[cursor->sid] -= cursor->payloadlen;
									*/
								}

								int sid = -1;
								bool lss = false;
								int ms_index = search_tcp_option(cursor->segment, OPT_KIND_MS_TCP);
								if(ms_index>=0){
									sid = (cursor->segment->payload[ms_index+2]>>2) & 0x1F;
									lss = cursor->segment->payload[ms_index+2]>>7;
								}
								if(sid >= 0){
									// MS option is present in cursor segment
									if(tcb->write_side_close_state[sid] == WR_CLOSE_ST_LSS_TXED && lss){
										tcb->write_side_close_state[sid] = WR_CLOSE_ST_LSS_ACKED;
										stream_close_handler(tcb, sid);
									}
								}


								if(prev == NULL){
									tcb->txfirst = cursor->next;
									if(tcb->txfirst == NULL){
										tcb->txlast = NULL; // The list is now empty
									}
									free(cursor->segment);
									free(cursor);
									cursor = tcb->txfirst;
									if(tcb->txfirst == NULL){
										break;
									}
								}else{
									prev->next = cursor->next;
									if(tcb->txlast == cursor){
										tcb->txlast = prev;
									}
									free(cursor->segment);
									free(cursor);
									cursor = prev->next;
								}
							}else{
								prev = cursor;
								cursor = cursor->next;
							}
						}
					}
				}
			}

			if(payload_length > 0){
				int sid = 0;
				int ssn = 0;
				bool dummy_payload = false;
				bool ms_option_included = false;
				if(tcb->ms_option_enabled){
					int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
					if(ms_index >= 0){
						sid = (tcp->payload[ms_index+2]>>2) & 0x1F;
						ssn = ((tcp->payload[ms_index+2]&0x3) << 8) | tcp->payload[ms_index+3];
						ms_option_included = true;
						dummy_payload = tcp->d_offs_res & (DMP >> 8);
					}
				}

				bool in_order_for_channel = true; // Updated later in the code

				uint32_t channel_offset = ntohl(tcp->seq)-tcb->ack_offs; // Position of this segment in the channel stream, without the initial random offset
				if(channel_offset >= tcb->cumulativeack){
					// This segment is not a duplicate of something already cumulative-acked

					uint32_t new_radwin = inflate_window_scale(ntohs(tcp->window), tcb->in_window_scale_factor);
					if(new_radwin >= tcb->radwin[sid]){
						tcb->radwin[sid] = new_radwin;
					}

					struct channel_rx_queue_node* newrx = NULL;
					if(tcb->unack == NULL){
						// The RX queue is empty and this packet is not a duplicate of an already ACKed one: this packet becomes the only one in the RX queue
						tcb->unack = tcb->unack_tail = newrx = create_channel_rx_queue_node(channel_offset, ip, tcp, NULL, NULL);
					}else{
						// There is already at least one packet in the RX queue: traverse the queue until you get to the end or you find a node with higher channel offset
						struct channel_rx_queue_node *prev = NULL, *cursor = tcb->unack;
						while(cursor != NULL && cursor->channel_offset < channel_offset){
							prev = cursor;
							cursor = cursor->next;
						}
						if(cursor == NULL){
							// We traversed the whole queue without finding any segment with a higher channel offset: insert the new one at the end of the queue
							newrx = create_channel_rx_queue_node(channel_offset, ip, tcp, prev, NULL);
							tcb->unack_tail = prev->next = newrx;

							// If we insert a segment at the end of its stream RX queue, we use it to update radwin

							tcb->radwin[sid] = new_radwin;
						}else{
							// Now cursor is either NULL or has a channel_offset <= to that of the RXed segment
							if(cursor->channel_offset != channel_offset){
								// using "cursor" as next handles correctly both the cases for end of the queue and for middle of the queue
								newrx = create_channel_rx_queue_node(channel_offset, ip, tcp, prev, cursor);
								
								cursor->prev = newrx;

								if(prev == NULL){
									// Insertion at the beginning of the queue
									tcb->unack = newrx;
								}else{
									// Insertion in the middle (or at the end) of the queue
									prev->next = newrx;
								}
							}else{
								// Duplicate of an out-of-order packet (ignored)
							}
						}
					}
					// if newrx == NULL the packet was a duplicate of an out-of-order packet
					if(newrx != NULL){
						// new node has been inserted in the channel queue

						//in_order_for_channel = false;

						if(tcb->ms_option_enabled){
							bool newrx_in_order_for_stream = true;
							struct channel_rx_queue_node* c = tcb->unack;
							while(c != NULL && c != newrx){
								if(c->sid == newrx->sid && c->segment != NULL){
									newrx_in_order_for_stream = false;
									break;
								}
								c = c->next;
							}
							if(newrx_in_order_for_stream){
								struct channel_rx_queue_node* cursor = newrx;
								int current_candidate_ssn = ssn; // Do avoid "polluting" the variable "ssn" used for newrx
								while(cursor != NULL && tcb->next_rx_ssn[sid] == current_candidate_ssn){
									// cursor contains an in-order segment for the stream
									
									// This unlinks the segments in cursor and links it to the new stream queue node
									struct stream_rx_queue_node* newrx_stream = create_stream_rx_queue_node(cursor);
									bool first_lss_segment = false;
									if(newrx_stream->lss & !tcb->lss_received[sid]){
										first_lss_segment = true;
										tcb->lss_received[sid] = true;
										stream_close_handler(tcb, sid);
									}

									if(!(tcb->lss_received[sid] && newrx_stream->lss && !first_lss_segment)){
										if((tcb->stream_rx_queue[sid] == NULL) != (tcb->stream_rx_queue_tail[sid] == NULL)){
											ERROR("invalid stream tail state (1)");
										}
										if(tcb->stream_rx_queue_tail[sid] == NULL){
											tcb->stream_rx_queue[sid] = tcb->stream_rx_queue_tail[sid] = newrx_stream;
										}else{
											struct stream_rx_queue_node* last = tcb->stream_rx_queue_tail[sid];
											last->next = newrx_stream;
											tcb->stream_rx_queue_tail[sid] = newrx_stream;
										}
									}else{
										//DEBUG("Discarding subsequent LSS");
									}

									
									
									update_next_ssn(&(tcb->next_rx_ssn[sid]));
									// advance to the next segment of this stream in the channel RX queue
									cursor = cursor->next;
									while(cursor != NULL){
										if(cursor->segment != NULL){
											int cursor_ms_index = search_tcp_option(cursor->segment, OPT_KIND_MS_TCP);
											if(cursor_ms_index>=0){
												int cursor_sid = (cursor->segment->payload[cursor_ms_index+2]>>2) & 0x1F;
												int cursor_ssn = ((cursor->segment->payload[cursor_ms_index+2]&0x3) << 8) | cursor->segment->payload[cursor_ms_index+3];
												if(cursor_sid == sid){
													current_candidate_ssn = cursor_ssn;
													break;
												}
											}
										}
										cursor = cursor->next;
									}
									// Now cursor is the next node in the channel RX queue referring to this stream, or NULL if there are no more segments for this stream
								}
							}
						}

						// Removal of in-order segments at the beginning of the channel RX queue
						while((tcb->unack != NULL) && (tcb->unack->channel_offset == tcb->cumulativeack)){
							
							in_order_for_channel = true; // I am removing something from the tx queue, so the incoming segment was in order for the channel

							if(tcb->ms_option_enabled){
								if(tcb->unack->segment != NULL){
									DEBUG("Last received packet before error:");
									print_l2_packet(l2_rx_buf);
									DEBUG("unack:");
									print_tcp_segment(tcb->unack->segment);
									DEBUG("unack channel_offset: %u", tcb->unack->channel_offset);
									DEBUG("unack payload length %d", tcb->unack->payload_length);
									DEBUG("next_rx_ssn %d received %d", tcb->next_rx_ssn[sid], ssn);
									ERROR("in-order segment not consumed from channel queue");
								}
							}else{
								// For non-MS connections, we can do here the insertion in the stream RX queue
								if(tcb->unack->segment == NULL){
									ERROR("There is no segment to place in the stream queue (non-MS)");
								}
								if(tcb->unack->dummy_payload){
									ERROR("received DMP segment on non-MS connection");
								}
								struct stream_rx_queue_node* newrx_stream = create_stream_rx_queue_node(tcb->unack); // tcb->unack->segment is set to NULL in the function

								if((tcb->stream_rx_queue[0] == NULL) != (tcb->stream_rx_queue_tail[0] == NULL)){
									ERROR("invalid stream tail state (2)");
								}
								if(tcb->stream_rx_queue[0] == NULL){
									tcb->stream_rx_queue[0] = tcb->stream_rx_queue_tail[0] = newrx_stream;
								}else{
									struct stream_rx_queue_node* last = tcb->stream_rx_queue_tail[0];
									last->next = newrx_stream;
									tcb->stream_rx_queue_tail[0] = newrx_stream;
								}
							}

							tcb->cumulativeack += tcb->unack->payload_length;
							if(!tcb->unack->dummy_payload){
								tcb->adwin[tcb->unack->sid] -= tcb->unack->payload_length;
							}

							if(tcb->unack->prev != NULL){
								// at the beginning of the RX queue, prev should always be NULL
								ERROR("unack.prev != NULL");
							}
							struct channel_rx_queue_node* next = tcb->unack->next;
							if(next != NULL){
								next->prev = NULL;
							}else{
								// We are deleting the last element in the unack queue: clear unack_tail accordingly
								tcb->unack_tail = NULL;
							}
							free(tcb->unack);
							tcb->unack = next;
						}
					}
				}

				if(!tcb->ms_option_enabled){
					//if(tcb->txfirst==NULL){
					
					// Generate an ACK without MS Option
					//prepare_tcp(i, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
					fast_send_tcp(i, ACK, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));

					//}
				}else{
					if(ms_option_included){
						//prepare_tcp(i, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
						if(!dummy_payload && in_order_for_channel){
							// Allocate a new SSN and send an ACK on the stream with the DMP flag

							int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
							uint8_t* opt = malloc(optlen);
							memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
							
							// Stream update
							opt[2] = sid<<2 | (tcb->next_ssn[sid] >> 8)&0x3;
							opt[3] = (tcb->next_ssn[sid])&0xFF;
							update_next_ssn(&(tcb->next_ssn[sid]));

							uint8_t* dummy_payload = malloc(1); // value doesn't matter

							prepare_tcp(i, ACK | DMP, dummy_payload, 1, opt, optlen);
							free(dummy_payload);
							free(opt);
						}
						else{
							// Generic ACK
							//ERROR("Inviare subito, non accodare!");
							//prepare_tcp(i, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
							fast_send_tcp(i, ACK, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
						}
					}else{
						DEBUG("Unexpected packet with payload but no MSTCP option:");
						print_l2_packet(l2_rx_buf);
						ERROR("Should we generate an ACK for this packet?");
					}
				}
			}

			// ts_recent update ( https://datatracker.ietf.org/doc/html/rfc7323#section-4.3 )
			uint32_t ts_index = search_tcp_option(tcp, OPT_KIND_TIMESTAMPS);
			uint32_t segment_ts_val = ntohl(*(uint32_t*) (tcp->payload+ts_index+2));
			uint32_t segment_seq = ntohl(tcp->seq);
			/*
			(2)	If:
					SEG.TSval >= TS.Recent and SEG.SEQ <= Last.ACK.sent
				then SEG.TSval is copied to TS.Recent; otherwise, it is ignored.
			*/
			if(		((segment_ts_val - tcb->ts_offset) >= (tcb->ts_recent - tcb->ts_offset)) 
					&& 
					((segment_seq - tcb->ack_offs) <= tcb->cumulativeack)
				){
				tcb->ts_recent = segment_ts_val;
			}

			scheduler(i);
		}



		clock_gettime(CLOCK_REALTIME, &end2);
		long duration_ns = (end2.tv_sec - start2.tv_sec) * 1000000000L + (end2.tv_nsec - start2.tv_nsec);
		long duration_us = duration_ns / 1000;
		//printf("pkt %ld us                                                \r", duration_us);
	}//packet reception while end

	assert_handler_lock_acquired("myio end");

	clock_gettime(CLOCK_REALTIME, &end);
	long duration_ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
	long duration_us = duration_ns / 1000;
	if(duration_us > TIMER_USECS){
		//DEBUG("myio %ld us", duration_us);
	}

	enable_signal_reception(true);
}
void mytimer(int ignored){
	disable_signal_reception(true);
	struct timespec start, end;
	clock_gettime(CLOCK_REALTIME, &start);

	tick++;

	for(int i=0;i<MAX_FD;i++){
		if(fdinfo[i].st != FDINFO_ST_TCB_CREATED){
			continue;
		}
		struct tcpctrlblk* tcb = fdinfo[i].tcb;
		if((tcb->fsm_timer!=0 ) && (tcb->fsm_timer < tick)){
			fsm(i, FSM_EVENT_TIMEOUT, NULL, NULL);
			continue;
		}
		if(fdinfo[i].sid != SID_UNASSIGNED && (tcb->stream_fsm_timer[fdinfo[i].sid] != 0) && (tcb->stream_fsm_timer[fdinfo[i].sid] <= tick)){
			/* Note: If for any reason the stream timeout is used for something different from the opening of streams without anything to transmit, you need to modify
			in prepare_tcp where the stream_fsm_timer is set to 0 if any segment is transmitted on the stream
			*/
			fsm(i, FSM_EVENT_STREAM_TIMEOUT, NULL, NULL);
			continue;
		}
		struct txcontrolbuf* txcb = tcb->txfirst;
		struct txcontrolbuf* prev = NULL;
		int acc = 0; // payload bytes accumulator
		while(txcb != NULL && (acc < tcb->cgwin+tcb->lta || txcb->payloadlen == 0 || txcb->dummy_payload)){
			// Karn invalidation not handled
			if(txcb->retry == 0){
				// This is the first TX attempt for a segment, and at this point I know that there is enough space in the cwnd to send it, so it will be sent
				if(!txcb->dummy_payload){
					tcb->flightsize += txcb->payloadlen;
				}
			} else if(txcb->txtime != 0 && txcb->txtime+tcb->timeout > tick){
				acc += txcb->payloadlen;
				txcb = txcb->next;
				continue;
			}
			if(txcb->retry > 0 && txcb->payloadlen == 0 && txcb->segment->flags == ACK){
				// If this is only an ACK without payload it does not need to be RETXed
				// we remove txcb from the TX queue
				free(txcb->segment);
				if(prev != NULL){
					prev->next = txcb->next;
				}else{
					tcb->txfirst = txcb->next;
				}
				if(tcb->txlast == txcb){
					tcb->txlast = prev;
				}
				free(txcb);
				txcb = prev != NULL? prev->next : tcb->txfirst;
				continue;
			}
			bool is_fast_transmit = (txcb->txtime == 0); // Fast retransmit (when dupACKs are received) is done by setting txtime=0
			txcb->txtime = tick;
			if(txcb->retry > 0 && !is_fast_transmit){
				//DEBUG("Segment RETX %d", txcb->retry);
				congctrl_fsm(tcb,FSM_EVENT_TIMEOUT,NULL,0);
				LOG_RTO(tcb->timeout);
			}
			txcb->retry++;

			update_tcp_header(i, txcb);
			send_ip((unsigned char*) txcb->segment, (unsigned char*) &(tcb->r_addr), txcb->totlen, TCP_PROTO);

			acc += txcb->payloadlen;
			prev = txcb;
			txcb = txcb->next;
		}
	}

	clock_gettime(CLOCK_REALTIME, &end);
	long duration_ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
	long duration_us = duration_ns / 1000;
	if(duration_us > TIMER_USECS){
		//DEBUG("mytimer %ld us", duration_us);
	}
	enable_signal_reception(true);
}


void* safe_malloc(size_t sz){
	disable_signal_reception(false);
	void* ret = malloc(sz);
	if(ret == NULL){
		perror("malloc");
		ERROR("safe_malloc %u failed", sz);
	}
	enable_signal_reception(false);
	return ret;
}

void safe_free(void* ptr){
	disable_signal_reception(false);
	if(ptr == NULL){
		ERROR("safe_free NULL param");
	}
	free(ptr);
	enable_signal_reception(false);
}

#if CL_MAIN == CL_MAIN_HTML
enum client_state{
	CLIENT_ST_IDLE = 0,
	CLIENT_ST_REQ,
	CLIENT_ST_RESP_H,
	CLIENT_ST_RESP_P,
	
};
int num_images;
char** img_list = NULL;
void parse_html(char* html, int length){
	num_images = 0;
	char* start_ptr = html;
	char* found;
	const char* const img_tag_seq = "<img ";
	const char* const img_src_seq = "src=";
	while((found = strcasestr(start_ptr, img_tag_seq)) != NULL){
		num_images++;
		start_ptr = found + strlen(img_tag_seq);
	}

	img_list = safe_malloc(num_images * sizeof(char*));

	start_ptr = html;
	int cur_img = 0;
	while((found = strcasestr(start_ptr, img_tag_seq)) != NULL){
		start_ptr = found + strlen(img_tag_seq);
		found = strcasestr(start_ptr, img_src_seq);
		found += strlen(img_src_seq);

		while((*found != '\"') && (*found != '\'')){
			found++;
		}
		found++; // skip first quote
		char* img_name_start = found;

		while((*found != '\"') && (*found != '\'')){
			found++;
		}
		char* img_name_end = found;

		int img_name_len = img_name_end - img_name_start;

		img_list[cur_img] = safe_malloc(img_name_len + 1);
		memcpy(img_list[cur_img], img_name_start, img_name_len);
		img_list[cur_img][img_name_len] = 0;

		cur_img ++;
	}
	
	if(cur_img != num_images){
		ERROR("cur_img %d != num_images %d", cur_img, num_images);
	}
}
void main_client_app(){
	myread_mode = MYREAD_MODE_BLOCKING;
	mywrite_mode = MYWRITE_MODE_BLOCKING;
	myconnect_mode = MYCONNECT_MODE_BLOCKING;

	int ret, s;

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(19500);
	addr.sin_addr.s_addr = inet_addr(SERVER_IP_STR);

	int64_t meas_start = get_timestamp_ms();

	s = mysocket(AF_INET,SOCK_STREAM,0);
	if(s == -1){
		myperror("mysocket");
		exit(EXIT_FAILURE);
	}

	ret = myconnect(s,(struct sockaddr * )&addr,sizeof(struct sockaddr_in));
	if(ret < 0){
		myperror("myconnect");
		exit(EXIT_FAILURE);
	}
	char* data = safe_malloc(RESP_BUF_SIZE); // both req and resp
	sprintf(data, "GET /index.html HTTP/1.1\r\nX-Client-ID: %d\r\nX-Req-Num: %d\r\n\r\n", 0, -1);
	int sent = 0, missing = strlen(data);
	while(missing > 0){
		ret = mywrite(s, data+sent, missing);
		if(ret < 0){
			myperror("mywrite");
			exit(EXIT_FAILURE);
		}
		sent += ret;
		missing -= ret;
	}
	memset(data, 0, RESP_BUF_SIZE);
	int recv_bytes = 0;
	int content_length = -1;
	int header_portion_length = -1;
	while(true){
		ret = myread(s, data+recv_bytes, (content_length < 0 ? RESP_BUF_SIZE : (header_portion_length+content_length)) - recv_bytes);
		if(ret < 0){
			myperror("myread");
			exit(EXIT_FAILURE);
		}
		if(ret == 0){
			myperror("unexpected read return 0");
			exit(EXIT_FAILURE);
		}
		recv_bytes += ret;
		if(content_length < 0){
			char* end_of_headers_substr = strstr(data, "\r\n\r\n");
			if(end_of_headers_substr != NULL){
				header_portion_length = (end_of_headers_substr + strlen("\r\n\r\n")) - data;
				content_length = RESP_PAYLOAD_BYTES;
				char* content_length_str = strcasestr(data, "Content-Length");
				if(content_length_str != NULL){
					while(*content_length_str != ':'){
						content_length_str++;
					}
					content_length_str++; // Skip ':
					while(*content_length_str == ' '){
						content_length_str++;
					}

					content_length = atoi(content_length_str);
				}
			}
		}

		if(content_length >= 0 && recv_bytes >= header_portion_length + content_length){
			data[recv_bytes] = 0;
			break;
		}
	}
	parse_html(data, content_length);
	safe_free(data);




	myread_mode = MYREAD_MODE_NON_BLOCKING;
	mywrite_mode = MYWRITE_MODE_NON_BLOCKING;
	myconnect_mode = MYCONNECT_MODE_NON_BLOCKING;


	int client_sockets[NUM_CLIENTS];
	int completed_requests[NUM_CLIENTS] = {0};
	int started_requests = 0;
	bool client_connected[NUM_CLIENTS] = {false};
	bool client_active[NUM_CLIENTS] = {false};
	enum client_state cl_st[NUM_CLIENTS];
	int current_request_number[NUM_CLIENTS];
	int cur_bytes[NUM_CLIENTS]; // both for write and for read
	char* client_buffer[NUM_CLIENTS];
	long ul_bytes[NUM_CLIENTS] = {0};
	long dl_bytes[NUM_CLIENTS] = {0};
	int response_tot_bytes[NUM_CLIENTS];
	
	client_sockets[0] = s;
	client_connected[0] = true;
	client_active[0] = true;
	cl_st[0] = CLIENT_ST_IDLE;
	client_buffer[0] = safe_malloc(RESP_BUF_SIZE);
	
	for(int i=1; i<NUM_CLIENTS; i++){
		s = mysocket(AF_INET,SOCK_STREAM,0);
		if(s == -1){
			myperror("mysocket");
			exit(EXIT_FAILURE);
		}
		client_sockets[i] = s;
	}

	while(true){

		// End main if all the clients are stopped
		bool all_stopped = true;
		for(int i=0; i<NUM_CLIENTS && all_stopped; i++){
			if(!client_connected[i] || client_active[i]){
				all_stopped = false;
			}
		}
		if(all_stopped){
			break;
		}
		
		// Attempt connection for all non-connected clients
		for(int i=0; i<NUM_CLIENTS; i++){
			if(client_connected[i]){
				continue;
			}
			if(started_requests >= num_images){
				client_connected[i] = true;
				client_active[i] = true;
				cl_st[i] = CLIENT_ST_IDLE;
				client_buffer[i] = safe_malloc(RESP_BUF_SIZE);
				continue;
			}
			ret = myconnect(client_sockets[i],(struct sockaddr * )&addr,sizeof(struct sockaddr_in));
			if(ret == -1 && myerrno == EAGAIN){
				myerrno = 0;
				continue;
			}
			if(ret < 0){
				myperror("myconnect");
				exit(EXIT_FAILURE);
			}
			DEBUG("connect %d", i);
			client_connected[i] = true;
			client_active[i] = true;
			cl_st[i] = CLIENT_ST_IDLE;
			client_buffer[i] = safe_malloc(RESP_BUF_SIZE);
		}

		uint32_t rand_i_base = sample_uint32() % NUM_CLIENTS;

		// Assign new requests to idle clients
		for(int i_offs=0; i_offs<NUM_CLIENTS && started_requests < num_images; i_offs++){
			int i = (rand_i_base + i_offs) % NUM_CLIENTS;
			if(client_active[i] && cl_st[i] == CLIENT_ST_IDLE){
				current_request_number[i] = started_requests;
				started_requests++;
				cl_st[i] = CLIENT_ST_REQ;
				cur_bytes[i] = 0;
			}
		}

		// Continue sending pending requests
		for(int i_offs=0; i_offs<NUM_CLIENTS; i_offs++){
			int i = (rand_i_base + i_offs) % NUM_CLIENTS;
			if(client_active[i] && cl_st[i] == CLIENT_ST_REQ){
				sprintf(client_buffer[i], "GET /%s HTTP/1.1\r\nX-Client-ID: %d\r\nX-Req-Num: %d\r\n\r\n", img_list[current_request_number[i]], i, current_request_number[i]);
				uint8_t* start = client_buffer[i]+cur_bytes[i];
				int missing = strlen(client_buffer[i]) - cur_bytes[i];
				int res = mywrite(client_sockets[i], start, missing);
				if(res < 0){
					if(myerrno == EAGAIN){
						myerrno = 0;
						return;
					}else{
						myperror("mywrite");
						ERROR("mywrite error");
					}
				}
				cur_bytes[i] += res;
				ul_bytes[i] += res;
				if(cur_bytes[i] == strlen(client_buffer[i])){
					cl_st[i] = CLIENT_ST_RESP_H;
					cur_bytes[i] = 0;
					// ...
				}
			}
		}

		// Read HTTP Headers
		for(int i_offs=0; i_offs<NUM_CLIENTS; i_offs++){
			int i = (rand_i_base + i_offs) % NUM_CLIENTS;
			if(client_active[i] && cl_st[i] == CLIENT_ST_RESP_H){
				ret = myread(client_sockets[i], client_buffer[i]+cur_bytes[i], RESP_BUF_SIZE);
				if(ret == -1 && myerrno == EAGAIN){
					myerrno = 0;
					continue;
				}
				cur_bytes[i] += ret;
				dl_bytes[i] += ret;
				client_buffer[i][cur_bytes[i]] = '\0';

				char* end_of_headers_substr = strstr(client_buffer[i], "\r\n\r\n"); 
				if(end_of_headers_substr != NULL){
					int header_portion_length = (end_of_headers_substr + strlen("\r\n\r\n")) - client_buffer[i];

					int content_length = RESP_PAYLOAD_BYTES; // Assume the expected payload length by default

					char* content_length_str = strcasestr(client_buffer[i], "Content-Length");
					if(content_length_str != NULL){
						while(*content_length_str != ':'){
							content_length_str++;
						}
						content_length_str++; // Skip ':
						while(*content_length_str == ' '){
							content_length_str++;
						}

						content_length = atoi(content_length_str);
					}
					response_tot_bytes[i] = header_portion_length + content_length;
					cl_st[i] = CLIENT_ST_RESP_P;
				}
			}
		}

		// Read HTTP Payload
		for(int i_offs=0; i_offs<NUM_CLIENTS; i_offs++){
			int i = (rand_i_base + i_offs) % NUM_CLIENTS;
			if(client_active[i] && cl_st[i] == CLIENT_ST_RESP_P){
				int missing =  response_tot_bytes[i] - cur_bytes[i];
				if(missing == 0){
					goto after_read;
				}
				if(missing < 0){
					ERROR(".");
				}
				ret = myread(client_sockets[i], client_buffer[i]+cur_bytes[i], missing);
				if(ret == -1 && myerrno == EAGAIN){
					myerrno = 0;
					continue;
				}
				cur_bytes[i] += ret;
				dl_bytes[i] += ret;

				after_read:
				if(cur_bytes[i] == response_tot_bytes[i]){
					//client_buffer[i][cur_bytes[i]] = 0;
					//DEBUG(client_buffer[i]);
					cur_bytes[i] = 0;
					cl_st[i] = CLIENT_ST_IDLE;
					completed_requests[i]++;
				}
			}
		}




		// Close all idle clients if there are no more requests to do
		if(started_requests >= num_images){
			for(int i=0; i<NUM_CLIENTS; i++){
				if(client_active[i] && cl_st[i] == CLIENT_ST_IDLE){
					myclose(client_sockets[i]);
					client_active[i] = false;
					safe_free(client_buffer[i]);
					DEBUG("close %d", i);
				}
			}
		}
	}

	int64_t meas_end = get_timestamp_ms();
	int64_t meas_dur = meas_end - meas_start;

	DEBUG("all requests completed :)");
	DEBUG("%"PRId64" ms", meas_dur);
	DEBUG("wait...");
	persistent_nanosleep(2, 0);
	DEBUG("main_client_app end");
}
#endif

#if CL_MAIN == CL_MAIN_AGGREGATE
enum client_state{
	CLIENT_ST_IDLE = 0,
	CLIENT_ST_REQ,
	CLIENT_ST_RESP_H,
	CLIENT_ST_RESP_P,
	
};
void main_client_app(){
	myread_mode = MYREAD_MODE_BLOCKING;
	mywrite_mode = MYWRITE_MODE_BLOCKING;
	myconnect_mode = MYCONNECT_MODE_BLOCKING;

	int ret, s;

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(19500);
	addr.sin_addr.s_addr = inet_addr(SERVER_IP_STR);

	int64_t meas_start = get_timestamp_ms();

	s = mysocket(AF_INET,SOCK_STREAM,0);
	if(s == -1){
		myperror("mysocket");
		exit(EXIT_FAILURE);
	}

	ret = myconnect(s,(struct sockaddr * )&addr,sizeof(struct sockaddr_in));
	if(ret < 0){
		myperror("myconnect");
		exit(EXIT_FAILURE);
	}
	char* data = safe_malloc(RESP_BUF_SIZE); // both req and resp
	sprintf(data, "GET /%d HTTP/1.1\r\nX-Client-ID: %d\r\nX-Req-Num: %d\r\n\r\n", RESP_PAYLOAD_BYTES, 0, -1);
	int sent = 0, missing = strlen(data);
	while(missing > 0){
		ret = mywrite(s, data+sent, missing);
		if(ret < 0){
			myperror("mywrite");
			exit(EXIT_FAILURE);
		}
		sent += ret;
		missing -= ret;
	}
	memset(data, 0, RESP_BUF_SIZE);
	int recv_bytes = 0;
	int content_length = -1;
	int header_portion_length = -1;
	while(true){
		ret = myread(s, data+recv_bytes, (content_length < 0 ? RESP_BUF_SIZE : (header_portion_length+content_length)) - recv_bytes);
		if(ret < 0){
			myperror("myread");
			exit(EXIT_FAILURE);
		}
		if(ret == 0){
			myperror("unexpected read return 0");
			exit(EXIT_FAILURE);
		}
		recv_bytes += ret;
		if(content_length < 0){
			char* end_of_headers_substr = strstr(data, "\r\n\r\n");
			if(end_of_headers_substr != NULL){
				header_portion_length = (end_of_headers_substr + strlen("\r\n\r\n")) - data;
				content_length = RESP_PAYLOAD_BYTES;
				char* content_length_str = strcasestr(data, "Content-Length");
				if(content_length_str != NULL){
					while(*content_length_str != ':'){
						content_length_str++;
					}
					content_length_str++; // Skip ':
					while(*content_length_str == ' '){
						content_length_str++;
					}

					content_length = atoi(content_length_str);
				}
			}
		}

		if(content_length >= 0 && recv_bytes >= header_portion_length + content_length){
			//data[recv_bytes] = 0;
			//DEBUG(data);
			break;
		}
		//nanosleep(&short_sleep, NULL); 
	}
	safe_free(data);


	int test_num_bytes = payload_size_arr[sample_uint32() % (sizeof(payload_size_arr)/sizeof(payload_size_arr[0]))];
	int num_clients_test = num_clients_arr[sample_uint32() % (sizeof(num_clients_arr)/sizeof(num_clients_arr[0]))];

	bool app_delay[NUM_CLIENT_REQUESTS_MAX];
	for(int i=0; i<NUM_CLIENT_REQUESTS_MAX; i++){
		app_delay[i] = false;
	}
	
	#ifdef DELAY_REQ_PROB
	int delayed = 0;
	uint32_t old_prng_state = prng_state;
	prng_state = 1234;
	while(delayed < NUM_CLIENT_REQUESTS_MAX * DELAY_REQ_PROB){
		// rejection sampling
		int sampled_pos = sample_uint32() % NUM_CLIENT_REQUESTS_MAX;
		if(app_delay[sampled_pos]){
			continue;
		}
		app_delay[sampled_pos] = true;
		delayed++;
	}
	prng_state = old_prng_state;
	#endif


	if(!MS_ENABLED && num_clients_test > 6){
		num_clients_test = 6;
	}
	
	//DEBUG("Starting the measurement");
	



	myread_mode = MYREAD_MODE_NON_BLOCKING;
	mywrite_mode = MYWRITE_MODE_NON_BLOCKING;
	myconnect_mode = MYCONNECT_MODE_NON_BLOCKING;


	int client_sockets[NUM_CLIENTS_MAX];
	int completed_requests[NUM_CLIENTS_MAX] = {0};
	int started_requests = 0;
	bool client_connected[NUM_CLIENTS_MAX] = {false};
	bool client_active[NUM_CLIENTS_MAX] = {false};
	enum client_state cl_st[NUM_CLIENTS_MAX];
	int current_request_number[NUM_CLIENTS_MAX];
	int cur_bytes[NUM_CLIENTS_MAX]; // both for write and for read
	char* client_buffer[NUM_CLIENTS_MAX];
	long ul_bytes[NUM_CLIENTS_MAX] = {0};
	long dl_bytes[NUM_CLIENTS_MAX] = {0};
	int response_tot_bytes[NUM_CLIENTS_MAX];
	
	client_sockets[0] = s;
	client_connected[0] = true;
	client_active[0] = true;
	cl_st[0] = CLIENT_ST_IDLE;
	client_buffer[0] = safe_malloc(RESP_BUF_SIZE);
	
	for(int i=1; i<num_clients_test; i++){
		s = mysocket(AF_INET,SOCK_STREAM,0);
		if(s == -1){
			myperror("mysocket");
			exit(EXIT_FAILURE);
		}
		client_sockets[i] = s;
	}

	while(true){

		// End main if all the clients are stopped
		bool all_stopped = true;
		for(int i=0; i<num_clients_test && all_stopped; i++){
			if(!client_connected[i] || client_active[i]){
				all_stopped = false;
			}
		}
		if(all_stopped){
			break;
		}
		
		// Attempt connection for all non-connected clients
		for(int i=0; i<num_clients_test; i++){
			if(client_connected[i]){
				continue;
			}
			if(started_requests >= num_client_requests_test){
				client_connected[i] = true;
				client_active[i] = true;
				cl_st[i] = CLIENT_ST_IDLE;
				client_buffer[i] = safe_malloc(RESP_BUF_SIZE);
				continue;
			}
			ret = myconnect(client_sockets[i],(struct sockaddr * )&addr,sizeof(struct sockaddr_in));
			if(ret == -1 && myerrno == EAGAIN){
				myerrno = 0;
				continue;
			}
			if(ret < 0){
				myperror("myconnect");
				exit(EXIT_FAILURE);
			}
			client_connected[i] = true;
			client_active[i] = true;
			cl_st[i] = CLIENT_ST_IDLE;
			client_buffer[i] = safe_malloc(RESP_BUF_SIZE);
		}

		uint32_t rand_i_base = sample_uint32() % num_clients_test;

		// Assign new requests to idle clients
		for(int i_offs=0; i_offs<num_clients_test && started_requests < num_client_requests_test; i_offs++){
			int i = (rand_i_base + i_offs) % num_clients_test;
			if(client_active[i] && cl_st[i] == CLIENT_ST_IDLE){
				current_request_number[i] = started_requests;
				started_requests++;
				cl_st[i] = CLIENT_ST_REQ;
				cur_bytes[i] = 0;
			}
		}

		// Continue sending pending requests
		for(int i_offs=0; i_offs<num_clients_test; i_offs++){
			int i = (rand_i_base + i_offs) % num_clients_test;
			if(client_active[i] && cl_st[i] == CLIENT_ST_REQ){
				#ifdef DELAY_REQ_PROB
				double sample = sample_uniform_0_1();
				sprintf(client_buffer[i], "GET /%d HTTP/1.1\r\nX-Client-ID: %d\r\nX-Req-Num: %d\r\nX-Delay: %d\r\n\r\n", test_num_bytes, i, current_request_number[i], app_delay[current_request_number[i]]);
				#else
				sprintf(client_buffer[i], "GET /%d HTTP/1.1\r\nX-Client-ID: %d\r\nX-Req-Num: %d\r\n\r\n", test_num_bytes, i, current_request_number[i]);
				#endif
				
				uint8_t* start = client_buffer[i]+cur_bytes[i];
				int missing = strlen(client_buffer[i]) - cur_bytes[i];
				int res = mywrite(client_sockets[i], start, missing);
				if(res < 0){
					if(myerrno == EAGAIN){
						myerrno = 0;
						return;
					}else{
						myperror("mywrite");
						ERROR("mywrite error");
					}
				}
				cur_bytes[i] += res;
				ul_bytes[i] += res;
				if(cur_bytes[i] == strlen(client_buffer[i])){
					cl_st[i] = CLIENT_ST_RESP_H;
					cur_bytes[i] = 0;
					// ...
				}
			}
		}

		// Read HTTP Headers
		for(int i_offs=0; i_offs<num_clients_test; i_offs++){
			int i = (rand_i_base + i_offs) % num_clients_test;
			if(client_active[i] && cl_st[i] == CLIENT_ST_RESP_H){
				ret = myread(client_sockets[i], client_buffer[i]+cur_bytes[i], RESP_BUF_SIZE);
				if(ret == -1 && myerrno == EAGAIN){
					myerrno = 0;
					continue;
				}
				cur_bytes[i] += ret;
				dl_bytes[i] += ret;
				client_buffer[i][cur_bytes[i]] = '\0';

				char* end_of_headers_substr = strstr(client_buffer[i], "\r\n\r\n"); 
				if(end_of_headers_substr != NULL){
					int header_portion_length = (end_of_headers_substr + strlen("\r\n\r\n")) - client_buffer[i];

					int content_length = RESP_PAYLOAD_BYTES; // Assume the expected payload length by default

					char* content_length_str = strcasestr(client_buffer[i], "Content-Length");
					if(content_length_str != NULL){
						while(*content_length_str != ':'){
							content_length_str++;
						}
						content_length_str++; // Skip ':
						while(*content_length_str == ' '){
							content_length_str++;
						}

						content_length = atoi(content_length_str);
					}
					response_tot_bytes[i] = header_portion_length + content_length;
					cl_st[i] = CLIENT_ST_RESP_P;
				}
			}
		}

		// Read HTTP Payload
		for(int i_offs=0; i_offs<num_clients_test; i_offs++){
			int i = (rand_i_base + i_offs) % num_clients_test;
			if(client_active[i] && cl_st[i] == CLIENT_ST_RESP_P){
				int missing =  response_tot_bytes[i] - cur_bytes[i];
				if(missing == 0){
					goto after_read;
				}
				if(missing < 0){
					ERROR(".");
				}
				ret = myread(client_sockets[i], client_buffer[i]+cur_bytes[i], missing);
				if(ret == -1 && myerrno == EAGAIN){
					myerrno = 0;
					continue;
				}
				cur_bytes[i] += ret;
				dl_bytes[i] += ret;

				after_read:
				if(cur_bytes[i] == response_tot_bytes[i]){
					//client_buffer[i][cur_bytes[i]] = 0;
					//DEBUG(client_buffer[i]);
					cur_bytes[i] = 0;
					cl_st[i] = CLIENT_ST_IDLE;
					completed_requests[i]++;
				}
			}
		}




		// Close all idle clients if there are no more requests to do
		if(started_requests >= num_client_requests_test){
			for(int i=0; i<num_clients_test; i++){
				if(client_active[i] && cl_st[i] == CLIENT_ST_IDLE){
					myclose(client_sockets[i]);
					client_active[i] = false;
					safe_free(client_buffer[i]);
				}
			}
		}
		//nanosleep(&short_sleep, NULL);
	}
	int64_t meas_end = get_timestamp_ms();
	int64_t meas_dur = meas_end - meas_start;

	
	DEBUG("all requests completed :)");
	DEBUG("########################### Statitics ###########################");
	long ul_sum = 0, dl_sum = 0;
	for(int i=0; i<num_clients_test; i++){
		ul_sum += ul_bytes[i];
		dl_sum += dl_bytes[i];
		DEBUG("Client %d: %d requests (ul %ld dl %ld)", i, completed_requests[i], ul_bytes[i], dl_bytes[i]);
	}
	DEBUG("Total: %.2f KB/s DL %.2f KB/s UL (%"PRId64" ms, %.2f s)", ((double)dl_sum) / meas_dur, ((double)ul_sum) / meas_dur, meas_dur, ((double)(meas_dur)/1000));
	DEBUG("#################################################################");
	//DEBUG("wait...");
	//persistent_nanosleep(2, 0);
	DEBUG("main_client_app end");
	

	/*
	long ul_sum = 0, dl_sum = 0;
	for(int i=0; i<num_clients_test; i++){
		ul_sum += ul_bytes[i];
		dl_sum += dl_bytes[i];
	}
	printf("%d;%d;%d;%d;%"PRId64";%ld;%ld\n", MS_ENABLED?1:0,num_clients_test, num_client_requests_test, test_num_bytes, meas_dur, dl_sum, ul_sum);
	*/
}
#endif

#if CL_MAIN == CL_MAIN_SERIAL_BLOCKING
char data[RESP_BUF_SIZE]; // both req and resp
void main_client_app(){
	myread_mode = MYREAD_MODE_BLOCKING;
	mywrite_mode = MYWRITE_MODE_BLOCKING;
	myconnect_mode = MYCONNECT_MODE_BLOCKING;

	int test_num_requests = num_req_arr[sample_uint32() % (sizeof(num_req_arr)/sizeof(num_req_arr[0]))];
	int test_num_bytes = payload_size_arr[sample_uint32() % (sizeof(payload_size_arr)/sizeof(payload_size_arr[0]))];
	//DEBUG("%d %d", test_num_requests, test_num_bytes);

	long ul_sum = 0, dl_sum = 0;
	//DEBUG("Starting the measurement");
	int64_t meas_start = get_timestamp_ms();


	for(int num_req = 0; num_req < test_num_requests; num_req++){
		int ret;
		int s = mysocket(AF_INET,SOCK_STREAM,0);
		if(s == -1){
			myperror("mysocket");
			exit(EXIT_FAILURE);
		}
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(19500);
		addr.sin_addr.s_addr = inet_addr(SERVER_IP_STR);
		ret = myconnect(s,(struct sockaddr * )&addr,sizeof(struct sockaddr_in));
		if(ret < 0){
			myperror("myconnect");
			exit(EXIT_FAILURE);
		}
		int expected_payload_bytes = test_num_bytes;
		//char data[RESP_BUF_SIZE]; // both req and resp
		sprintf(data, "GET /%d HTTP/1.1\r\nX-Client-ID: %d\r\nX-Req-Num: %d\r\n\r\n", expected_payload_bytes, num_req, num_req);
		int sent = 0, missing = strlen(data);
		while(missing > 0){
			ret = mywrite(s, data+sent, missing);
			if(ret < 0){
				myperror("mywrite");
				exit(EXIT_FAILURE);
			}
			sent += ret;
			missing -= ret;

			ul_sum += ret;
		}

		memset(data, 0, sizeof(data));
		int recv_bytes = 0;
		int content_length = -1;
		int header_portion_length = -1;
		while(true){
			ret = myread(s, data+recv_bytes, (content_length < 0 ? sizeof(data) : (header_portion_length+content_length)) - recv_bytes);
			if(ret < 0){
				myperror("myread");
				exit(EXIT_FAILURE);
			}
			if(ret == 0){
				myperror("unexpected read return 0");
				exit(EXIT_FAILURE);
			}
			recv_bytes += ret;
			dl_sum += ret;
			if(content_length < 0){
				char* end_of_headers_substr = strstr(data, "\r\n\r\n");
				if(end_of_headers_substr != NULL){
					header_portion_length = (end_of_headers_substr + strlen("\r\n\r\n")) - data;
					content_length = expected_payload_bytes;
					char* content_length_str = strcasestr(data, "Content-Length");
					if(content_length_str != NULL){
						while(*content_length_str != ':'){
							content_length_str++;
						}
						content_length_str++; // Skip ':
						while(*content_length_str == ' '){
							content_length_str++;
						}

						content_length = atoi(content_length_str);
					}
				}
			}

			if(content_length >= 0 && recv_bytes >= header_portion_length + content_length){
				myclose(s);
				break;
			}
		}
		//if(num_req == 0 || num_req % 2){
			int64_t meas_end = get_timestamp_ms();
			int64_t meas_dur = meas_end - meas_start;
			printf("%d;%d;%d;%"PRId64";%ld;%ld;%ld\n", MS_ENABLED?1:0,num_req+1, test_num_bytes, meas_dur, dl_sum, ul_sum, hs_time_tot);
		//}
	}
	#if 0
	int64_t meas_end = get_timestamp_ms();
	int64_t meas_dur = meas_end - meas_start;


	/*
	DEBUG("all requests completed :)");
	DEBUG("########################### Statitics ###########################");
	DEBUG("Total: %.2f KB/s DL %.2f KB/s UL (%"PRId64" ms, %.2f s)", ((double)dl_sum) / meas_dur, ((double)ul_sum) / meas_dur, meas_dur, ((double)(meas_dur)/1000));
	DEBUG("#################################################################");
	DEBUG("wait...");
	*/
	
	printf("%d;%d;%d;%"PRId64";%ld;%ld;%ld\n", MS_ENABLED?1:0,test_num_requests, test_num_bytes, meas_dur, dl_sum, ul_sum, hs_time_tot);
	//persistent_nanosleep(2, 0);
	//DEBUG("main_client_app end");
	#endif
}
#endif

#if CL_MAIN == CL_MAIN_PARALLEL
enum client_state{
	CLIENT_ST_REQ = 0,
	CLIENT_ST_RESP_H,
	CLIENT_ST_RESP_P,
	CLIENT_ST_STOPPED
};

enum client_state cl_st[NUM_CLIENTS];
int current_req_num[NUM_CLIENTS];
int current_req_bytes[NUM_CLIENTS];
char resp_arr[NUM_CLIENTS][RESP_BUF_SIZE];
int resp_tot_bytes[NUM_CLIENTS];
int resp_recv_bytes[NUM_CLIENTS];


void single_client_app(int* client_sockets, int i /* num_client */){
	if(cl_st[i] == CLIENT_ST_REQ){
		uint8_t data[REQ_BUF_SIZE];
		sprintf(data, "GET /%d HTTP/1.1\r\nX-Client-ID: %d\r\nX-Req-Num: %d\r\n\r\n", RESP_PAYLOAD_BYTES, i, current_req_num[i]);
		uint8_t* start = data+current_req_bytes[i];
		int missing = strlen(data) - current_req_bytes[i];
		int res = mywrite(client_sockets[i], start, missing);
		if(res < 0){
			if(myerrno == EAGAIN){
				myerrno = 0;
				return;
			}else{
				myperror("mywrite");
				ERROR("mywrite error");
			}
		}
		current_req_bytes[i] += res;
		if(current_req_bytes[i] == strlen(data)){
			cl_st[i] = CLIENT_ST_RESP_H;
			memset(resp_arr[i], 0, sizeof(resp_arr[i]));
		}
	}else if(cl_st[i] == CLIENT_ST_RESP_H){
		int n = myread(client_sockets[i], resp_arr[i]+resp_recv_bytes[i], sizeof(resp_arr[i]));
		if(n == -1 && myerrno == EAGAIN){
			myerrno = 0;
			return;
		}
		resp_recv_bytes[i]+=n;
		resp_arr[i][resp_recv_bytes[i]] = '\0';

		char* end_of_headers_substr = strstr(resp_arr[i], "\r\n\r\n"); 
		if(end_of_headers_substr != NULL){
			int header_portion_length = (end_of_headers_substr + strlen("\r\n\r\n")) - resp_arr[i];

			int content_length = RESP_PAYLOAD_BYTES; // Assume the expected payload length by default

			char* content_length_str = strcasestr(resp_arr[i], "Content-Length");
			if(content_length_str != NULL){
				while(*content_length_str != ':'){
					content_length_str++;
				}
				content_length_str++; // Skip ':
				while(*content_length_str == ' '){
					content_length_str++;
				}

				content_length = atoi(content_length_str);
			}
			resp_tot_bytes[i] = header_portion_length + content_length;
			cl_st[i] = CLIENT_ST_RESP_P;
		}
	}else if(cl_st[i] == CLIENT_ST_RESP_P){
		int missing =  resp_tot_bytes[i] - resp_recv_bytes[i];
		if(missing == 0){
			goto after_read;
		}
		if(missing < 0){
			ERROR(".");
		}
		int n = myread(client_sockets[i], resp_arr[i]+resp_recv_bytes[i], missing);
		if(n == -1 && myerrno == EAGAIN){
			myerrno = 0;
			return;
		}
		resp_recv_bytes[i]+=n;

		after_read:
		if(resp_recv_bytes[i] == resp_tot_bytes[i]){
			//resp_arr[i][resp_recv_bytes[i]] = 0;
			//DEBUG(resp_arr[i]);
			resp_recv_bytes[i] = 0;
			resp_tot_bytes[i] = 0;
			current_req_bytes[i] = 0;
			memset(resp_arr[i], 0, sizeof(resp_arr[i]));
			current_req_num[i]++;
			if(current_req_num[i] < NUM_CLIENT_REQUESTS){
				cl_st[i] = CLIENT_ST_REQ;
			}else{
				myclose(client_sockets[i]);
				cl_st[i] = CLIENT_ST_STOPPED;
			}
		}
	}
}

void main_client_app(){
	int client_sockets[NUM_CLIENTS];
	// Client code to connect to a server
	int s = mysocket(AF_INET,SOCK_STREAM,0);
	if(s == -1){
		myperror("mysocket");
		exit(EXIT_FAILURE);
	}
	DEBUG("mysocket OK");
	client_sockets[0] = s;
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(19500);
	addr.sin_addr.s_addr = inet_addr(SERVER_IP_STR);
	DEBUG("myconnect blk %d (fd %d)", 0, s);
	while(true){
		
		int ret = myconnect(s,(struct sockaddr * )&addr,sizeof(struct sockaddr_in));
		if(ret == -1 && myerrno == EAGAIN){
			continue;
		}
		if(ret < 0){
			myperror("myconnect");
			exit(EXIT_FAILURE);
		}
		break;
	}
	DEBUG("myconnect OK");
	persistent_nanosleep(1,0);
	for(int i=1; i<NUM_CLIENTS; i++){
		int s_loop = mysocket(AF_INET,SOCK_STREAM,0);
		if(s_loop == -1){
			myperror("mysocket");
			exit(EXIT_FAILURE);
		}
		DEBUG("myconnect non-blk %d (fd %d)", i, s_loop);
		int ret = myconnect(s,(struct sockaddr * )&addr,sizeof(struct sockaddr_in));
		if(ret == -1 && myerrno == EAGAIN){
			continue;
		}
		if(ret < 0){
			myperror("myconnect loop");
			exit(EXIT_FAILURE);
		}
		DEBUG("myconnect OK");
		client_sockets[i] = s_loop;
	}
	while(true){
		for(int i=0; i<NUM_CLIENTS; i++){
			single_client_app(client_sockets, i);
		}
		bool all_stopped = true;
		for(int i=0; i<NUM_CLIENTS; i++){
			if(cl_st[i] != CLIENT_ST_STOPPED){
				all_stopped = false;
				break;
			}
		}
		if(all_stopped){
			break;
		}
	}
	DEBUG("CLIENT - ALL STOPPED");
	DEBUG("wait...");
	persistent_nanosleep(2, 0);
	DEBUG("main_client_app end");
}
#endif

enum server_state{
	SERVER_ST_REQ = 0,
	SERVER_ST_RESP,
	SERVER_ST_STOPPED,
};

struct single_srv_data{
	int s;
	enum server_state srv_st;
	char req_arr[REQ_BUF_SIZE];
	int requested_payload_bytes;
	int current_resp_bytes;
	int64_t delay_timer;
	FILE* fp;
};
uint8_t srv_data[RESP_BUF_SIZE];
void full_duplex_server_app(int listening_socket){
	struct single_srv_data* clients = NULL;
	int num_clients = 0;
	while(true){

		struct sockaddr_in remote_addr;
		remote_addr.sin_family=AF_INET;
		int len = sizeof(struct sockaddr_in);
		int new_client_socket = myaccept(listening_socket, (struct sockaddr*) &remote_addr, &len);
		if(new_client_socket >= 0){
			//DEBUG("myaccept client %d", num_clients);
			struct single_srv_data* new_arr = safe_malloc(sizeof(struct single_srv_data)*(num_clients+1));
			if((num_clients == 0) != (clients == NULL)){
				ERROR("full_duplex_server_app invalid state num_clients client_sockets");
			}
			if(clients != NULL){
				memcpy(new_arr, clients, sizeof(struct single_srv_data)*num_clients);
				safe_free(clients);
			}
			clients = new_arr;
			memset(&clients[num_clients], 0, sizeof(clients[num_clients]));
			clients[num_clients].s = new_client_socket;
			num_clients++;
		}

		for(int i=0; i<num_clients; i++){
			if(clients[i].srv_st == SERVER_ST_REQ){
				char* strend = clients[i].req_arr;
				while(*strend){
					strend++;
				}
				int n = myread(clients[i].s, strend, sizeof(clients[i].req_arr));
				if(n == -1 && myerrno == EAGAIN){
					myerrno = 0;
					goto single_app_return;
				}
				if(n == 0){
					//DEBUG("received close from client %d", i);
					myclose(clients[i].s);
					clients[i].srv_st = SERVER_ST_STOPPED;
					goto single_app_return;
				}
				strend += n;
				*strend= '\0';
				char* end_of_headers_substr = strstr(clients[i].req_arr, "\r\n\r\n"); 
				if(end_of_headers_substr != NULL){
					DEBUG(clients[i].req_arr);

					char* requested_ptr = strstr(clients[i].req_arr, "/")+1;
					char* str_end = requested_ptr;
					bool all_digits = true;
					while(*str_end != ' ' && *str_end != '?' && *str_end != '\r' && *str_end != '\n'){
						if(*str_end < '0' || *str_end > '9'){
							all_digits = false;
						}
						str_end++;
					}

					if(all_digits){
						clients[i].requested_payload_bytes = atoi(strstr(clients[i].req_arr, "/")+1);
						clients[i].fp = NULL;
					}else{
						*str_end = 0;
						char file_path[50];
						sprintf(file_path, "website_folder/%s", (str_end != requested_ptr) ? requested_ptr : "index.html");

						clients[i].requested_payload_bytes = 0;

						clients[i].fp = fopen(file_path, "r");
						if(clients[i].fp != NULL){
							disable_signal_reception(false);
							fseek(clients[i].fp, 0, SEEK_END); // seek to end of file
							enable_signal_reception(false);
							clients[i].requested_payload_bytes = (int) ftell(clients[i].fp); // get current file pointer
						}
					}

					char* delay_header = strcasestr(clients[i].req_arr, "X-Delay: ");
					if(delay_header != NULL){
						char* delay_payload = delay_header + strlen("X-Delay: ");
						if(*delay_payload == '1'){
							clients[i].delay_timer = get_timestamp_ms() + DELAY_DURATION_MS;
						}
					}

					clients[i].current_resp_bytes = 0;
					clients[i].srv_st = SERVER_ST_RESP;
				}
			}else if(clients[i].srv_st == SERVER_ST_RESP){
				if(clients[i].delay_timer != 0 && get_timestamp_ms() < clients[i].delay_timer){
					// Timer not elapsed
					goto single_app_return;
				}
				sprintf(srv_data, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Server-ID: %d\r\n\r\n", clients[i].requested_payload_bytes, i);
				int end_index = strlen(srv_data);
				uint8_t* start;
				int missing;
				if(clients[i].fp == NULL){
					for(int j=0; j<clients[i].requested_payload_bytes; j++){
						srv_data[end_index + j] = 'X';
					}
					srv_data[end_index + clients[i].requested_payload_bytes] = 0;
					start = srv_data+clients[i].current_resp_bytes;
					missing = strlen(srv_data) - clients[i].current_resp_bytes;
				}else{
					if(clients[i].current_resp_bytes < end_index){
						// Read the whole file from the beginning
						disable_signal_reception(false);
						fseek(clients[i].fp, 0, SEEK_SET); // seek back to beginning of file
						enable_signal_reception(false);
						int res = fread(srv_data+end_index, clients[i].requested_payload_bytes, 1, clients[i].fp);
						if(res < 0){
							perror("fread");
							ERROR("fread if");
						}
						start = srv_data;
						missing = end_index + res;
					}else{
						int start_position = clients[i].current_resp_bytes - end_index; // How many bytes we already have sent through mywrite
						disable_signal_reception(false);
						fseek(clients[i].fp, start_position, SEEK_SET); // seek to the first byte that was not sent through mywrite
						enable_signal_reception(false);
						int missing_from_file = clients[i].requested_payload_bytes - start_position;
						int res = fread(srv_data, missing_from_file, 1, clients[i].fp);
						if(res < 0){
							perror("fread");
							ERROR("fread else");
						}
						start = srv_data;
						missing = res;
					}
				}
				int res = mywrite(clients[i].s, start, missing);
				if(res < 0){
					if(myerrno == EAGAIN){
						myerrno = 0;
						goto single_app_return;
					}else{
						myperror("mywrite");
						ERROR("mywrite error");
					}
				}
				clients[i].current_resp_bytes += res;
				if(clients[i].current_resp_bytes == end_index + clients[i].requested_payload_bytes){
					clients[i].srv_st = SERVER_ST_REQ;
					memset(clients[i].req_arr, 0, sizeof(clients[i].req_arr));
					clients[i].delay_timer = 0;

					if(clients[i].fp != NULL){
						fclose(clients[i].fp);
						clients[i].fp = NULL;
					}
				}
			}
			single_app_return:
			;
		}

		// Stopped cleanup
		int cur = 0;
		while(cur < num_clients){
			if(clients[cur].srv_st == SERVER_ST_STOPPED){
				// copy clients from cur+1 to num_clients-1 (included), so num_clients-cur-1 in total
				for(int cur2 = cur+1; cur2 < num_clients; cur2++){
					clients[cur2-1] = clients[cur2];
				}
				DEBUG("num_clients=%d", num_clients);
				num_clients--;
				if(num_clients == 0){
					clients = NULL;
				}else{
					clients = realloc(clients, sizeof(struct single_srv_data)*num_clients);
				}
			}else{
				cur++;
			}
		}
		//nanosleep(&short_sleep, NULL); 
	}
	DEBUG("SERVER - ALL STOPPED");
	DEBUG("wait...");
	persistent_nanosleep(2, 0);
	DEBUG("full_duplex_server_app end");
}

int main(){
	// https://chatgpt.com/share/6831f26e-d848-8007-9105-69f30fe620ff
	if (setvbuf(stdout, NULL, _IONBF, 0) != 0) {
		perror("Failed to set stdout to unbuffered");
		exit(EXIT_FAILURE);
	}

	LOG_START();
	// Register cleanup function for normal program termination
    // This handles exit() and normal return from main()
    atexit(LOG_END);
    
    // Register signal handlers for interrupts
    signal(SIGINT, exit_handler);   // Ctrl+C
    signal(SIGTERM, exit_handler);  // Termination signal

	load_ifconfig();

	raw_socket_setup();

	// Mask configuration (moved here for sa_mask reuse) 
	if( -1 == sigemptyset(&global_signal_mask)) {perror("sigemtpyset"); return EXIT_FAILURE;}
	if( -1 == sigaddset(&global_signal_mask, SIGIO)){perror("sigaddset SIGIO"); return EXIT_FAILURE;} 
	if( -1 == sigaddset(&global_signal_mask, SIGALRM)){perror("sigaddset SIGALRM"); return EXIT_FAILURE;} 

	// Signal handlers association
	// https://claude.ai/share/cead81ba-d6f2-4f36-89e2-3a2dca9515fe
	struct sigaction action_io, action_timer;
	memset(&action_io, 0, sizeof(action_io));
	memset(&action_timer, 0, sizeof(action_timer));
	action_io.sa_flags = SA_RESTART;
	action_timer.sa_flags = SA_RESTART;
	action_io.sa_mask = global_signal_mask;
	action_timer.sa_mask = global_signal_mask;
	action_io.sa_handler = myio;
	action_timer.sa_handler = mytimer;
	sigaction(SIGIO, &action_io, NULL);
	sigaction(SIGALRM, &action_timer, NULL);

	// Enable the reception of signals
	if( -1 == sigprocmask(SIG_UNBLOCK, &global_signal_mask, NULL)){perror("sigprocmask"); return EXIT_FAILURE;}

	// Create and start the periodic timer
	struct itimerval myt;
	myt.it_interval.tv_sec=TIMER_USECS / 1000000;				/* Interval for periodic timer */
	myt.it_interval.tv_usec=TIMER_USECS % 1000000;	/* Interval for periodic timer */
	myt.it_value.tv_sec=TIMER_USECS / 1000000;    				/* Time until next expiration */
	myt.it_value.tv_usec=TIMER_USECS % 1000000;		/* Time until next expiration */
	if( -1 == setitimer(ITIMER_REAL, &myt, NULL)){
		perror("setitimer"); 
		return EXIT_FAILURE;
	}

	last_port = MIN_PORT + sample_uint32() % (MAX_PORT - MIN_PORT);

	if(MAIN_MODE == CLIENT){
		main_client_app();
	}else if(MAIN_MODE == SERVER){
		int listening_socket=mysocket(AF_INET,SOCK_STREAM,0);
		if(listening_socket == -1){
			myperror("mysocket");
			exit(EXIT_FAILURE);
		}
		DEBUG("mysocket OK");
		struct sockaddr_in loc_addr;
		loc_addr.sin_family = AF_INET;
		loc_addr.sin_port = htons(19500); // Automatic port
		loc_addr.sin_addr.s_addr = 0; // Automatic addr (myip)
		if( -1 == mybind(listening_socket,(struct sockaddr *) &loc_addr, sizeof(struct sockaddr_in))){
			myperror("mybind"); 
			exit(EXIT_FAILURE);
		}
		DEBUG("mybind OK");
		if ( mylisten(listening_socket,5) == -1 ) { 
			myperror("mylisten"); 
			exit(EXIT_FAILURE);
		}
		DEBUG("mylisten OK");
		
		/*
		int client_sockets[NUM_CLIENTS];
		for(int i=0; i<NUM_CLIENTS; i++){
			struct sockaddr_in remote_addr;
			remote_addr.sin_family=AF_INET;
			int len = sizeof(struct sockaddr_in);
			DEBUG("wait myaccept client %d", i);
			int s;
			do{
				s = myaccept(listening_socket, (struct sockaddr*) &remote_addr, &len);
				if(s<0 && myerrno != EAGAIN){
					myperror("myaccept");
					exit(EXIT_FAILURE);
				}
			}while(s < 0);
			DEBUG("myaccept %d OK (fd %d)", i, s);
			client_sockets[i] = s;
		}
		*/
		full_duplex_server_app(listening_socket);
	}else{
		ERROR("Invalid MAIN_MODE %d", MAIN_MODE);
	}
}