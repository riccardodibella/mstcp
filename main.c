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
#include <stdalign.h>

/* DEFINE MACROS */

//#define NODEBUG
#define NOLOGS
//#define SHORTLOGS

#define MALLOC_IMPL_GLIBC 0
#define MALLOC_IMPL_RDB 1
#define MALLOC_IMPL_TLSF 2
#define MALLOC_IMPL_DLMALLOC 3

#define CHOSEN_MALLOC_IMPL MALLOC_IMPL_DLMALLOC


#if CHOSEN_MALLOC_IMPL != MALLOC_IMPL_GLIBC
#define USE_CUSTOM_MALLOC
#endif

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
#define NUM_CLIENT_REQUESTS 1
/*
int num_req_arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
int payload_size_arr[] = {10, 100, 1000, 10000, 100000};
*/
/*
int num_req_arr[] = {1, 2, 4, 6, 8, 10};
int payload_size_arr[] = {10, 100, 1000, 2000, 5000, 10000, 20000};
*/
//int num_req_arr[] = {/*1, 2, 4, 6, 8, */10};
int num_req_arr[] = {1};
//int payload_size_arr[] = {/*200, 2000, 20000, 200000*/};
int payload_size_arr[] = {100};

//int num_req_arr[] = {1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
//int payload_size_arr[] = {2000};
#undef RESP_PAYLOAD_BYTES
#define RESP_PAYLOAD_BYTES 100

#endif

#if CL_MAIN == CL_MAIN_AGGREGATE

#undef RESP_PAYLOAD_BYTES
#define RESP_PAYLOAD_BYTES 1000000 // This is the maximum

#define NUM_CLIENTS_MAX 4
#define NUM_CLIENT_REQUESTS_MAX 128
int num_client_requests_test = NUM_CLIENT_REQUESTS_MAX;

#define MS_ENABLED true
// TCP: 1, 6
// MS: 1, 6, 32
int num_clients_arr[] = {NUM_CLIENTS_MAX}; 
int payload_size_arr[] = {RESP_PAYLOAD_BYTES};

//#define DELAY_REQ_PROB 1E-1

#endif

#if CL_MAIN == CL_MAIN_HTML
#define MS_ENABLED false
#define NUM_CLIENTS 6
#endif

#define REQ_BUF_SIZE 100
#define RESP_BUF_SIZE (100+RESP_PAYLOAD_BYTES)


//#define UPLINK_DROP_PROB 0
//#define DOWNLINK_DROP_PROB 0


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
#define INTERFACE_NAME "lo" // load_ifconfig

#define SERVER_IP_STR "127.0.0.1"
#define MAIN_LOOP_NANOSLEEP false
#else
#define INTERFACE_NAME "eth0" // load_ifconfig

//#define SERVER_IP_STR "88.80.187.84"
//#define SERVER_IP_STR "172.104.237.69"
#define SERVER_IP_STR "178.79.147.254"
#define MAIN_LOOP_NANOSLEEP false
#endif

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

#define L2_RX_BUF_SIZE 1600 // This was 30000 for some reason... I try to lower it, just out of curiosity, I don't know if this is a problem or not
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

#define REQUESTED_KERNEL_RX_BUF_SIZE (32*1024*1024)
#define REQUESTED_KERNEL_TX_BUF_SIZE (32*1024*1024)

#define MIN_PORT 19000
#define MAX_PORT 19999

#define TCP_PROTO 6 // protocol field inside IP header

#define TCP_MSS 1460
//#define TCP_MSS 1460 // MTU = 1500, MSS = MTU - 20 (IP Header) - 20 (TCP Header)
#define FIXED_OPTIONS_LENGTH 40
#define MAX_SEGMENT_PAYLOAD (TCP_MSS - FIXED_OPTIONS_LENGTH) // 1420, may be used for congestion control

#define MIN_FD 3 // fds 0, 1 and 2 are left empty

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
#define FSM_EVENT_TIMEOUT 4 // Channel timeout (connection closing)
#define FSM_EVENT_STREAM_TIMEOUT 5 // Stream timeout (no data has been sent upon stream opening, so a dummy byte is sent on that stream to open it)
#define FSM_EVENT_DO_CHANNEL_CLOSE 6

#define TCB_ST_CLOSED 10 // initial state
#define TCB_ST_LISTEN 11  // represents waiting for a connection request from any remote TCP and port.
#define TCB_ST_SYN_SENT 12 // represents waiting for a matching connection request after having sent a connection request.
#define TCB_ST_SYN_RECEIVED 13 // represents waiting for a confirming connection request acknowledgment after having both received and sent a connection request.
#define TCB_ST_ESTABLISHED 14 // represents an open connection, data received can be delivered to the user.  The normal state for the data transfer phase of the connection.
#define TCB_ST_FIN_WAIT_1 15 // waiting for a connection termination request from the remote TCP, or an acknowledgment of the conne
#define TCB_ST_FIN_WAIT_2 16 // waiting for a connection termination request from the remote TCP.
#define TCB_ST_CLOSE_WAIT 17 // waiting for a connection termination request from the local user. // unreachable with MS-TCP
#define TCB_ST_CLOSING 18  // waiting for a connection termination request acknowledgment from the remote TCP.
#define TCB_ST_LAST_ACK 19 // waiting for an acknowledgment of the connection termination request previously sent to the remote TCP
#define TCB_ST_TIME_WAIT 20 // waiting for enough time to pass to be sure the remote TCP received the acknowledgment of its connecti

#define STREAM_STATE_UNUSED 0
#define STREAM_STATE_READY 1 // only for passive open before accept
#define STREAM_STATE_OPENED 2


// The following is not true! State CLOSED is never used, instead it returns to UNUSED when these conditions are true
// Transitions to state CLOSED must be managed in 2 points: when write_side_close_state becomes LSS_ACKED, and where the flag lss_received is set, during myio
// #define STREAM_STATE_CLOSED 3 // commented out because this state is never reached
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
#define INIT_CGWIN 10 //in MSS
#define INIT_THRESH 1000000 //in MSS
#define FAST_RETX_DUPACK_THRESH 3 // How many consecutive dupACKs trigger a transition to fast retransmit (defined to 3 in RFC 5681)

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
	bool fin;
	int sid;
	int ssn;
	int payloadlen;
	bool dummy_payload;
	int totlen; // Includes IP header, TCP header, options and padding
	struct tcp_segment* segment;

	int64_t txtime;
	unsigned int retry;
};

struct channel_rx_queue_node{
	struct channel_rx_queue_node* next;
	struct channel_rx_queue_node* prev;
	uint32_t channel_offset; // sequence number - tcb->ack_offs
	int total_segment_length;
	int payload_length;
	bool fin;
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
	uint32_t scheduler_tokens[TOT_SID]; // mytcp: radwin
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
	int write_side_close_state[TOT_SID]; // WR_CLOSE_ST_OPEN / LSS_REQUESTED / LSS_TXED / LSS_ACKED

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
	struct txcontrolbuf *txfirst, *txlast;

	unsigned short r_port; // Channel property
	unsigned int r_addr; // Channel property
	struct channel_rx_queue_node* unack; // mytcp: struct rxcontrol* unack ; Channel queue of RXed packets yet to be acked
	struct channel_rx_queue_node* unack_tail;
	unsigned int cumulativeack; // Channel property
	unsigned int ack_offs; // Channel property
    unsigned int seq_offs; // Channel property
	long long timeout; // Channel property
	unsigned int sequence; // Channel property
	unsigned int highest_sent_sequence_number; // Channel property 
	unsigned int mss; // Channel property
	unsigned int payload_mss; // mss - FIXED_OPTIONS_LENGTH
	unsigned int stream_end; // Channel property (bad name) - unused
	uint64_t fsm_timer; // Channel property
	uint32_t init_radwin; // Used in MS-TCP as a default value for radwin of new streams
	unsigned int requested_acks;

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

unsigned int network_interface_index; // filled with if_nametoindex at startup

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

struct arpcacheline arpcache[MAX_ARP+1];

bool resolve_gateway_mac_requested = false;

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
	#ifndef NODEBUG
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
	#ifndef NODEBUG
	printf("DEBUG %.6u: ", (uint32_t) tick);
	va_list args;
	va_start(args, c);
	vprintf(c, args);
	va_end(args);
	printf("\n");
	#endif
}

#if CHOSEN_MALLOC_IMPL == MALLOC_IMPL_GLIBC
void* mymalloc(size_t size){
	return malloc(size);
}
void myfree(void* p){
	free(p);
}
void* myrealloc(void *ptr, size_t size){
	return realloc(ptr, size);
}
#endif

#if CHOSEN_MALLOC_IMPL == MALLOC_IMPL_RDB
#define MYMALLOC_AVAILABLE_MB 64
#define MYMALLOC_CHUNK_SIZE 128


#define MYMALLOC_AVAILABLE_BYTES (MYMALLOC_AVAILABLE_MB*1024*1024) 
#define MYMALLOC_NUM_CHUNKS (MYMALLOC_AVAILABLE_BYTES / MYMALLOC_CHUNK_SIZE)

uint32_t mymalloc_region_extensions[MYMALLOC_NUM_CHUNKS] = {0};
alignas(MYMALLOC_CHUNK_SIZE) uint8_t mymalloc_buffer[MYMALLOC_AVAILABLE_BYTES];

uint32_t next_chunk_hint = 0;
void* mymalloc(size_t size){
	if(size==0){
		return NULL;
	}
	if(size > UINT32_MAX){
		ERROR("mymalloc size %u > max %u", size, UINT32_MAX);
	}

	uint32_t requested_chunks = size / MYMALLOC_CHUNK_SIZE + (size % MYMALLOC_CHUNK_SIZE != 0);
	int current_first_free = next_chunk_hint;
	bool started_from_beginning = (next_chunk_hint == 0);
	while(true){
		if(current_first_free >= MYMALLOC_NUM_CHUNKS){
			if(!started_from_beginning){
				current_first_free = 0;
				started_from_beginning = true;
				continue;
			}else{
				ERROR("mymalloc out of memory (requested size %lu chunks %u)", size, requested_chunks);
				myerrno=ENOMEM;
				return NULL;
			}
		}
		if(mymalloc_region_extensions[current_first_free] != 0){
			current_first_free+=mymalloc_region_extensions[current_first_free];
			continue;
		}
		bool all_free=true;
		for(int i=1; i<requested_chunks; i++){
			if(current_first_free + i >= MYMALLOC_NUM_CHUNKS){
				current_first_free += i;
				all_free=false;
				break;
			}
			if(mymalloc_region_extensions[current_first_free+i] != 0){
				current_first_free += i + mymalloc_region_extensions[current_first_free+i];
				all_free=false;
				break;
			}
		}
		if(!all_free){
			// current_first_free already updated
			continue;
		}

		// Found free region at current_first_free
		next_chunk_hint = current_first_free + requested_chunks;
		mymalloc_region_extensions[current_first_free] = requested_chunks;
		return (void*) &(mymalloc_buffer[current_first_free*MYMALLOC_CHUNK_SIZE]);
	}
	ERROR("we should never arrive after the free in mymalloc");
}
void myfree(void* p){
	if(p == NULL){
		return;
	}

	ssize_t buffer_pos = ((uint8_t*)p - mymalloc_buffer);
	if(buffer_pos < 0 || buffer_pos >= MYMALLOC_AVAILABLE_BYTES || buffer_pos % MYMALLOC_CHUNK_SIZE != 0){
		ERROR("myfree invalid buffer_pos %lu", buffer_pos);
	}
	uint32_t chunk_number = buffer_pos / MYMALLOC_CHUNK_SIZE;
	if(mymalloc_region_extensions[chunk_number] == 0){
		ERROR("myfree mymalloc_region_extensions[%u] == 0", chunk_number);
	}
	mymalloc_region_extensions[chunk_number] = 0;
}
void* myrealloc(void *ptr, size_t size){
	if(ptr==NULL){
		return mymalloc(size);
	}
	if(size == 0){
		myfree(ptr);
		return NULL;
	}
	if(size > UINT32_MAX){
		ERROR("myrealloc size %u > max %u", size, UINT32_MAX);
	}
	ssize_t buffer_pos = ((uint8_t*)ptr - mymalloc_buffer);
	if(buffer_pos < 0 || buffer_pos >= MYMALLOC_AVAILABLE_BYTES || buffer_pos % MYMALLOC_CHUNK_SIZE != 0){
		ERROR("myrealloc invalid buffer_pos %lu", buffer_pos);
	}
	uint32_t chunk_number = buffer_pos / MYMALLOC_CHUNK_SIZE;
	if(mymalloc_region_extensions[chunk_number] == 0){
		ERROR("myrealloc mymalloc_region_extensions[%u] == 0", chunk_number);
	}
	uint32_t src_chunks = mymalloc_region_extensions[chunk_number];
	uint32_t dst_chunks = size / MYMALLOC_CHUNK_SIZE + (size % MYMALLOC_CHUNK_SIZE != 0);
	if(dst_chunks <= src_chunks){
		mymalloc_region_extensions[chunk_number] = dst_chunks;
		return ptr;
	}
	void* to_return = mymalloc(size);
	if(to_return == NULL){
		ERROR("myrealloc mymalloc returned NULL");
	}
	memcpy(to_return, ptr, src_chunks*MYMALLOC_CHUNK_SIZE);
	myfree(ptr);
	return to_return;
}
#endif

#if CHOSEN_MALLOC_IMPL == MALLOC_IMPL_TLSF
// https://github.com/mattconte/tlsf/blob/master/tlsf.h
#pragma region TLSF_H
#ifndef INCLUDED_tlsf
#define INCLUDED_tlsf

/*
** Two Level Segregated Fit memory allocator, version 3.1.
** Written by Matthew Conte
**	http://tlsf.baisoku.org
**
** Based on the original documentation by Miguel Masmano:
**	http://www.gii.upv.es/tlsf/main/docs
**
** This implementation was written to the specification
** of the document, therefore no GPL restrictions apply.
** 
** Copyright (c) 2006-2016, Matthew Conte
** All rights reserved.
** 
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the copyright holder nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
** 
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL MATTHEW CONTE BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* tlsf_t: a TLSF structure. Can contain 1 to N pools. */
/* pool_t: a block of memory that TLSF can manage. */
typedef void* tlsf_t;
typedef void* pool_t;

/* Create/destroy a memory pool. */
tlsf_t tlsf_create(void* mem);
tlsf_t tlsf_create_with_pool(void* mem, size_t bytes);
void tlsf_destroy(tlsf_t tlsf);
pool_t tlsf_get_pool(tlsf_t tlsf);

/* Add/remove memory pools. */
pool_t tlsf_add_pool(tlsf_t tlsf, void* mem, size_t bytes);
void tlsf_remove_pool(tlsf_t tlsf, pool_t pool);

/* malloc/memalign/realloc/free replacements. */
void* tlsf_malloc(tlsf_t tlsf, size_t bytes);
void* tlsf_memalign(tlsf_t tlsf, size_t align, size_t bytes);
void* tlsf_realloc(tlsf_t tlsf, void* ptr, size_t size);
void tlsf_free(tlsf_t tlsf, void* ptr);

/* Returns internal block size, not original request size */
size_t tlsf_block_size(void* ptr);

/* Overheads/limits of internal structures. */
size_t tlsf_size(void);
size_t tlsf_align_size(void);
size_t tlsf_block_size_min(void);
size_t tlsf_block_size_max(void);
size_t tlsf_pool_overhead(void);
size_t tlsf_alloc_overhead(void);

/* Debugging. */
typedef void (*tlsf_walker)(void* ptr, size_t size, int used, void* user);
void tlsf_walk_pool(pool_t pool, tlsf_walker walker, void* user);
/* Returns nonzero if any internal consistency check fails. */
int tlsf_check(tlsf_t tlsf);
int tlsf_check_pool(pool_t pool);

#if defined(__cplusplus)
};
#endif

#endif
#pragma endregion TLSF_H

// https://github.com/mattconte/tlsf/blob/master/tlsf.c
#pragma region TLSF_C
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__cplusplus)
#define tlsf_decl inline
#else
#define tlsf_decl static
#endif

/*
** Architecture-specific bit manipulation routines.
**
** TLSF achieves O(1) cost for malloc and free operations by limiting
** the search for a free block to a free list of guaranteed size
** adequate to fulfill the request, combined with efficient free list
** queries using bitmasks and architecture-specific bit-manipulation
** routines.
**
** Most modern processors provide instructions to count leading zeroes
** in a word, find the lowest and highest set bit, etc. These
** specific implementations will be used when available, falling back
** to a reasonably efficient generic implementation.
**
** NOTE: TLSF spec relies on ffs/fls returning value 0..31.
** ffs/fls return 1-32 by default, returning 0 for error.
*/

/*
** Detect whether or not we are building for a 32- or 64-bit (LP/LLP)
** architecture. There is no reliable portable method at compile-time.
*/
#if defined (__alpha__) || defined (__ia64__) || defined (__x86_64__) \
	|| defined (_WIN64) || defined (__LP64__) || defined (__LLP64__)
#define TLSF_64BIT
#endif

/*
** gcc 3.4 and above have builtin support, specialized for architecture.
** Some compilers masquerade as gcc; patchlevel test filters them out.
*/
#if defined (__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)) \
	&& defined (__GNUC_PATCHLEVEL__)

#if defined (__SNC__)
/* SNC for Playstation 3. */

tlsf_decl int tlsf_ffs(unsigned int word)
{
	const unsigned int reverse = word & (~word + 1);
	const int bit = 32 - __builtin_clz(reverse);
	return bit - 1;
}

#else

tlsf_decl int tlsf_ffs(unsigned int word)
{
	return __builtin_ffs(word) - 1;
}

#endif

tlsf_decl int tlsf_fls(unsigned int word)
{
	const int bit = word ? 32 - __builtin_clz(word) : 0;
	return bit - 1;
}

#elif defined (_MSC_VER) && (_MSC_VER >= 1400) && (defined (_M_IX86) || defined (_M_X64))
/* Microsoft Visual C++ support on x86/X64 architectures. */

#include <intrin.h>

#pragma intrinsic(_BitScanReverse)
#pragma intrinsic(_BitScanForward)

tlsf_decl int tlsf_fls(unsigned int word)
{
	unsigned long index;
	return _BitScanReverse(&index, word) ? index : -1;
}

tlsf_decl int tlsf_ffs(unsigned int word)
{
	unsigned long index;
	return _BitScanForward(&index, word) ? index : -1;
}

#elif defined (_MSC_VER) && defined (_M_PPC)
/* Microsoft Visual C++ support on PowerPC architectures. */

#include <ppcintrinsics.h>

tlsf_decl int tlsf_fls(unsigned int word)
{
	const int bit = 32 - _CountLeadingZeros(word);
	return bit - 1;
}

tlsf_decl int tlsf_ffs(unsigned int word)
{
	const unsigned int reverse = word & (~word + 1);
	const int bit = 32 - _CountLeadingZeros(reverse);
	return bit - 1;
}

#elif defined (__ARMCC_VERSION)
/* RealView Compilation Tools for ARM */

tlsf_decl int tlsf_ffs(unsigned int word)
{
	const unsigned int reverse = word & (~word + 1);
	const int bit = 32 - __clz(reverse);
	return bit - 1;
}

tlsf_decl int tlsf_fls(unsigned int word)
{
	const int bit = word ? 32 - __clz(word) : 0;
	return bit - 1;
}

#elif defined (__ghs__)
/* Green Hills support for PowerPC */

#include <ppc_ghs.h>

tlsf_decl int tlsf_ffs(unsigned int word)
{
	const unsigned int reverse = word & (~word + 1);
	const int bit = 32 - __CLZ32(reverse);
	return bit - 1;
}

tlsf_decl int tlsf_fls(unsigned int word)
{
	const int bit = word ? 32 - __CLZ32(word) : 0;
	return bit - 1;
}

#else
/* Fall back to generic implementation. */

tlsf_decl int tlsf_fls_generic(unsigned int word)
{
	int bit = 32;

	if (!word) bit -= 1;
	if (!(word & 0xffff0000)) { word <<= 16; bit -= 16; }
	if (!(word & 0xff000000)) { word <<= 8; bit -= 8; }
	if (!(word & 0xf0000000)) { word <<= 4; bit -= 4; }
	if (!(word & 0xc0000000)) { word <<= 2; bit -= 2; }
	if (!(word & 0x80000000)) { word <<= 1; bit -= 1; }

	return bit;
}

/* Implement ffs in terms of fls. */
tlsf_decl int tlsf_ffs(unsigned int word)
{
	return tlsf_fls_generic(word & (~word + 1)) - 1;
}

tlsf_decl int tlsf_fls(unsigned int word)
{
	return tlsf_fls_generic(word) - 1;
}

#endif

/* Possibly 64-bit version of tlsf_fls. */
#if defined (TLSF_64BIT)
tlsf_decl int tlsf_fls_sizet(size_t size)
{
	int high = (int)(size >> 32);
	int bits = 0;
	if (high)
	{
		bits = 32 + tlsf_fls(high);
	}
	else
	{
		bits = tlsf_fls((int)size & 0xffffffff);

	}
	return bits;
}
#else
#define tlsf_fls_sizet tlsf_fls
#endif

#undef tlsf_decl

/*
** Constants.
*/

/* Public constants: may be modified. */
enum tlsf_public
{
	/* log2 of number of linear subdivisions of block sizes. Larger
	** values require more memory in the control structure. Values of
	** 4 or 5 are typical.
	*/
	SL_INDEX_COUNT_LOG2 = 5,
};

/* Private constants: do not modify. */
enum tlsf_private
{
#if defined (TLSF_64BIT)
	/* All allocation sizes and addresses are aligned to 8 bytes. */
	ALIGN_SIZE_LOG2 = 3,
#else
	/* All allocation sizes and addresses are aligned to 4 bytes. */
	ALIGN_SIZE_LOG2 = 2,
#endif
	ALIGN_SIZE = (1 << ALIGN_SIZE_LOG2),

	/*
	** We support allocations of sizes up to (1 << FL_INDEX_MAX) bits.
	** However, because we linearly subdivide the second-level lists, and
	** our minimum size granularity is 4 bytes, it doesn't make sense to
	** create first-level lists for sizes smaller than SL_INDEX_COUNT * 4,
	** or (1 << (SL_INDEX_COUNT_LOG2 + 2)) bytes, as there we will be
	** trying to split size ranges into more slots than we have available.
	** Instead, we calculate the minimum threshold size, and place all
	** blocks below that size into the 0th first-level list.
	*/

#if defined (TLSF_64BIT)
	/*
	** TODO: We can increase this to support larger sizes, at the expense
	** of more overhead in the TLSF structure.
	*/
	FL_INDEX_MAX = 32,
#else
	FL_INDEX_MAX = 30,
#endif
	SL_INDEX_COUNT = (1 << SL_INDEX_COUNT_LOG2),
	FL_INDEX_SHIFT = (SL_INDEX_COUNT_LOG2 + ALIGN_SIZE_LOG2),
	FL_INDEX_COUNT = (FL_INDEX_MAX - FL_INDEX_SHIFT + 1),

	SMALL_BLOCK_SIZE = (1 << FL_INDEX_SHIFT),
};

/*
** Cast and min/max macros.
*/

#define tlsf_cast(t, exp)	((t) (exp))
#define tlsf_min(a, b)		((a) < (b) ? (a) : (b))
#define tlsf_max(a, b)		((a) > (b) ? (a) : (b))

/*
** Set assert macro, if it has not been provided by the user.
*/
#if !defined (tlsf_assert)
#define tlsf_assert assert
#endif

/*
** Static assertion mechanism.
*/

#define _tlsf_glue2(x, y) x ## y
#define _tlsf_glue(x, y) _tlsf_glue2(x, y)
#define tlsf_static_assert(exp) \
	typedef char _tlsf_glue(static_assert, __LINE__) [(exp) ? 1 : -1]

/* This code has been tested on 32- and 64-bit (LP/LLP) architectures. */
tlsf_static_assert(sizeof(int) * CHAR_BIT == 32);
tlsf_static_assert(sizeof(size_t) * CHAR_BIT >= 32);
tlsf_static_assert(sizeof(size_t) * CHAR_BIT <= 64);

/* SL_INDEX_COUNT must be <= number of bits in sl_bitmap's storage type. */
tlsf_static_assert(sizeof(unsigned int) * CHAR_BIT >= SL_INDEX_COUNT);

/* Ensure we've properly tuned our sizes. */
tlsf_static_assert(ALIGN_SIZE == SMALL_BLOCK_SIZE / SL_INDEX_COUNT);

/*
** Data structures and associated constants.
*/

/*
** Block header structure.
**
** There are several implementation subtleties involved:
** - The prev_phys_block field is only valid if the previous block is free.
** - The prev_phys_block field is actually stored at the end of the
**   previous block. It appears at the beginning of this structure only to
**   simplify the implementation.
** - The next_free / prev_free fields are only valid if the block is free.
*/
typedef struct block_header_t
{
	/* Points to the previous physical block. */
	struct block_header_t* prev_phys_block;

	/* The size of this block, excluding the block header. */
	size_t size;

	/* Next and previous free blocks. */
	struct block_header_t* next_free;
	struct block_header_t* prev_free;
} block_header_t;

/*
** Since block sizes are always at least a multiple of 4, the two least
** significant bits of the size field are used to store the block status:
** - bit 0: whether block is busy or free
** - bit 1: whether previous block is busy or free
*/
static const size_t block_header_free_bit = 1 << 0;
static const size_t block_header_prev_free_bit = 1 << 1;

/*
** The size of the block header exposed to used blocks is the size field.
** The prev_phys_block field is stored *inside* the previous free block.
*/
static const size_t block_header_overhead = sizeof(size_t);

/* User data starts directly after the size field in a used block. */
static const size_t block_start_offset =
	offsetof(block_header_t, size) + sizeof(size_t);

/*
** A free block must be large enough to store its header minus the size of
** the prev_phys_block field, and no larger than the number of addressable
** bits for FL_INDEX.
*/
static const size_t block_size_min = 
	sizeof(block_header_t) - sizeof(block_header_t*);
static const size_t block_size_max = tlsf_cast(size_t, 1) << FL_INDEX_MAX;


/* The TLSF control structure. */
typedef struct control_t
{
	/* Empty lists point at this block to indicate they are free. */
	block_header_t block_null;

	/* Bitmaps for free lists. */
	unsigned int fl_bitmap;
	unsigned int sl_bitmap[FL_INDEX_COUNT];

	/* Head of free lists. */
	block_header_t* blocks[FL_INDEX_COUNT][SL_INDEX_COUNT];
} control_t;

/* A type used for casting when doing pointer arithmetic. */
typedef ptrdiff_t tlsfptr_t;

/*
** block_header_t member functions.
*/

static size_t block_size(const block_header_t* block)
{
	return block->size & ~(block_header_free_bit | block_header_prev_free_bit);
}

static void block_set_size(block_header_t* block, size_t size)
{
	const size_t oldsize = block->size;
	block->size = size | (oldsize & (block_header_free_bit | block_header_prev_free_bit));
}

static int block_is_last(const block_header_t* block)
{
	return block_size(block) == 0;
}

static int block_is_free(const block_header_t* block)
{
	return tlsf_cast(int, block->size & block_header_free_bit);
}

static void block_set_free(block_header_t* block)
{
	block->size |= block_header_free_bit;
}

static void block_set_used(block_header_t* block)
{
	block->size &= ~block_header_free_bit;
}

static int block_is_prev_free(const block_header_t* block)
{
	return tlsf_cast(int, block->size & block_header_prev_free_bit);
}

static void block_set_prev_free(block_header_t* block)
{
	block->size |= block_header_prev_free_bit;
}

static void block_set_prev_used(block_header_t* block)
{
	block->size &= ~block_header_prev_free_bit;
}

static block_header_t* block_from_ptr(const void* ptr)
{
	return tlsf_cast(block_header_t*,
		tlsf_cast(unsigned char*, ptr) - block_start_offset);
}

static void* block_to_ptr(const block_header_t* block)
{
	return tlsf_cast(void*,
		tlsf_cast(unsigned char*, block) + block_start_offset);
}

/* Return location of next block after block of given size. */
static block_header_t* offset_to_block(const void* ptr, size_t size)
{
	return tlsf_cast(block_header_t*, tlsf_cast(tlsfptr_t, ptr) + size);
}

/* Return location of previous block. */
static block_header_t* block_prev(const block_header_t* block)
{
	tlsf_assert(block_is_prev_free(block) && "previous block must be free");
	return block->prev_phys_block;
}

/* Return location of next existing block. */
static block_header_t* block_next(const block_header_t* block)
{
	block_header_t* next = offset_to_block(block_to_ptr(block),
		block_size(block) - block_header_overhead);
	tlsf_assert(!block_is_last(block));
	return next;
}

/* Link a new block with its physical neighbor, return the neighbor. */
static block_header_t* block_link_next(block_header_t* block)
{
	block_header_t* next = block_next(block);
	next->prev_phys_block = block;
	return next;
}

static void block_mark_as_free(block_header_t* block)
{
	/* Link the block to the next block, first. */
	block_header_t* next = block_link_next(block);
	block_set_prev_free(next);
	block_set_free(block);
}

static void block_mark_as_used(block_header_t* block)
{
	block_header_t* next = block_next(block);
	block_set_prev_used(next);
	block_set_used(block);
}

static size_t align_up(size_t x, size_t align)
{
	tlsf_assert(0 == (align & (align - 1)) && "must align to a power of two");
	return (x + (align - 1)) & ~(align - 1);
}

static size_t align_down(size_t x, size_t align)
{
	tlsf_assert(0 == (align & (align - 1)) && "must align to a power of two");
	return x - (x & (align - 1));
}

static void* align_ptr(const void* ptr, size_t align)
{
	const tlsfptr_t aligned =
		(tlsf_cast(tlsfptr_t, ptr) + (align - 1)) & ~(align - 1);
	tlsf_assert(0 == (align & (align - 1)) && "must align to a power of two");
	return tlsf_cast(void*, aligned);
}

/*
** Adjust an allocation size to be aligned to word size, and no smaller
** than internal minimum.
*/
static size_t adjust_request_size(size_t size, size_t align)
{
	size_t adjust = 0;
	if (size)
	{
		const size_t aligned = align_up(size, align);

		/* aligned sized must not exceed block_size_max or we'll go out of bounds on sl_bitmap */
		if (aligned < block_size_max) 
		{
			adjust = tlsf_max(aligned, block_size_min);
		}
	}
	return adjust;
}

/*
** TLSF utility functions. In most cases, these are direct translations of
** the documentation found in the white paper.
*/

static void mapping_insert(size_t size, int* fli, int* sli)
{
	int fl, sl;
	if (size < SMALL_BLOCK_SIZE)
	{
		/* Store small blocks in first list. */
		fl = 0;
		sl = tlsf_cast(int, size) / (SMALL_BLOCK_SIZE / SL_INDEX_COUNT);
	}
	else
	{
		fl = tlsf_fls_sizet(size);
		sl = tlsf_cast(int, size >> (fl - SL_INDEX_COUNT_LOG2)) ^ (1 << SL_INDEX_COUNT_LOG2);
		fl -= (FL_INDEX_SHIFT - 1);
	}
	*fli = fl;
	*sli = sl;
}

/* This version rounds up to the next block size (for allocations) */
static void mapping_search(size_t size, int* fli, int* sli)
{
	if (size >= SMALL_BLOCK_SIZE)
	{
		const size_t round = (1 << (tlsf_fls_sizet(size) - SL_INDEX_COUNT_LOG2)) - 1;
		size += round;
	}
	mapping_insert(size, fli, sli);
}

static block_header_t* search_suitable_block(control_t* control, int* fli, int* sli)
{
	int fl = *fli;
	int sl = *sli;

	/*
	** First, search for a block in the list associated with the given
	** fl/sl index.
	*/
	unsigned int sl_map = control->sl_bitmap[fl] & (~0U << sl);
	if (!sl_map)
	{
		/* No block exists. Search in the next largest first-level list. */
		const unsigned int fl_map = control->fl_bitmap & (~0U << (fl + 1));
		if (!fl_map)
		{
			/* No free blocks available, memory has been exhausted. */
			return 0;
		}

		fl = tlsf_ffs(fl_map);
		*fli = fl;
		sl_map = control->sl_bitmap[fl];
	}
	tlsf_assert(sl_map && "internal error - second level bitmap is null");
	sl = tlsf_ffs(sl_map);
	*sli = sl;

	/* Return the first block in the free list. */
	return control->blocks[fl][sl];
}

/* Remove a free block from the free list.*/
static void remove_free_block(control_t* control, block_header_t* block, int fl, int sl)
{
	block_header_t* prev = block->prev_free;
	block_header_t* next = block->next_free;
	tlsf_assert(prev && "prev_free field can not be null");
	tlsf_assert(next && "next_free field can not be null");
	next->prev_free = prev;
	prev->next_free = next;

	/* If this block is the head of the free list, set new head. */
	if (control->blocks[fl][sl] == block)
	{
		control->blocks[fl][sl] = next;

		/* If the new head is null, clear the bitmap. */
		if (next == &control->block_null)
		{
			control->sl_bitmap[fl] &= ~(1U << sl);

			/* If the second bitmap is now empty, clear the fl bitmap. */
			if (!control->sl_bitmap[fl])
			{
				control->fl_bitmap &= ~(1U << fl);
			}
		}
	}
}

/* Insert a free block into the free block list. */
static void insert_free_block(control_t* control, block_header_t* block, int fl, int sl)
{
	block_header_t* current = control->blocks[fl][sl];
	tlsf_assert(current && "free list cannot have a null entry");
	tlsf_assert(block && "cannot insert a null entry into the free list");
	block->next_free = current;
	block->prev_free = &control->block_null;
	current->prev_free = block;

	tlsf_assert(block_to_ptr(block) == align_ptr(block_to_ptr(block), ALIGN_SIZE)
		&& "block not aligned properly");
	/*
	** Insert the new block at the head of the list, and mark the first-
	** and second-level bitmaps appropriately.
	*/
	control->blocks[fl][sl] = block;
	control->fl_bitmap |= (1U << fl);
	control->sl_bitmap[fl] |= (1U << sl);
}

/* Remove a given block from the free list. */
static void block_remove(control_t* control, block_header_t* block)
{
	int fl, sl;
	mapping_insert(block_size(block), &fl, &sl);
	remove_free_block(control, block, fl, sl);
}

/* Insert a given block into the free list. */
static void block_insert(control_t* control, block_header_t* block)
{
	int fl, sl;
	mapping_insert(block_size(block), &fl, &sl);
	insert_free_block(control, block, fl, sl);
}

static int block_can_split(block_header_t* block, size_t size)
{
	return block_size(block) >= sizeof(block_header_t) + size;
}

/* Split a block into two, the second of which is free. */
static block_header_t* block_split(block_header_t* block, size_t size)
{
	/* Calculate the amount of space left in the remaining block. */
	block_header_t* remaining =
		offset_to_block(block_to_ptr(block), size - block_header_overhead);

	const size_t remain_size = block_size(block) - (size + block_header_overhead);

	tlsf_assert(block_to_ptr(remaining) == align_ptr(block_to_ptr(remaining), ALIGN_SIZE)
		&& "remaining block not aligned properly");

	tlsf_assert(block_size(block) == remain_size + size + block_header_overhead);
	block_set_size(remaining, remain_size);
	tlsf_assert(block_size(remaining) >= block_size_min && "block split with invalid size");

	block_set_size(block, size);
	block_mark_as_free(remaining);

	return remaining;
}

/* Absorb a free block's storage into an adjacent previous free block. */
static block_header_t* block_absorb(block_header_t* prev, block_header_t* block)
{
	tlsf_assert(!block_is_last(prev) && "previous block can't be last");
	/* Note: Leaves flags untouched. */
	prev->size += block_size(block) + block_header_overhead;
	block_link_next(prev);
	return prev;
}

/* Merge a just-freed block with an adjacent previous free block. */
static block_header_t* block_merge_prev(control_t* control, block_header_t* block)
{
	if (block_is_prev_free(block))
	{
		block_header_t* prev = block_prev(block);
		tlsf_assert(prev && "prev physical block can't be null");
		tlsf_assert(block_is_free(prev) && "prev block is not free though marked as such");
		block_remove(control, prev);
		block = block_absorb(prev, block);
	}

	return block;
}

/* Merge a just-freed block with an adjacent free block. */
static block_header_t* block_merge_next(control_t* control, block_header_t* block)
{
	block_header_t* next = block_next(block);
	tlsf_assert(next && "next physical block can't be null");

	if (block_is_free(next))
	{
		tlsf_assert(!block_is_last(block) && "previous block can't be last");
		block_remove(control, next);
		block = block_absorb(block, next);
	}

	return block;
}

/* Trim any trailing block space off the end of a block, return to pool. */
static void block_trim_free(control_t* control, block_header_t* block, size_t size)
{
	tlsf_assert(block_is_free(block) && "block must be free");
	if (block_can_split(block, size))
	{
		block_header_t* remaining_block = block_split(block, size);
		block_link_next(block);
		block_set_prev_free(remaining_block);
		block_insert(control, remaining_block);
	}
}

/* Trim any trailing block space off the end of a used block, return to pool. */
static void block_trim_used(control_t* control, block_header_t* block, size_t size)
{
	tlsf_assert(!block_is_free(block) && "block must be used");
	if (block_can_split(block, size))
	{
		/* If the next block is free, we must coalesce. */
		block_header_t* remaining_block = block_split(block, size);
		block_set_prev_used(remaining_block);

		remaining_block = block_merge_next(control, remaining_block);
		block_insert(control, remaining_block);
	}
}

static block_header_t* block_trim_free_leading(control_t* control, block_header_t* block, size_t size)
{
	block_header_t* remaining_block = block;
	if (block_can_split(block, size))
	{
		/* We want the 2nd block. */
		remaining_block = block_split(block, size - block_header_overhead);
		block_set_prev_free(remaining_block);

		block_link_next(block);
		block_insert(control, block);
	}

	return remaining_block;
}

static block_header_t* block_locate_free(control_t* control, size_t size)
{
	int fl = 0, sl = 0;
	block_header_t* block = 0;

	if (size)
	{
		mapping_search(size, &fl, &sl);
		
		/*
		** mapping_search can futz with the size, so for excessively large sizes it can sometimes wind up 
		** with indices that are off the end of the block array.
		** So, we protect against that here, since this is the only callsite of mapping_search.
		** Note that we don't need to check sl, since it comes from a modulo operation that guarantees it's always in range.
		*/
		if (fl < FL_INDEX_COUNT)
		{
			block = search_suitable_block(control, &fl, &sl);
		}
	}

	if (block)
	{
		tlsf_assert(block_size(block) >= size);
		remove_free_block(control, block, fl, sl);
	}

	return block;
}

static void* block_prepare_used(control_t* control, block_header_t* block, size_t size)
{
	void* p = 0;
	if (block)
	{
		tlsf_assert(size && "size must be non-zero");
		block_trim_free(control, block, size);
		block_mark_as_used(block);
		p = block_to_ptr(block);
	}
	return p;
}

/* Clear structure and point all empty lists at the null block. */
static void control_construct(control_t* control)
{
	int i, j;

	control->block_null.next_free = &control->block_null;
	control->block_null.prev_free = &control->block_null;

	control->fl_bitmap = 0;
	for (i = 0; i < FL_INDEX_COUNT; ++i)
	{
		control->sl_bitmap[i] = 0;
		for (j = 0; j < SL_INDEX_COUNT; ++j)
		{
			control->blocks[i][j] = &control->block_null;
		}
	}
}

/*
** Debugging utilities.
*/

typedef struct integrity_t
{
	int prev_status;
	int status;
} integrity_t;

#define tlsf_insist(x) { tlsf_assert(x); if (!(x)) { status--; } }

static void integrity_walker(void* ptr, size_t size, int used, void* user)
{
	block_header_t* block = block_from_ptr(ptr);
	integrity_t* integ = tlsf_cast(integrity_t*, user);
	const int this_prev_status = block_is_prev_free(block) ? 1 : 0;
	const int this_status = block_is_free(block) ? 1 : 0;
	const size_t this_block_size = block_size(block);

	int status = 0;
	(void)used;
	tlsf_insist(integ->prev_status == this_prev_status && "prev status incorrect");
	tlsf_insist(size == this_block_size && "block size incorrect");

	integ->prev_status = this_status;
	integ->status += status;
}

int tlsf_check(tlsf_t tlsf)
{
	int i, j;

	control_t* control = tlsf_cast(control_t*, tlsf);
	int status = 0;

	/* Check that the free lists and bitmaps are accurate. */
	for (i = 0; i < FL_INDEX_COUNT; ++i)
	{
		for (j = 0; j < SL_INDEX_COUNT; ++j)
		{
			const int fl_map = control->fl_bitmap & (1U << i);
			const int sl_list = control->sl_bitmap[i];
			const int sl_map = sl_list & (1U << j);
			const block_header_t* block = control->blocks[i][j];

			/* Check that first- and second-level lists agree. */
			if (!fl_map)
			{
				tlsf_insist(!sl_map && "second-level map must be null");
			}

			if (!sl_map)
			{
				tlsf_insist(block == &control->block_null && "block list must be null");
				continue;
			}

			/* Check that there is at least one free block. */
			tlsf_insist(sl_list && "no free blocks in second-level map");
			tlsf_insist(block != &control->block_null && "block should not be null");

			while (block != &control->block_null)
			{
				int fli, sli;
				tlsf_insist(block_is_free(block) && "block should be free");
				tlsf_insist(!block_is_prev_free(block) && "blocks should have coalesced");
				tlsf_insist(!block_is_free(block_next(block)) && "blocks should have coalesced");
				tlsf_insist(block_is_prev_free(block_next(block)) && "block should be free");
				tlsf_insist(block_size(block) >= block_size_min && "block not minimum size");

				mapping_insert(block_size(block), &fli, &sli);
				tlsf_insist(fli == i && sli == j && "block size indexed in wrong list");
				block = block->next_free;
			}
		}
	}

	return status;
}

#undef tlsf_insist

static void default_walker(void* ptr, size_t size, int used, void* user)
{
	(void)user;
	printf("\t%p %s size: %x (%p)\n", ptr, used ? "used" : "free", (unsigned int)size, block_from_ptr(ptr));
}

void tlsf_walk_pool(pool_t pool, tlsf_walker walker, void* user)
{
	tlsf_walker pool_walker = walker ? walker : default_walker;
	block_header_t* block =
		offset_to_block(pool, -(int)block_header_overhead);

	while (block && !block_is_last(block))
	{
		pool_walker(
			block_to_ptr(block),
			block_size(block),
			!block_is_free(block),
			user);
		block = block_next(block);
	}
}

size_t tlsf_block_size(void* ptr)
{
	size_t size = 0;
	if (ptr)
	{
		const block_header_t* block = block_from_ptr(ptr);
		size = block_size(block);
	}
	return size;
}

int tlsf_check_pool(pool_t pool)
{
	/* Check that the blocks are physically correct. */
	integrity_t integ = { 0, 0 };
	tlsf_walk_pool(pool, integrity_walker, &integ);

	return integ.status;
}

/*
** Size of the TLSF structures in a given memory block passed to
** tlsf_create, equal to the size of a control_t
*/
size_t tlsf_size(void)
{
	return sizeof(control_t);
}

size_t tlsf_align_size(void)
{
	return ALIGN_SIZE;
}

size_t tlsf_block_size_min(void)
{
	return block_size_min;
}

size_t tlsf_block_size_max(void)
{
	return block_size_max;
}

/*
** Overhead of the TLSF structures in a given memory block passed to
** tlsf_add_pool, equal to the overhead of a free block and the
** sentinel block.
*/
size_t tlsf_pool_overhead(void)
{
	return 2 * block_header_overhead;
}

size_t tlsf_alloc_overhead(void)
{
	return block_header_overhead;
}

pool_t tlsf_add_pool(tlsf_t tlsf, void* mem, size_t bytes)
{
	block_header_t* block;
	block_header_t* next;

	const size_t pool_overhead = tlsf_pool_overhead();
	const size_t pool_bytes = align_down(bytes - pool_overhead, ALIGN_SIZE);

	if (((ptrdiff_t)mem % ALIGN_SIZE) != 0)
	{
		printf("tlsf_add_pool: Memory must be aligned by %u bytes.\n",
			(unsigned int)ALIGN_SIZE);
		return 0;
	}

	if (pool_bytes < block_size_min || pool_bytes > block_size_max)
	{
#if defined (TLSF_64BIT)
		printf("tlsf_add_pool: Memory size must be between 0x%x and 0x%x00 bytes.\n", 
			(unsigned int)(pool_overhead + block_size_min),
			(unsigned int)((pool_overhead + block_size_max) / 256));
#else
		printf("tlsf_add_pool: Memory size must be between %u and %u bytes.\n", 
			(unsigned int)(pool_overhead + block_size_min),
			(unsigned int)(pool_overhead + block_size_max));
#endif
		return 0;
	}

	/*
	** Create the main free block. Offset the start of the block slightly
	** so that the prev_phys_block field falls outside of the pool -
	** it will never be used.
	*/
	block = offset_to_block(mem, -(tlsfptr_t)block_header_overhead);
	block_set_size(block, pool_bytes);
	block_set_free(block);
	block_set_prev_used(block);
	block_insert(tlsf_cast(control_t*, tlsf), block);

	/* Split the block to create a zero-size sentinel block. */
	next = block_link_next(block);
	block_set_size(next, 0);
	block_set_used(next);
	block_set_prev_free(next);

	return mem;
}

void tlsf_remove_pool(tlsf_t tlsf, pool_t pool)
{
	control_t* control = tlsf_cast(control_t*, tlsf);
	block_header_t* block = offset_to_block(pool, -(int)block_header_overhead);

	int fl = 0, sl = 0;

	tlsf_assert(block_is_free(block) && "block should be free");
	tlsf_assert(!block_is_free(block_next(block)) && "next block should not be free");
	tlsf_assert(block_size(block_next(block)) == 0 && "next block size should be zero");

	mapping_insert(block_size(block), &fl, &sl);
	remove_free_block(control, block, fl, sl);
}

/*
** TLSF main interface.
*/

#if _DEBUG
int test_ffs_fls()
{
	/* Verify ffs/fls work properly. */
	int rv = 0;
	rv += (tlsf_ffs(0) == -1) ? 0 : 0x1;
	rv += (tlsf_fls(0) == -1) ? 0 : 0x2;
	rv += (tlsf_ffs(1) == 0) ? 0 : 0x4;
	rv += (tlsf_fls(1) == 0) ? 0 : 0x8;
	rv += (tlsf_ffs(0x80000000) == 31) ? 0 : 0x10;
	rv += (tlsf_ffs(0x80008000) == 15) ? 0 : 0x20;
	rv += (tlsf_fls(0x80000008) == 31) ? 0 : 0x40;
	rv += (tlsf_fls(0x7FFFFFFF) == 30) ? 0 : 0x80;

#if defined (TLSF_64BIT)
	rv += (tlsf_fls_sizet(0x80000000) == 31) ? 0 : 0x100;
	rv += (tlsf_fls_sizet(0x100000000) == 32) ? 0 : 0x200;
	rv += (tlsf_fls_sizet(0xffffffffffffffff) == 63) ? 0 : 0x400;
#endif

	if (rv)
	{
		printf("test_ffs_fls: %x ffs/fls tests failed.\n", rv);
	}
	return rv;
}
#endif

tlsf_t tlsf_create(void* mem)
{
#if _DEBUG
	if (test_ffs_fls())
	{
		return 0;
	}
#endif

	if (((tlsfptr_t)mem % ALIGN_SIZE) != 0)
	{
		printf("tlsf_create: Memory must be aligned to %u bytes.\n",
			(unsigned int)ALIGN_SIZE);
		return 0;
	}

	control_construct(tlsf_cast(control_t*, mem));

	return tlsf_cast(tlsf_t, mem);
}

tlsf_t tlsf_create_with_pool(void* mem, size_t bytes)
{
	tlsf_t tlsf = tlsf_create(mem);
	tlsf_add_pool(tlsf, (char*)mem + tlsf_size(), bytes - tlsf_size());
	return tlsf;
}

void tlsf_destroy(tlsf_t tlsf)
{
	/* Nothing to do. */
	(void)tlsf;
}

pool_t tlsf_get_pool(tlsf_t tlsf)
{
	return tlsf_cast(pool_t, (char*)tlsf + tlsf_size());
}

void* tlsf_malloc(tlsf_t tlsf, size_t size)
{
	control_t* control = tlsf_cast(control_t*, tlsf);
	const size_t adjust = adjust_request_size(size, ALIGN_SIZE);
	block_header_t* block = block_locate_free(control, adjust);
	return block_prepare_used(control, block, adjust);
}

void* tlsf_memalign(tlsf_t tlsf, size_t align, size_t size)
{
	control_t* control = tlsf_cast(control_t*, tlsf);
	const size_t adjust = adjust_request_size(size, ALIGN_SIZE);

	/*
	** We must allocate an additional minimum block size bytes so that if
	** our free block will leave an alignment gap which is smaller, we can
	** trim a leading free block and release it back to the pool. We must
	** do this because the previous physical block is in use, therefore
	** the prev_phys_block field is not valid, and we can't simply adjust
	** the size of that block.
	*/
	const size_t gap_minimum = sizeof(block_header_t);
	const size_t size_with_gap = adjust_request_size(adjust + align + gap_minimum, align);

	/*
	** If alignment is less than or equals base alignment, we're done.
	** If we requested 0 bytes, return null, as tlsf_malloc(0) does.
	*/
	const size_t aligned_size = (adjust && align > ALIGN_SIZE) ? size_with_gap : adjust;

	block_header_t* block = block_locate_free(control, aligned_size);

	/* This can't be a static assert. */
	tlsf_assert(sizeof(block_header_t) == block_size_min + block_header_overhead);

	if (block)
	{
		void* ptr = block_to_ptr(block);
		void* aligned = align_ptr(ptr, align);
		size_t gap = tlsf_cast(size_t,
			tlsf_cast(tlsfptr_t, aligned) - tlsf_cast(tlsfptr_t, ptr));

		/* If gap size is too small, offset to next aligned boundary. */
		if (gap && gap < gap_minimum)
		{
			const size_t gap_remain = gap_minimum - gap;
			const size_t offset = tlsf_max(gap_remain, align);
			const void* next_aligned = tlsf_cast(void*,
				tlsf_cast(tlsfptr_t, aligned) + offset);

			aligned = align_ptr(next_aligned, align);
			gap = tlsf_cast(size_t,
				tlsf_cast(tlsfptr_t, aligned) - tlsf_cast(tlsfptr_t, ptr));
		}

		if (gap)
		{
			tlsf_assert(gap >= gap_minimum && "gap size too small");
			block = block_trim_free_leading(control, block, gap);
		}
	}

	return block_prepare_used(control, block, adjust);
}

void tlsf_free(tlsf_t tlsf, void* ptr)
{
	/* Don't attempt to free a NULL pointer. */
	if (ptr)
	{
		control_t* control = tlsf_cast(control_t*, tlsf);
		block_header_t* block = block_from_ptr(ptr);
		tlsf_assert(!block_is_free(block) && "block already marked as free");
		block_mark_as_free(block);
		block = block_merge_prev(control, block);
		block = block_merge_next(control, block);
		block_insert(control, block);
	}
}

/*
** The TLSF block information provides us with enough information to
** provide a reasonably intelligent implementation of realloc, growing or
** shrinking the currently allocated block as required.
**
** This routine handles the somewhat esoteric edge cases of realloc:
** - a non-zero size with a null pointer will behave like malloc
** - a zero size with a non-null pointer will behave like free
** - a request that cannot be satisfied will leave the original buffer
**   untouched
** - an extended buffer size will leave the newly-allocated area with
**   contents undefined
*/
void* tlsf_realloc(tlsf_t tlsf, void* ptr, size_t size)
{
	control_t* control = tlsf_cast(control_t*, tlsf);
	void* p = 0;

	/* Zero-size requests are treated as free. */
	if (ptr && size == 0)
	{
		tlsf_free(tlsf, ptr);
	}
	/* Requests with NULL pointers are treated as malloc. */
	else if (!ptr)
	{
		p = tlsf_malloc(tlsf, size);
	}
	else
	{
		block_header_t* block = block_from_ptr(ptr);
		block_header_t* next = block_next(block);

		const size_t cursize = block_size(block);
		const size_t combined = cursize + block_size(next) + block_header_overhead;
		const size_t adjust = adjust_request_size(size, ALIGN_SIZE);

		tlsf_assert(!block_is_free(block) && "block already marked as free");

		/*
		** If the next block is used, or when combined with the current
		** block, does not offer enough space, we must reallocate and copy.
		*/
		if (adjust > cursize && (!block_is_free(next) || adjust > combined))
		{
			p = tlsf_malloc(tlsf, size);
			if (p)
			{
				const size_t minsize = tlsf_min(cursize, size);
				memcpy(p, ptr, minsize);
				tlsf_free(tlsf, ptr);
			}
		}
		else
		{
			/* Do we need to expand to the next block? */
			if (adjust > cursize)
			{
				block_merge_next(control, block);
				block_mark_as_used(block);
			}

			/* Trim the resulting block and return the original pointer. */
			block_trim_used(control, block, adjust);
			p = ptr;
		}
	}

	return p;
}
#pragma endregion TLSF_C

#define TLSF_POOL_MB 64
#define TLSF_POOL_BYTES (TLSF_POOL_MB * 1024 * 1024)

alignas(8) static uint8_t tlsf_pool_buffer[TLSF_POOL_BYTES];
static tlsf_t tlsf_instance = NULL;

static inline void ensure_tlsf_initialized(void) {
	if (tlsf_instance == NULL) {
		tlsf_instance = tlsf_create_with_pool(tlsf_pool_buffer, TLSF_POOL_BYTES);
		if (tlsf_instance == NULL) {
			ERROR("tlsf_create_with_pool failed");
		}
	}
}

void* mymalloc(size_t size) {
	if (size == 0) {
		return NULL;
	}
	ensure_tlsf_initialized();

	void* ptr = tlsf_malloc(tlsf_instance, size);
	if (ptr == NULL) {
		ERROR("tlsf_malloc out of memory (requested size %zu)", size);
		myerrno = ENOMEM;
	}
	return ptr;
}

void myfree(void* p) {
	if (p == NULL) {
		return;
	}
	// If myfree is ever called before any mymalloc, ensure_tlsf_initialized avoids a NULL handle
	ensure_tlsf_initialized();
	tlsf_free(tlsf_instance, p);
}

void* myrealloc(void* ptr, size_t size) {
	if (ptr == NULL) {
		return mymalloc(size);
	}
	if (size == 0) {
		myfree(ptr);
		return NULL;
	}
	ensure_tlsf_initialized();

	void* new_ptr = tlsf_realloc(tlsf_instance, ptr, size);
	if (new_ptr == NULL) {
		ERROR("tlsf_realloc out of memory (requested size %zu)", size);
		myerrno = ENOMEM;
	}
	return new_ptr;
}
#endif

#if CHOSEN_MALLOC_IMPL == MALLOC_IMPL_DLMALLOC
// https://claude.ai/share/ea6600bb-7be7-42e8-833c-7da84f7b2385

#define ONLY_MSPACES 1
#define HAVE_MMAP 0
#define HAVE_MREMAP 0
#define HAVE_MORECORE 0
#define USE_LOCKS 0
#define NO_MALLINFO 1
#define MALLOC_FAILURE_ACTION /* nothing */

// https://gee.cs.oswego.edu/pub/misc/malloc.c
#pragma region DLMALLOC_C
/*
Copyright 2023 Doug Lea

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

* Version 2.8.6 Wed Aug 29 06:57:58 2012  Doug Lea
  Re-licensed 25 Sep 2023 with MIT-0 replacing obsolete CC0
  See https://opensource.org/license/mit-0/

* Quickstart

  This library is all in one file to simplify the most common usage:
  ftp it, compile it (-O3), and link it into another program. All of
  the compile-time options default to reasonable values for use on
  most platforms.  You might later want to step through various
  compile-time and dynamic tuning options.

  For convenience, an include file for code using this malloc is at:
     ftp://gee.cs.oswego.edu/pub/misc/malloc-2.8.6.h
  You don't really need this .h file unless you call functions not
  defined in your system include files.  The .h file contains only the
  excerpts from this file needed for using this malloc on ANSI C/C++
  systems, so long as you haven't changed compile-time options about
  naming and tuning parameters.  If you do, then you can create your
  own malloc.h that does include all settings by cutting at the point
  indicated below. Note that you may already by default be using a C
  library containing a malloc that is based on some version of this
  malloc (for example in linux). You might still want to use the one
  in this file to customize settings or to avoid overheads associated
  with library versions.

* Vital statistics:

  Supported pointer/size_t representation:       4 or 8 bytes
       size_t MUST be an unsigned type of the same width as
       pointers. (If you are using an ancient system that declares
       size_t as a signed type, or need it to be a different width
       than pointers, you can use a previous release of this malloc
       (e.g. 2.7.2) supporting these.)

  Alignment:                                     8 bytes (minimum)
       This suffices for nearly all current machines and C compilers.
       However, you can define MALLOC_ALIGNMENT to be wider than this
       if necessary (up to 128bytes), at the expense of using more space.

  Minimum overhead per allocated chunk:   4 or  8 bytes (if 4byte sizes)
                                          8 or 16 bytes (if 8byte sizes)
       Each malloced chunk has a hidden word of overhead holding size
       and status information, and additional cross-check word
       if FOOTERS is defined.

  Minimum allocated size: 4-byte ptrs:  16 bytes    (including overhead)
                          8-byte ptrs:  32 bytes    (including overhead)

       Even a request for zero bytes (i.e., malloc(0)) returns a
       pointer to something of the minimum allocatable size.
       The maximum overhead wastage (i.e., number of extra bytes
       allocated than were requested in malloc) is less than or equal
       to the minimum size, except for requests >= mmap_threshold that
       are serviced via mmap(), where the worst case wastage is about
       32 bytes plus the remainder from a system page (the minimal
       mmap unit); typically 4096 or 8192 bytes.

  Security: static-safe; optionally more or less
       The "security" of malloc refers to the ability of malicious
       code to accentuate the effects of errors (for example, freeing
       space that is not currently malloc'ed or overwriting past the
       ends of chunks) in code that calls malloc.  This malloc
       guarantees not to modify any memory locations below the base of
       heap, i.e., static variables, even in the presence of usage
       errors.  The routines additionally detect most improper frees
       and reallocs.  All this holds as long as the static bookkeeping
       for malloc itself is not corrupted by some other means.  This
       is only one aspect of security -- these checks do not, and
       cannot, detect all possible programming errors.

       If FOOTERS is defined nonzero, then each allocated chunk
       carries an additional check word to verify that it was malloced
       from its space.  These check words are the same within each
       execution of a program using malloc, but differ across
       executions, so externally crafted fake chunks cannot be
       freed. This improves security by rejecting frees/reallocs that
       could corrupt heap memory, in addition to the checks preventing
       writes to statics that are always on.  This may further improve
       security at the expense of time and space overhead.  (Note that
       FOOTERS may also be worth using with MSPACES.)

       By default detected errors cause the program to abort (calling
       "abort()"). You can override this to instead proceed past
       errors by defining PROCEED_ON_ERROR.  In this case, a bad free
       has no effect, and a malloc that encounters a bad address
       caused by user overwrites will ignore the bad address by
       dropping pointers and indices to all known memory. This may
       be appropriate for programs that should continue if at all
       possible in the face of programming errors, although they may
       run out of memory because dropped memory is never reclaimed.

       If you don't like either of these options, you can define
       CORRUPTION_ERROR_ACTION and USAGE_ERROR_ACTION to do anything
       else. And if if you are sure that your program using malloc has
       no errors or vulnerabilities, you can define INSECURE to 1,
       which might (or might not) provide a small performance improvement.

       It is also possible to limit the maximum total allocatable
       space, using malloc_set_footprint_limit. This is not
       designed as a security feature in itself (calls to set limits
       are not screened or privileged), but may be useful as one
       aspect of a secure implementation.

  Thread-safety: NOT thread-safe unless USE_LOCKS defined non-zero
       When USE_LOCKS is defined, each public call to malloc, free,
       etc is surrounded with a lock. By default, this uses a plain
       pthread mutex, win32 critical section, or a spin-lock if if
       available for the platform and not disabled by setting
       USE_SPIN_LOCKS=0.  However, if USE_RECURSIVE_LOCKS is defined,
       recursive versions are used instead (which are not required for
       base functionality but may be needed in layered extensions).
       Using a global lock is not especially fast, and can be a major
       bottleneck.  It is designed only to provide minimal protection
       in concurrent environments, and to provide a basis for
       extensions.  If you are using malloc in a concurrent program,
       consider instead using nedmalloc
       (http://www.nedprod.com/programs/portable/nedmalloc/) or
       ptmalloc (See http://www.malloc.de), which are derived from
       versions of this malloc.

  System requirements: Any combination of MORECORE and/or MMAP/MUNMAP
       This malloc can use unix sbrk or any emulation (invoked using
       the CALL_MORECORE macro) and/or mmap/munmap or any emulation
       (invoked using CALL_MMAP/CALL_MUNMAP) to get and release system
       memory.  On most unix systems, it tends to work best if both
       MORECORE and MMAP are enabled.  On Win32, it uses emulations
       based on VirtualAlloc. It also uses common C library functions
       like memset.

  Compliance: I believe it is compliant with the Single Unix Specification
       (See http://www.unix.org). Also SVID/XPG, ANSI C, and probably
       others as well.

* Overview of algorithms

  This is not the fastest, most space-conserving, most portable, or
  most tunable malloc ever written. However it is among the fastest
  while also being among the most space-conserving, portable and
  tunable.  Consistent balance across these factors results in a good
  general-purpose allocator for malloc-intensive programs.

  In most ways, this malloc is a best-fit allocator. Generally, it
  chooses the best-fitting existing chunk for a request, with ties
  broken in approximately least-recently-used order. (This strategy
  normally maintains low fragmentation.) However, for requests less
  than 256bytes, it deviates from best-fit when there is not an
  exactly fitting available chunk by preferring to use space adjacent
  to that used for the previous small request, as well as by breaking
  ties in approximately most-recently-used order. (These enhance
  locality of series of small allocations.)  And for very large requests
  (>= 256Kb by default), it relies on system memory mapping
  facilities, if supported.  (This helps avoid carrying around and
  possibly fragmenting memory used only for large chunks.)

  All operations (except malloc_stats and mallinfo) have execution
  times that are bounded by a constant factor of the number of bits in
  a size_t, not counting any clearing in calloc or copying in realloc,
  or actions surrounding MORECORE and MMAP that have times
  proportional to the number of non-contiguous regions returned by
  system allocation routines, which is often just 1. In real-time
  applications, you can optionally suppress segment traversals using
  NO_SEGMENT_TRAVERSAL, which assures bounded execution even when
  system allocators return non-contiguous spaces, at the typical
  expense of carrying around more memory and increased fragmentation.

  The implementation is not very modular and seriously overuses
  macros. Perhaps someday all C compilers will do as good a job
  inlining modular code as can now be done by brute-force expansion,
  but now, enough of them seem not to.

  Some compilers issue a lot of warnings about code that is
  dead/unreachable only on some platforms, and also about intentional
  uses of negation on unsigned types. All known cases of each can be
  ignored.

  For a longer but out of date high-level description, see
     http://gee.cs.oswego.edu/dl/html/malloc.html

* MSPACES
  If MSPACES is defined, then in addition to malloc, free, etc.,
  this file also defines mspace_malloc, mspace_free, etc. These
  are versions of malloc routines that take an "mspace" argument
  obtained using create_mspace, to control all internal bookkeeping.
  If ONLY_MSPACES is defined, only these versions are compiled.
  So if you would like to use this allocator for only some allocations,
  and your system malloc for others, you can compile with
  ONLY_MSPACES and then do something like...
    static mspace mymspace = create_mspace(0,0); // for example
    #define mymalloc(bytes)  mspace_malloc(mymspace, bytes)

  (Note: If you only need one instance of an mspace, you can instead
  use "USE_DL_PREFIX" to relabel the global malloc.)

  You can similarly create thread-local allocators by storing
  mspaces as thread-locals. For example:
    static __thread mspace tlms = 0;
    void*  tlmalloc(size_t bytes) {
      if (tlms == 0) tlms = create_mspace(0, 0);
      return mspace_malloc(tlms, bytes);
    }
    void  tlfree(void* mem) { mspace_free(tlms, mem); }

  Unless FOOTERS is defined, each mspace is completely independent.
  You cannot allocate from one and free to another (although
  conformance is only weakly checked, so usage errors are not always
  caught). If FOOTERS is defined, then each chunk carries around a tag
  indicating its originating mspace, and frees are directed to their
  originating spaces. Normally, this requires use of locks.

 -------------------------  Compile-time options ---------------------------

Be careful in setting #define values for numerical constants of type
size_t. On some systems, literal values are not automatically extended
to size_t precision unless they are explicitly casted. You can also
use the symbolic values MAX_SIZE_T, SIZE_T_ONE, etc below.

WIN32                    default: defined if _WIN32 defined
  Defining WIN32 sets up defaults for MS environment and compilers.
  Otherwise defaults are for unix. Beware that there seem to be some
  cases where this malloc might not be a pure drop-in replacement for
  Win32 malloc: Random-looking failures from Win32 GDI API's (eg;
  SetDIBits()) may be due to bugs in some video driver implementations
  when pixel buffers are malloc()ed, and the region spans more than
  one VirtualAlloc()ed region. Because dlmalloc uses a small (64Kb)
  default granularity, pixel buffers may straddle virtual allocation
  regions more often than when using the Microsoft allocator.  You can
  avoid this by using VirtualAlloc() and VirtualFree() for all pixel
  buffers rather than using malloc().  If this is not possible,
  recompile this malloc with a larger DEFAULT_GRANULARITY. Note:
  in cases where MSC and gcc (cygwin) are known to differ on WIN32,
  conditions use _MSC_VER to distinguish them.

DLMALLOC_EXPORT       default: extern
  Defines how public APIs are declared. If you want to export via a
  Windows DLL, you might define this as
    #define DLMALLOC_EXPORT extern  __declspec(dllexport)
  If you want a POSIX ELF shared object, you might use
    #define DLMALLOC_EXPORT extern __attribute__((visibility("default")))

MALLOC_ALIGNMENT         default: (size_t)(2 * sizeof(void *))
  Controls the minimum alignment for malloc'ed chunks.  It must be a
  power of two and at least 8, even on machines for which smaller
  alignments would suffice. It may be defined as larger than this
  though. Note however that code and data structures are optimized for
  the case of 8-byte alignment.

MSPACES                  default: 0 (false)
  If true, compile in support for independent allocation spaces.
  This is only supported if HAVE_MMAP is true.

ONLY_MSPACES             default: 0 (false)
  If true, only compile in mspace versions, not regular versions.

USE_LOCKS                default: 0 (false)
  Causes each call to each public routine to be surrounded with
  pthread or WIN32 mutex lock/unlock. (If set true, this can be
  overridden on a per-mspace basis for mspace versions.) If set to a
  non-zero value other than 1, locks are used, but their
  implementation is left out, so lock functions must be supplied manually,
  as described below.

USE_SPIN_LOCKS           default: 1 iff USE_LOCKS and spin locks available
  If true, uses custom spin locks for locking. This is currently
  supported only gcc >= 4.1, older gccs on x86 platforms, and recent
  MS compilers.  Otherwise, posix locks or win32 critical sections are
  used.

USE_RECURSIVE_LOCKS      default: not defined
  If defined nonzero, uses recursive (aka reentrant) locks, otherwise
  uses plain mutexes. This is not required for malloc proper, but may
  be needed for layered allocators such as nedmalloc.

LOCK_AT_FORK            default: not defined
  If defined nonzero, performs pthread_atfork upon initialization
  to initialize child lock while holding parent lock. The implementation
  assumes that pthread locks (not custom locks) are being used. In other
  cases, you may need to customize the implementation.

FOOTERS                  default: 0
  If true, provide extra checking and dispatching by placing
  information in the footers of allocated chunks. This adds
  space and time overhead.

INSECURE                 default: 0
  If true, omit checks for usage errors and heap space overwrites.

USE_DL_PREFIX            default: NOT defined
  Causes compiler to prefix all public routines with the string 'dl'.
  This can be useful when you only want to use this malloc in one part
  of a program, using your regular system malloc elsewhere.

MALLOC_INSPECT_ALL       default: NOT defined
  If defined, compiles malloc_inspect_all and mspace_inspect_all, that
  perform traversal of all heap space.  Unless access to these
  functions is otherwise restricted, you probably do not want to
  include them in secure implementations.

ABORT                    default: defined as abort()
  Defines how to abort on failed checks.  On most systems, a failed
  check cannot die with an "assert" or even print an informative
  message, because the underlying print routines in turn call malloc,
  which will fail again.  Generally, the best policy is to simply call
  abort(). It's not very useful to do more than this because many
  errors due to overwriting will show up as address faults (null, odd
  addresses etc) rather than malloc-triggered checks, so will also
  abort.  Also, most compilers know that abort() does not return, so
  can better optimize code conditionally calling it.

PROCEED_ON_ERROR           default: defined as 0 (false)
  Controls whether detected bad addresses cause them to bypassed
  rather than aborting. If set, detected bad arguments to free and
  realloc are ignored. And all bookkeeping information is zeroed out
  upon a detected overwrite of freed heap space, thus losing the
  ability to ever return it from malloc again, but enabling the
  application to proceed. If PROCEED_ON_ERROR is defined, the
  static variable malloc_corruption_error_count is compiled in
  and can be examined to see if errors have occurred. This option
  generates slower code than the default abort policy.

DEBUG                    default: NOT defined
  The DEBUG setting is mainly intended for people trying to modify
  this code or diagnose problems when porting to new platforms.
  However, it may also be able to better isolate user errors than just
  using runtime checks.  The assertions in the check routines spell
  out in more detail the assumptions and invariants underlying the
  algorithms.  The checking is fairly extensive, and will slow down
  execution noticeably. Calling malloc_stats or mallinfo with DEBUG
  set will attempt to check every non-mmapped allocated and free chunk
  in the course of computing the summaries.

ABORT_ON_ASSERT_FAILURE   default: defined as 1 (true)
  Debugging assertion failures can be nearly impossible if your
  version of the assert macro causes malloc to be called, which will
  lead to a cascade of further failures, blowing the runtime stack.
  ABORT_ON_ASSERT_FAILURE cause assertions failures to call abort(),
  which will usually make debugging easier.

MALLOC_FAILURE_ACTION     default: sets errno to ENOMEM, or no-op on win32
  The action to take before "return 0" when malloc fails to be able to
  return memory because there is none available.

HAVE_MORECORE             default: 1 (true) unless win32 or ONLY_MSPACES
  True if this system supports sbrk or an emulation of it.

MORECORE                  default: sbrk
  The name of the sbrk-style system routine to call to obtain more
  memory.  See below for guidance on writing custom MORECORE
  functions. The type of the argument to sbrk/MORECORE varies across
  systems.  It cannot be size_t, because it supports negative
  arguments, so it is normally the signed type of the same width as
  size_t (sometimes declared as "intptr_t").  It doesn't much matter
  though. Internally, we only call it with arguments less than half
  the max value of a size_t, which should work across all reasonable
  possibilities, although sometimes generating compiler warnings.

MORECORE_CONTIGUOUS       default: 1 (true) if HAVE_MORECORE
  If true, take advantage of fact that consecutive calls to MORECORE
  with positive arguments always return contiguous increasing
  addresses.  This is true of unix sbrk. It does not hurt too much to
  set it true anyway, since malloc copes with non-contiguities.
  Setting it false when definitely non-contiguous saves time
  and possibly wasted space it would take to discover this though.

MORECORE_CANNOT_TRIM      default: NOT defined
  True if MORECORE cannot release space back to the system when given
  negative arguments. This is generally necessary only if you are
  using a hand-crafted MORECORE function that cannot handle negative
  arguments.

NO_SEGMENT_TRAVERSAL       default: 0
  If non-zero, suppresses traversals of memory segments
  returned by either MORECORE or CALL_MMAP. This disables
  merging of segments that are contiguous, and selectively
  releasing them to the OS if unused, but bounds execution times.

HAVE_MMAP                 default: 1 (true)
  True if this system supports mmap or an emulation of it.  If so, and
  HAVE_MORECORE is not true, MMAP is used for all system
  allocation. If set and HAVE_MORECORE is true as well, MMAP is
  primarily used to directly allocate very large blocks. It is also
  used as a backup strategy in cases where MORECORE fails to provide
  space from system. Note: A single call to MUNMAP is assumed to be
  able to unmap memory that may have be allocated using multiple calls
  to MMAP, so long as they are adjacent.

HAVE_MREMAP               default: 1 on linux, else 0
  If true realloc() uses mremap() to re-allocate large blocks and
  extend or shrink allocation spaces.

MMAP_CLEARS               default: 1 except on WINCE.
  True if mmap clears memory so calloc doesn't need to. This is true
  for standard unix mmap using /dev/zero and on WIN32 except for WINCE.

USE_BUILTIN_FFS            default: 0 (i.e., not used)
  Causes malloc to use the builtin ffs() function to compute indices.
  Some compilers may recognize and intrinsify ffs to be faster than the
  supplied C version. Also, the case of x86 using gcc is special-cased
  to an asm instruction, so is already as fast as it can be, and so
  this setting has no effect. Similarly for Win32 under recent MS compilers.
  (On most x86s, the asm version is only slightly faster than the C version.)

malloc_getpagesize         default: derive from system includes, or 4096.
  The system page size. To the extent possible, this malloc manages
  memory from the system in page-size units.  This may be (and
  usually is) a function rather than a constant. This is ignored
  if WIN32, where page size is determined using getSystemInfo during
  initialization.

USE_DEV_RANDOM             default: 0 (i.e., not used)
  Causes malloc to use /dev/random to initialize secure magic seed for
  stamping footers. Otherwise, the current time is used.

NO_MALLINFO                default: 0
  If defined, don't compile "mallinfo". This can be a simple way
  of dealing with mismatches between system declarations and
  those in this file.

MALLINFO_FIELD_TYPE        default: size_t
  The type of the fields in the mallinfo struct. This was originally
  defined as "int" in SVID etc, but is more usefully defined as
  size_t. The value is used only if  HAVE_USR_INCLUDE_MALLOC_H is not set

NO_MALLOC_STATS            default: 0
  If defined, don't compile "malloc_stats". This avoids calls to
  fprintf and bringing in stdio dependencies you might not want.

REALLOC_ZERO_BYTES_FREES    default: not defined
  This should be set if a call to realloc with zero bytes should
  be the same as a call to free. Some people think it should. Otherwise,
  since this malloc returns a unique pointer for malloc(0), so does
  realloc(p, 0).

LACKS_UNISTD_H, LACKS_FCNTL_H, LACKS_SYS_PARAM_H, LACKS_SYS_MMAN_H
LACKS_STRINGS_H, LACKS_STRING_H, LACKS_SYS_TYPES_H,  LACKS_ERRNO_H
LACKS_STDLIB_H LACKS_SCHED_H LACKS_TIME_H  default: NOT defined unless on WIN32
  Define these if your system does not have these header files.
  You might need to manually insert some of the declarations they provide.

DEFAULT_GRANULARITY        default: page size if MORECORE_CONTIGUOUS,
                                system_info.dwAllocationGranularity in WIN32,
                                otherwise 64K.
      Also settable using mallopt(M_GRANULARITY, x)
  The unit for allocating and deallocating memory from the system.  On
  most systems with contiguous MORECORE, there is no reason to
  make this more than a page. However, systems with MMAP tend to
  either require or encourage larger granularities.  You can increase
  this value to prevent system allocation functions to be called so
  often, especially if they are slow.  The value must be at least one
  page and must be a power of two.  Setting to 0 causes initialization
  to either page size or win32 region size.  (Note: In previous
  versions of malloc, the equivalent of this option was called
  "TOP_PAD")

DEFAULT_TRIM_THRESHOLD    default: 2MB
      Also settable using mallopt(M_TRIM_THRESHOLD, x)
  The maximum amount of unused top-most memory to keep before
  releasing via malloc_trim in free().  Automatic trimming is mainly
  useful in long-lived programs using contiguous MORECORE.  Because
  trimming via sbrk can be slow on some systems, and can sometimes be
  wasteful (in cases where programs immediately afterward allocate
  more large chunks) the value should be high enough so that your
  overall system performance would improve by releasing this much
  memory.  As a rough guide, you might set to a value close to the
  average size of a process (program) running on your system.
  Releasing this much memory would allow such a process to run in
  memory.  Generally, it is worth tuning trim thresholds when a
  program undergoes phases where several large chunks are allocated
  and released in ways that can reuse each other's storage, perhaps
  mixed with phases where there are no such chunks at all. The trim
  value must be greater than page size to have any useful effect.  To
  disable trimming completely, you can set to MAX_SIZE_T. Note that the trick
  some people use of mallocing a huge space and then freeing it at
  program startup, in an attempt to reserve system memory, doesn't
  have the intended effect under automatic trimming, since that memory
  will immediately be returned to the system.

DEFAULT_MMAP_THRESHOLD       default: 256K
      Also settable using mallopt(M_MMAP_THRESHOLD, x)
  The request size threshold for using MMAP to directly service a
  request. Requests of at least this size that cannot be allocated
  using already-existing space will be serviced via mmap.  (If enough
  normal freed space already exists it is used instead.)  Using mmap
  segregates relatively large chunks of memory so that they can be
  individually obtained and released from the host system. A request
  serviced through mmap is never reused by any other request (at least
  not directly; the system may just so happen to remap successive
  requests to the same locations).  Segregating space in this way has
  the benefits that: Mmapped space can always be individually released
  back to the system, which helps keep the system level memory demands
  of a long-lived program low.  Also, mapped memory doesn't become
  `locked' between other chunks, as can happen with normally allocated
  chunks, which means that even trimming via malloc_trim would not
  release them.  However, it has the disadvantage that the space
  cannot be reclaimed, consolidated, and then used to service later
  requests, as happens with normal chunks.  The advantages of mmap
  nearly always outweigh disadvantages for "large" chunks, but the
  value of "large" may vary across systems.  The default is an
  empirically derived value that works well in most systems. You can
  disable mmap by setting to MAX_SIZE_T.

MAX_RELEASE_CHECK_RATE   default: 4095 unless not HAVE_MMAP
  The number of consolidated frees between checks to release
  unused segments when freeing. When using non-contiguous segments,
  especially with multiple mspaces, checking only for topmost space
  doesn't always suffice to trigger trimming. To compensate for this,
  free() will, with a period of MAX_RELEASE_CHECK_RATE (or the
  current number of segments, if greater) try to release unused
  segments to the OS when freeing chunks that result in
  consolidation. The best value for this parameter is a compromise
  between slowing down frees with relatively costly checks that
  rarely trigger versus holding on to unused memory. To effectively
  disable, set to MAX_SIZE_T. This may lead to a very slight speed
  improvement at the expense of carrying around more memory.
*/

/* Version identifier to allow people to support multiple versions */
#ifndef DLMALLOC_VERSION
#define DLMALLOC_VERSION 20806
#endif /* DLMALLOC_VERSION */

#ifndef DLMALLOC_EXPORT
#define DLMALLOC_EXPORT extern
#endif

#ifndef WIN32
#ifdef _WIN32
#define WIN32 1
#endif  /* _WIN32 */
#ifdef _WIN32_WCE
#define LACKS_FCNTL_H
#define WIN32 1
#endif /* _WIN32_WCE */
#endif  /* WIN32 */
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>
#define HAVE_MMAP 1
#define HAVE_MORECORE 0
#define LACKS_UNISTD_H
#define LACKS_SYS_PARAM_H
#define LACKS_SYS_MMAN_H
#define LACKS_STRING_H
#define LACKS_STRINGS_H
#define LACKS_SYS_TYPES_H
#define LACKS_ERRNO_H
#define LACKS_SCHED_H
#ifndef MALLOC_FAILURE_ACTION
#define MALLOC_FAILURE_ACTION
#endif /* MALLOC_FAILURE_ACTION */
#ifndef MMAP_CLEARS
#ifdef _WIN32_WCE /* WINCE reportedly does not clear */
#define MMAP_CLEARS 0
#else
#define MMAP_CLEARS 1
#endif /* _WIN32_WCE */
#endif /*MMAP_CLEARS */
#endif  /* WIN32 */

#if defined(DARWIN) || defined(_DARWIN)
/* Mac OSX docs advise not to use sbrk; it seems better to use mmap */
#ifndef HAVE_MORECORE
#define HAVE_MORECORE 0
#define HAVE_MMAP 1
/* OSX allocators provide 16 byte alignment */
#ifndef MALLOC_ALIGNMENT
#define MALLOC_ALIGNMENT ((size_t)16U)
#endif
#endif  /* HAVE_MORECORE */
#endif  /* DARWIN */

#ifndef LACKS_SYS_TYPES_H
#include <sys/types.h>  /* For size_t */
#endif  /* LACKS_SYS_TYPES_H */

/* The maximum possible size_t value has all bits set */
#define MAX_SIZE_T           (~(size_t)0)

#ifndef USE_LOCKS /* ensure true if spin or recursive locks set */
#define USE_LOCKS  ((defined(USE_SPIN_LOCKS) && USE_SPIN_LOCKS != 0) || \
                    (defined(USE_RECURSIVE_LOCKS) && USE_RECURSIVE_LOCKS != 0))
#endif /* USE_LOCKS */

#if USE_LOCKS /* Spin locks for gcc >= 4.1, older gcc on x86, MSC >= 1310 */
#if ((defined(__GNUC__) &&                                              \
      ((__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 1)) ||      \
       defined(__i386__) || defined(__x86_64__))) ||                    \
     (defined(_MSC_VER) && _MSC_VER>=1310))
#ifndef USE_SPIN_LOCKS
#define USE_SPIN_LOCKS 1
#endif /* USE_SPIN_LOCKS */
#elif USE_SPIN_LOCKS
#error "USE_SPIN_LOCKS defined without implementation"
#endif /* ... locks available... */
#elif !defined(USE_SPIN_LOCKS)
#define USE_SPIN_LOCKS 0
#endif /* USE_LOCKS */

#ifndef ONLY_MSPACES
#define ONLY_MSPACES 0
#endif  /* ONLY_MSPACES */
#ifndef MSPACES
#if ONLY_MSPACES
#define MSPACES 1
#else   /* ONLY_MSPACES */
#define MSPACES 0
#endif  /* ONLY_MSPACES */
#endif  /* MSPACES */
#ifndef MALLOC_ALIGNMENT
#define MALLOC_ALIGNMENT ((size_t)(2 * sizeof(void *)))
#endif  /* MALLOC_ALIGNMENT */
#ifndef FOOTERS
#define FOOTERS 0
#endif  /* FOOTERS */
#ifndef ABORT
#define ABORT  abort()
#endif  /* ABORT */
#ifndef ABORT_ON_ASSERT_FAILURE
#define ABORT_ON_ASSERT_FAILURE 1
#endif  /* ABORT_ON_ASSERT_FAILURE */
#ifndef PROCEED_ON_ERROR
#define PROCEED_ON_ERROR 0
#endif  /* PROCEED_ON_ERROR */

#ifndef INSECURE
#define INSECURE 0
#endif  /* INSECURE */
#ifndef MALLOC_INSPECT_ALL
#define MALLOC_INSPECT_ALL 0
#endif  /* MALLOC_INSPECT_ALL */
#ifndef HAVE_MMAP
#define HAVE_MMAP 1
#endif  /* HAVE_MMAP */
#ifndef MMAP_CLEARS
#define MMAP_CLEARS 1
#endif  /* MMAP_CLEARS */
#ifndef HAVE_MREMAP
#ifdef linux
#define HAVE_MREMAP 1
#define _GNU_SOURCE /* Turns on mremap() definition */
#else   /* linux */
#define HAVE_MREMAP 0
#endif  /* linux */
#endif  /* HAVE_MREMAP */
#ifndef MALLOC_FAILURE_ACTION
#define MALLOC_FAILURE_ACTION  errno = ENOMEM;
#endif  /* MALLOC_FAILURE_ACTION */
#ifndef HAVE_MORECORE
#if ONLY_MSPACES
#define HAVE_MORECORE 0
#else   /* ONLY_MSPACES */
#define HAVE_MORECORE 1
#endif  /* ONLY_MSPACES */
#endif  /* HAVE_MORECORE */
#if !HAVE_MORECORE
#define MORECORE_CONTIGUOUS 0
#else   /* !HAVE_MORECORE */
#define MORECORE_DEFAULT sbrk
#ifndef MORECORE_CONTIGUOUS
#define MORECORE_CONTIGUOUS 1
#endif  /* MORECORE_CONTIGUOUS */
#endif  /* HAVE_MORECORE */
#ifndef DEFAULT_GRANULARITY
#if (MORECORE_CONTIGUOUS || defined(WIN32))
#define DEFAULT_GRANULARITY (0)  /* 0 means to compute in init_mparams */
#else   /* MORECORE_CONTIGUOUS */
#define DEFAULT_GRANULARITY ((size_t)64U * (size_t)1024U)
#endif  /* MORECORE_CONTIGUOUS */
#endif  /* DEFAULT_GRANULARITY */
#ifndef DEFAULT_TRIM_THRESHOLD
#ifndef MORECORE_CANNOT_TRIM
#define DEFAULT_TRIM_THRESHOLD ((size_t)2U * (size_t)1024U * (size_t)1024U)
#else   /* MORECORE_CANNOT_TRIM */
#define DEFAULT_TRIM_THRESHOLD MAX_SIZE_T
#endif  /* MORECORE_CANNOT_TRIM */
#endif  /* DEFAULT_TRIM_THRESHOLD */
#ifndef DEFAULT_MMAP_THRESHOLD
#if HAVE_MMAP
#define DEFAULT_MMAP_THRESHOLD ((size_t)256U * (size_t)1024U)
#else   /* HAVE_MMAP */
#define DEFAULT_MMAP_THRESHOLD MAX_SIZE_T
#endif  /* HAVE_MMAP */
#endif  /* DEFAULT_MMAP_THRESHOLD */
#ifndef MAX_RELEASE_CHECK_RATE
#if HAVE_MMAP
#define MAX_RELEASE_CHECK_RATE 4095
#else
#define MAX_RELEASE_CHECK_RATE MAX_SIZE_T
#endif /* HAVE_MMAP */
#endif /* MAX_RELEASE_CHECK_RATE */
#ifndef USE_BUILTIN_FFS
#define USE_BUILTIN_FFS 0
#endif  /* USE_BUILTIN_FFS */
#ifndef USE_DEV_RANDOM
#define USE_DEV_RANDOM 0
#endif  /* USE_DEV_RANDOM */
#ifndef NO_MALLINFO
#define NO_MALLINFO 0
#endif  /* NO_MALLINFO */
#ifndef MALLINFO_FIELD_TYPE
#define MALLINFO_FIELD_TYPE size_t
#endif  /* MALLINFO_FIELD_TYPE */
#ifndef NO_MALLOC_STATS
#define NO_MALLOC_STATS 0
#endif  /* NO_MALLOC_STATS */
#ifndef NO_SEGMENT_TRAVERSAL
#define NO_SEGMENT_TRAVERSAL 0
#endif /* NO_SEGMENT_TRAVERSAL */

/*
  mallopt tuning options.  SVID/XPG defines four standard parameter
  numbers for mallopt, normally defined in malloc.h.  None of these
  are used in this malloc, so setting them has no effect. But this
  malloc does support the following options.
*/

#define M_TRIM_THRESHOLD     (-1)
#define M_GRANULARITY        (-2)
#define M_MMAP_THRESHOLD     (-3)

/* ------------------------ Mallinfo declarations ------------------------ */

#if !NO_MALLINFO
/*
  This version of malloc supports the standard SVID/XPG mallinfo
  routine that returns a struct containing usage properties and
  statistics. It should work on any system that has a
  /usr/include/malloc.h defining struct mallinfo.  The main
  declaration needed is the mallinfo struct that is returned (by-copy)
  by mallinfo().  The malloinfo struct contains a bunch of fields that
  are not even meaningful in this version of malloc.  These fields are
  are instead filled by mallinfo() with other numbers that might be of
  interest.

  HAVE_USR_INCLUDE_MALLOC_H should be set if you have a
  /usr/include/malloc.h file that includes a declaration of struct
  mallinfo.  If so, it is included; else a compliant version is
  declared below.  These must be precisely the same for mallinfo() to
  work.  The original SVID version of this struct, defined on most
  systems with mallinfo, declares all fields as ints. But some others
  define as unsigned long. If your system defines the fields using a
  type of different width than listed here, you MUST #include your
  system version and #define HAVE_USR_INCLUDE_MALLOC_H.
*/

/* #define HAVE_USR_INCLUDE_MALLOC_H */

#ifdef HAVE_USR_INCLUDE_MALLOC_H
#include "/usr/include/malloc.h"
#else /* HAVE_USR_INCLUDE_MALLOC_H */
#ifndef STRUCT_MALLINFO_DECLARED
/* HP-UX (and others?) redefines mallinfo unless _STRUCT_MALLINFO is defined */
#define _STRUCT_MALLINFO
#define STRUCT_MALLINFO_DECLARED 1
struct mallinfo {
  MALLINFO_FIELD_TYPE arena;    /* non-mmapped space allocated from system */
  MALLINFO_FIELD_TYPE ordblks;  /* number of free chunks */
  MALLINFO_FIELD_TYPE smblks;   /* always 0 */
  MALLINFO_FIELD_TYPE hblks;    /* always 0 */
  MALLINFO_FIELD_TYPE hblkhd;   /* space in mmapped regions */
  MALLINFO_FIELD_TYPE usmblks;  /* maximum total allocated space */
  MALLINFO_FIELD_TYPE fsmblks;  /* always 0 */
  MALLINFO_FIELD_TYPE uordblks; /* total allocated space */
  MALLINFO_FIELD_TYPE fordblks; /* total free space */
  MALLINFO_FIELD_TYPE keepcost; /* releasable (via malloc_trim) space */
};
#endif /* STRUCT_MALLINFO_DECLARED */
#endif /* HAVE_USR_INCLUDE_MALLOC_H */
#endif /* NO_MALLINFO */

/*
  Try to persuade compilers to inline. The most critical functions for
  inlining are defined as macros, so these aren't used for them.
*/

#ifndef FORCEINLINE
  #if defined(__GNUC__)
#define FORCEINLINE __inline __attribute__ ((always_inline))
  #elif defined(_MSC_VER)
    #define FORCEINLINE __forceinline
  #endif
#endif
#ifndef NOINLINE
  #if defined(__GNUC__)
    #define NOINLINE __attribute__ ((noinline))
  #elif defined(_MSC_VER)
    #define NOINLINE __declspec(noinline)
  #else
    #define NOINLINE
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#ifndef FORCEINLINE
 #define FORCEINLINE inline
#endif
#endif /* __cplusplus */
#ifndef FORCEINLINE
 #define FORCEINLINE
#endif

#if !ONLY_MSPACES

/* ------------------- Declarations of public routines ------------------- */

#ifndef USE_DL_PREFIX
#define dlcalloc               calloc
#define dlfree                 free
#define dlmalloc               malloc
#define dlmemalign             memalign
#define dlposix_memalign       posix_memalign
#define dlrealloc              realloc
#define dlrealloc_in_place     realloc_in_place
#define dlvalloc               valloc
#define dlpvalloc              pvalloc
#define dlmallinfo             mallinfo
#define dlmallopt              mallopt
#define dlmalloc_trim          malloc_trim
#define dlmalloc_stats         malloc_stats
#define dlmalloc_usable_size   malloc_usable_size
#define dlmalloc_footprint     malloc_footprint
#define dlmalloc_max_footprint malloc_max_footprint
#define dlmalloc_footprint_limit malloc_footprint_limit
#define dlmalloc_set_footprint_limit malloc_set_footprint_limit
#define dlmalloc_inspect_all   malloc_inspect_all
#define dlindependent_calloc   independent_calloc
#define dlindependent_comalloc independent_comalloc
#define dlbulk_free            bulk_free
#endif /* USE_DL_PREFIX */

/*
  malloc(size_t n)
  Returns a pointer to a newly allocated chunk of at least n bytes, or
  null if no space is available, in which case errno is set to ENOMEM
  on ANSI C systems.

  If n is zero, malloc returns a minimum-sized chunk. (The minimum
  size is 16 bytes on most 32bit systems, and 32 bytes on 64bit
  systems.)  Note that size_t is an unsigned type, so calls with
  arguments that would be negative if signed are interpreted as
  requests for huge amounts of space, which will often fail. The
  maximum supported value of n differs across systems, but is in all
  cases less than the maximum representable value of a size_t.
*/
DLMALLOC_EXPORT void* dlmalloc(size_t);

/*
  free(void* p)
  Releases the chunk of memory pointed to by p, that had been previously
  allocated using malloc or a related routine such as realloc.
  It has no effect if p is null. If p was not malloced or already
  freed, free(p) will by default cause the current program to abort.
*/
DLMALLOC_EXPORT void  dlfree(void*);

/*
  calloc(size_t n_elements, size_t element_size);
  Returns a pointer to n_elements * element_size bytes, with all locations
  set to zero.
*/
DLMALLOC_EXPORT void* dlcalloc(size_t, size_t);

/*
  realloc(void* p, size_t n)
  Returns a pointer to a chunk of size n that contains the same data
  as does chunk p up to the minimum of (n, p's size) bytes, or null
  if no space is available.

  The returned pointer may or may not be the same as p. The algorithm
  prefers extending p in most cases when possible, otherwise it
  employs the equivalent of a malloc-copy-free sequence.

  If p is null, realloc is equivalent to malloc.

  If space is not available, realloc returns null, errno is set (if on
  ANSI) and p is NOT freed.

  if n is for fewer bytes than already held by p, the newly unused
  space is lopped off and freed if possible.  realloc with a size
  argument of zero (re)allocates a minimum-sized chunk.

  The old unix realloc convention of allowing the last-free'd chunk
  to be used as an argument to realloc is not supported.
*/
DLMALLOC_EXPORT void* dlrealloc(void*, size_t);

/*
  realloc_in_place(void* p, size_t n)
  Resizes the space allocated for p to size n, only if this can be
  done without moving p (i.e., only if there is adjacent space
  available if n is greater than p's current allocated size, or n is
  less than or equal to p's size). This may be used instead of plain
  realloc if an alternative allocation strategy is needed upon failure
  to expand space; for example, reallocation of a buffer that must be
  memory-aligned or cleared. You can use realloc_in_place to trigger
  these alternatives only when needed.

  Returns p if successful; otherwise null.
*/
DLMALLOC_EXPORT void* dlrealloc_in_place(void*, size_t);

/*
  memalign(size_t alignment, size_t n);
  Returns a pointer to a newly allocated chunk of n bytes, aligned
  in accord with the alignment argument.

  The alignment argument should be a power of two. If the argument is
  not a power of two, the nearest greater power is used.
  8-byte alignment is guaranteed by normal malloc calls, so don't
  bother calling memalign with an argument of 8 or less.

  Overreliance on memalign is a sure way to fragment space.
*/
DLMALLOC_EXPORT void* dlmemalign(size_t, size_t);

/*
  int posix_memalign(void** pp, size_t alignment, size_t n);
  Allocates a chunk of n bytes, aligned in accord with the alignment
  argument. Differs from memalign only in that it (1) assigns the
  allocated memory to *pp rather than returning it, (2) fails and
  returns EINVAL if the alignment is not a power of two (3) fails and
  returns ENOMEM if memory cannot be allocated.
*/
DLMALLOC_EXPORT int dlposix_memalign(void**, size_t, size_t);

/*
  valloc(size_t n);
  Equivalent to memalign(pagesize, n), where pagesize is the page
  size of the system. If the pagesize is unknown, 4096 is used.
*/
DLMALLOC_EXPORT void* dlvalloc(size_t);

/*
  mallopt(int parameter_number, int parameter_value)
  Sets tunable parameters The format is to provide a
  (parameter-number, parameter-value) pair.  mallopt then sets the
  corresponding parameter to the argument value if it can (i.e., so
  long as the value is meaningful), and returns 1 if successful else
  0.  To workaround the fact that mallopt is specified to use int,
  not size_t parameters, the value -1 is specially treated as the
  maximum unsigned size_t value.

  SVID/XPG/ANSI defines four standard param numbers for mallopt,
  normally defined in malloc.h.  None of these are use in this malloc,
  so setting them has no effect. But this malloc also supports other
  options in mallopt. See below for details.  Briefly, supported
  parameters are as follows (listed defaults are for "typical"
  configurations).

  Symbol            param #  default    allowed param values
  M_TRIM_THRESHOLD     -1   2*1024*1024   any   (-1 disables)
  M_GRANULARITY        -2     page size   any power of 2 >= page size
  M_MMAP_THRESHOLD     -3      256*1024   any   (or 0 if no MMAP support)
*/
DLMALLOC_EXPORT int dlmallopt(int, int);

/*
  malloc_footprint();
  Returns the number of bytes obtained from the system.  The total
  number of bytes allocated by malloc, realloc etc., is less than this
  value. Unlike mallinfo, this function returns only a precomputed
  result, so can be called frequently to monitor memory consumption.
  Even if locks are otherwise defined, this function does not use them,
  so results might not be up to date.
*/
DLMALLOC_EXPORT size_t dlmalloc_footprint(void);

/*
  malloc_max_footprint();
  Returns the maximum number of bytes obtained from the system. This
  value will be greater than current footprint if deallocated space
  has been reclaimed by the system. The peak number of bytes allocated
  by malloc, realloc etc., is less than this value. Unlike mallinfo,
  this function returns only a precomputed result, so can be called
  frequently to monitor memory consumption.  Even if locks are
  otherwise defined, this function does not use them, so results might
  not be up to date.
*/
DLMALLOC_EXPORT size_t dlmalloc_max_footprint(void);

/*
  malloc_footprint_limit();
  Returns the number of bytes that the heap is allowed to obtain from
  the system, returning the last value returned by
  malloc_set_footprint_limit, or the maximum size_t value if
  never set. The returned value reflects a permission. There is no
  guarantee that this number of bytes can actually be obtained from
  the system.
*/
DLMALLOC_EXPORT size_t dlmalloc_footprint_limit();

/*
  malloc_set_footprint_limit();
  Sets the maximum number of bytes to obtain from the system, causing
  failure returns from malloc and related functions upon attempts to
  exceed this value. The argument value may be subject to page
  rounding to an enforceable limit; this actual value is returned.
  Using an argument of the maximum possible size_t effectively
  disables checks. If the argument is less than or equal to the
  current malloc_footprint, then all future allocations that require
  additional system memory will fail. However, invocation cannot
  retroactively deallocate existing used memory.
*/
DLMALLOC_EXPORT size_t dlmalloc_set_footprint_limit(size_t bytes);

#if MALLOC_INSPECT_ALL
/*
  malloc_inspect_all(void(*handler)(void *start,
                                    void *end,
                                    size_t used_bytes,
                                    void* callback_arg),
                      void* arg);
  Traverses the heap and calls the given handler for each managed
  region, skipping all bytes that are (or may be) used for bookkeeping
  purposes.  Traversal does not include include chunks that have been
  directly memory mapped. Each reported region begins at the start
  address, and continues up to but not including the end address.  The
  first used_bytes of the region contain allocated data. If
  used_bytes is zero, the region is unallocated. The handler is
  invoked with the given callback argument. If locks are defined, they
  are held during the entire traversal. It is a bad idea to invoke
  other malloc functions from within the handler.

  For example, to count the number of in-use chunks with size greater
  than 1000, you could write:
  static int count = 0;
  void count_chunks(void* start, void* end, size_t used, void* arg) {
    if (used >= 1000) ++count;
  }
  then:
    malloc_inspect_all(count_chunks, NULL);

  malloc_inspect_all is compiled only if MALLOC_INSPECT_ALL is defined.
*/
DLMALLOC_EXPORT void dlmalloc_inspect_all(void(*handler)(void*, void *, size_t, void*),
                           void* arg);

#endif /* MALLOC_INSPECT_ALL */

#if !NO_MALLINFO
/*
  mallinfo()
  Returns (by copy) a struct containing various summary statistics:

  arena:     current total non-mmapped bytes allocated from system
  ordblks:   the number of free chunks
  smblks:    always zero.
  hblks:     current number of mmapped regions
  hblkhd:    total bytes held in mmapped regions
  usmblks:   the maximum total allocated space. This will be greater
                than current total if trimming has occurred.
  fsmblks:   always zero
  uordblks:  current total allocated space (normal or mmapped)
  fordblks:  total free space
  keepcost:  the maximum number of bytes that could ideally be released
               back to system via malloc_trim. ("ideally" means that
               it ignores page restrictions etc.)

  Because these fields are ints, but internal bookkeeping may
  be kept as longs, the reported values may wrap around zero and
  thus be inaccurate.
*/
DLMALLOC_EXPORT struct mallinfo dlmallinfo(void);
#endif /* NO_MALLINFO */

/*
  independent_calloc(size_t n_elements, size_t element_size, void* chunks[]);

  independent_calloc is similar to calloc, but instead of returning a
  single cleared space, it returns an array of pointers to n_elements
  independent elements that can hold contents of size elem_size, each
  of which starts out cleared, and can be independently freed,
  realloc'ed etc. The elements are guaranteed to be adjacently
  allocated (this is not guaranteed to occur with multiple callocs or
  mallocs), which may also improve cache locality in some
  applications.

  The "chunks" argument is optional (i.e., may be null, which is
  probably the most typical usage). If it is null, the returned array
  is itself dynamically allocated and should also be freed when it is
  no longer needed. Otherwise, the chunks array must be of at least
  n_elements in length. It is filled in with the pointers to the
  chunks.

  In either case, independent_calloc returns this pointer array, or
  null if the allocation failed.  If n_elements is zero and "chunks"
  is null, it returns a chunk representing an array with zero elements
  (which should be freed if not wanted).

  Each element must be freed when it is no longer needed. This can be
  done all at once using bulk_free.

  independent_calloc simplifies and speeds up implementations of many
  kinds of pools.  It may also be useful when constructing large data
  structures that initially have a fixed number of fixed-sized nodes,
  but the number is not known at compile time, and some of the nodes
  may later need to be freed. For example:

  struct Node { int item; struct Node* next; };

  struct Node* build_list() {
    struct Node** pool;
    int n = read_number_of_nodes_needed();
    if (n <= 0) return 0;
    pool = (struct Node**)(independent_calloc(n, sizeof(struct Node), 0);
    if (pool == 0) die();
    // organize into a linked list...
    struct Node* first = pool[0];
    for (i = 0; i < n-1; ++i)
      pool[i]->next = pool[i+1];
    free(pool);     // Can now free the array (or not, if it is needed later)
    return first;
  }
*/
DLMALLOC_EXPORT void** dlindependent_calloc(size_t, size_t, void**);

/*
  independent_comalloc(size_t n_elements, size_t sizes[], void* chunks[]);

  independent_comalloc allocates, all at once, a set of n_elements
  chunks with sizes indicated in the "sizes" array.    It returns
  an array of pointers to these elements, each of which can be
  independently freed, realloc'ed etc. The elements are guaranteed to
  be adjacently allocated (this is not guaranteed to occur with
  multiple callocs or mallocs), which may also improve cache locality
  in some applications.

  The "chunks" argument is optional (i.e., may be null). If it is null
  the returned array is itself dynamically allocated and should also
  be freed when it is no longer needed. Otherwise, the chunks array
  must be of at least n_elements in length. It is filled in with the
  pointers to the chunks.

  In either case, independent_comalloc returns this pointer array, or
  null if the allocation failed.  If n_elements is zero and chunks is
  null, it returns a chunk representing an array with zero elements
  (which should be freed if not wanted).

  Each element must be freed when it is no longer needed. This can be
  done all at once using bulk_free.

  independent_comallac differs from independent_calloc in that each
  element may have a different size, and also that it does not
  automatically clear elements.

  independent_comalloc can be used to speed up allocation in cases
  where several structs or objects must always be allocated at the
  same time.  For example:

  struct Head { ... }
  struct Foot { ... }

  void send_message(char* msg) {
    int msglen = strlen(msg);
    size_t sizes[3] = { sizeof(struct Head), msglen, sizeof(struct Foot) };
    void* chunks[3];
    if (independent_comalloc(3, sizes, chunks) == 0)
      die();
    struct Head* head = (struct Head*)(chunks[0]);
    char*        body = (char*)(chunks[1]);
    struct Foot* foot = (struct Foot*)(chunks[2]);
    // ...
  }

  In general though, independent_comalloc is worth using only for
  larger values of n_elements. For small values, you probably won't
  detect enough difference from series of malloc calls to bother.

  Overuse of independent_comalloc can increase overall memory usage,
  since it cannot reuse existing noncontiguous small chunks that
  might be available for some of the elements.
*/
DLMALLOC_EXPORT void** dlindependent_comalloc(size_t, size_t*, void**);

/*
  bulk_free(void* array[], size_t n_elements)
  Frees and clears (sets to null) each non-null pointer in the given
  array.  This is likely to be faster than freeing them one-by-one.
  If footers are used, pointers that have been allocated in different
  mspaces are not freed or cleared, and the count of all such pointers
  is returned.  For large arrays of pointers with poor locality, it
  may be worthwhile to sort this array before calling bulk_free.
*/
DLMALLOC_EXPORT size_t  dlbulk_free(void**, size_t n_elements);

/*
  pvalloc(size_t n);
  Equivalent to valloc(minimum-page-that-holds(n)), that is,
  round up n to nearest pagesize.
 */
DLMALLOC_EXPORT void*  dlpvalloc(size_t);

/*
  malloc_trim(size_t pad);

  If possible, gives memory back to the system (via negative arguments
  to sbrk) if there is unused memory at the `high' end of the malloc
  pool or in unused MMAP segments. You can call this after freeing
  large blocks of memory to potentially reduce the system-level memory
  requirements of a program. However, it cannot guarantee to reduce
  memory. Under some allocation patterns, some large free blocks of
  memory will be locked between two used chunks, so they cannot be
  given back to the system.

  The `pad' argument to malloc_trim represents the amount of free
  trailing space to leave untrimmed. If this argument is zero, only
  the minimum amount of memory to maintain internal data structures
  will be left. Non-zero arguments can be supplied to maintain enough
  trailing space to service future expected allocations without having
  to re-obtain memory from the system.

  Malloc_trim returns 1 if it actually released any memory, else 0.
*/
DLMALLOC_EXPORT int  dlmalloc_trim(size_t);

/*
  malloc_stats();
  Prints on stderr the amount of space obtained from the system (both
  via sbrk and mmap), the maximum amount (which may be more than
  current if malloc_trim and/or munmap got called), and the current
  number of bytes allocated via malloc (or realloc, etc) but not yet
  freed. Note that this is the number of bytes allocated, not the
  number requested. It will be larger than the number requested
  because of alignment and bookkeeping overhead. Because it includes
  alignment wastage as being in use, this figure may be greater than
  zero even when no user-level chunks are allocated.

  The reported current and maximum system memory can be inaccurate if
  a program makes other calls to system memory allocation functions
  (normally sbrk) outside of malloc.

  malloc_stats prints only the most commonly interesting statistics.
  More information can be obtained by calling mallinfo.
*/
DLMALLOC_EXPORT void  dlmalloc_stats(void);

/*
  malloc_usable_size(void* p);

  Returns the number of bytes you can actually use in
  an allocated chunk, which may be more than you requested (although
  often not) due to alignment and minimum size constraints.
  You can use this many bytes without worrying about
  overwriting other allocated objects. This is not a particularly great
  programming practice. malloc_usable_size can be more useful in
  debugging and assertions, for example:

  p = malloc(n);
  assert(malloc_usable_size(p) >= 256);
*/
size_t dlmalloc_usable_size(void*);

#endif /* ONLY_MSPACES */

#if MSPACES

/*
  mspace is an opaque type representing an independent
  region of space that supports mspace_malloc, etc.
*/
typedef void* mspace;

/*
  create_mspace creates and returns a new independent space with the
  given initial capacity, or, if 0, the default granularity size.  It
  returns null if there is no system memory available to create the
  space.  If argument locked is non-zero, the space uses a separate
  lock to control access. The capacity of the space will grow
  dynamically as needed to service mspace_malloc requests.  You can
  control the sizes of incremental increases of this space by
  compiling with a different DEFAULT_GRANULARITY or dynamically
  setting with mallopt(M_GRANULARITY, value).
*/
DLMALLOC_EXPORT mspace create_mspace(size_t capacity, int locked);

/*
  destroy_mspace destroys the given space, and attempts to return all
  of its memory back to the system, returning the total number of
  bytes freed. After destruction, the results of access to all memory
  used by the space become undefined.
*/
DLMALLOC_EXPORT size_t destroy_mspace(mspace msp);

/*
  create_mspace_with_base uses the memory supplied as the initial base
  of a new mspace. Part (less than 128*sizeof(size_t) bytes) of this
  space is used for bookkeeping, so the capacity must be at least this
  large. (Otherwise 0 is returned.) When this initial space is
  exhausted, additional memory will be obtained from the system.
  Destroying this space will deallocate all additionally allocated
  space (if possible) but not the initial base.
*/
DLMALLOC_EXPORT mspace create_mspace_with_base(void* base, size_t capacity, int locked);

/*
  mspace_track_large_chunks controls whether requests for large chunks
  are allocated in their own untracked mmapped regions, separate from
  others in this mspace. By default large chunks are not tracked,
  which reduces fragmentation. However, such chunks are not
  necessarily released to the system upon destroy_mspace.  Enabling
  tracking by setting to true may increase fragmentation, but avoids
  leakage when relying on destroy_mspace to release all memory
  allocated using this space.  The function returns the previous
  setting.
*/
DLMALLOC_EXPORT int mspace_track_large_chunks(mspace msp, int enable);


/*
  mspace_malloc behaves as malloc, but operates within
  the given space.
*/
DLMALLOC_EXPORT void* mspace_malloc(mspace msp, size_t bytes);

/*
  mspace_free behaves as free, but operates within
  the given space.

  If compiled with FOOTERS==1, mspace_free is not actually needed.
  free may be called instead of mspace_free because freed chunks from
  any space are handled by their originating spaces.
*/
DLMALLOC_EXPORT void mspace_free(mspace msp, void* mem);

/*
  mspace_realloc behaves as realloc, but operates within
  the given space.

  If compiled with FOOTERS==1, mspace_realloc is not actually
  needed.  realloc may be called instead of mspace_realloc because
  realloced chunks from any space are handled by their originating
  spaces.
*/
DLMALLOC_EXPORT void* mspace_realloc(mspace msp, void* mem, size_t newsize);

/*
  mspace_calloc behaves as calloc, but operates within
  the given space.
*/
DLMALLOC_EXPORT void* mspace_calloc(mspace msp, size_t n_elements, size_t elem_size);

/*
  mspace_memalign behaves as memalign, but operates within
  the given space.
*/
DLMALLOC_EXPORT void* mspace_memalign(mspace msp, size_t alignment, size_t bytes);

/*
  mspace_independent_calloc behaves as independent_calloc, but
  operates within the given space.
*/
DLMALLOC_EXPORT void** mspace_independent_calloc(mspace msp, size_t n_elements,
                                 size_t elem_size, void* chunks[]);

/*
  mspace_independent_comalloc behaves as independent_comalloc, but
  operates within the given space.
*/
DLMALLOC_EXPORT void** mspace_independent_comalloc(mspace msp, size_t n_elements,
                                   size_t sizes[], void* chunks[]);

/*
  mspace_footprint() returns the number of bytes obtained from the
  system for this space.
*/
DLMALLOC_EXPORT size_t mspace_footprint(mspace msp);

/*
  mspace_max_footprint() returns the peak number of bytes obtained from the
  system for this space.
*/
DLMALLOC_EXPORT size_t mspace_max_footprint(mspace msp);


#if !NO_MALLINFO
/*
  mspace_mallinfo behaves as mallinfo, but reports properties of
  the given space.
*/
DLMALLOC_EXPORT struct mallinfo mspace_mallinfo(mspace msp);
#endif /* NO_MALLINFO */

/*
  malloc_usable_size(void* p) behaves the same as malloc_usable_size;
*/
DLMALLOC_EXPORT size_t mspace_usable_size(const void* mem);

/*
  mspace_malloc_stats behaves as malloc_stats, but reports
  properties of the given space.
*/
DLMALLOC_EXPORT void mspace_malloc_stats(mspace msp);

/*
  mspace_trim behaves as malloc_trim, but
  operates within the given space.
*/
DLMALLOC_EXPORT int mspace_trim(mspace msp, size_t pad);

/*
  An alias for mallopt.
*/
DLMALLOC_EXPORT int mspace_mallopt(int, int);

#endif /* MSPACES */

#ifdef __cplusplus
}  /* end of extern "C" */
#endif /* __cplusplus */

/*
  ========================================================================
  To make a fully customizable malloc.h header file, cut everything
  above this line, put into file malloc.h, edit to suit, and #include it
  on the next line, as well as in programs that use this malloc.
  ========================================================================
*/

/* #include "malloc.h" */

/*------------------------------ internal #includes ---------------------- */

#ifdef _MSC_VER
#pragma warning( disable : 4146 ) /* no "unsigned" warnings */
#endif /* _MSC_VER */
#if !NO_MALLOC_STATS
#include <stdio.h>       /* for printing in malloc_stats */
#endif /* NO_MALLOC_STATS */
#ifndef LACKS_ERRNO_H
#include <errno.h>       /* for MALLOC_FAILURE_ACTION */
#endif /* LACKS_ERRNO_H */
#ifdef DEBUG
#if ABORT_ON_ASSERT_FAILURE
#undef assert
#define assert(x) if(!(x)) ABORT
#else /* ABORT_ON_ASSERT_FAILURE */
#include <assert.h>
#endif /* ABORT_ON_ASSERT_FAILURE */
#else  /* DEBUG */
#ifndef assert
#define assert(x)
#endif
#define DEBUG 0
#endif /* DEBUG */
#if !defined(WIN32) && !defined(LACKS_TIME_H)
#include <time.h>        /* for magic initialization */
#endif /* WIN32 */
#ifndef LACKS_STDLIB_H
#include <stdlib.h>      /* for abort() */
#endif /* LACKS_STDLIB_H */
#ifndef LACKS_STRING_H
#include <string.h>      /* for memset etc */
#endif  /* LACKS_STRING_H */
#if USE_BUILTIN_FFS
#ifndef LACKS_STRINGS_H
#include <strings.h>     /* for ffs */
#endif /* LACKS_STRINGS_H */
#endif /* USE_BUILTIN_FFS */
#if HAVE_MMAP
#ifndef LACKS_SYS_MMAN_H
/* On some versions of linux, mremap decl in mman.h needs __USE_GNU set */
#if (defined(linux) && !defined(__USE_GNU))
#define __USE_GNU 1
#include <sys/mman.h>    /* for mmap */
#undef __USE_GNU
#else
#include <sys/mman.h>    /* for mmap */
#endif /* linux */
#endif /* LACKS_SYS_MMAN_H */
#ifndef LACKS_FCNTL_H
#include <fcntl.h>
#endif /* LACKS_FCNTL_H */
#endif /* HAVE_MMAP */
#ifndef LACKS_UNISTD_H
#include <unistd.h>     /* for sbrk, sysconf */
#else /* LACKS_UNISTD_H */
#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__)
extern void*     sbrk(ptrdiff_t);
#endif /* FreeBSD etc */
#endif /* LACKS_UNISTD_H */

/* Declarations for locking */
#if USE_LOCKS
#ifndef WIN32
#if defined (__SVR4) && defined (__sun)  /* solaris */
#include <thread.h>
#elif !defined(LACKS_SCHED_H)
#include <sched.h>
#endif /* solaris or LACKS_SCHED_H */
#if (defined(USE_RECURSIVE_LOCKS) && USE_RECURSIVE_LOCKS != 0) || !USE_SPIN_LOCKS
#include <pthread.h>
#endif /* USE_RECURSIVE_LOCKS ... */
#elif defined(_MSC_VER)
#ifndef _M_AMD64
/* These are already defined on AMD64 builds */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
LONG __cdecl _InterlockedCompareExchange(LONG volatile *Dest, LONG Exchange, LONG Comp);
LONG __cdecl _InterlockedExchange(LONG volatile *Target, LONG Value);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* _M_AMD64 */
#pragma intrinsic (_InterlockedCompareExchange)
#pragma intrinsic (_InterlockedExchange)
#define interlockedcompareexchange _InterlockedCompareExchange
#define interlockedexchange _InterlockedExchange
#elif defined(WIN32) && defined(__GNUC__)
#define interlockedcompareexchange(a, b, c) __sync_val_compare_and_swap(a, c, b)
#define interlockedexchange __sync_lock_test_and_set
#endif /* Win32 */
#else /* USE_LOCKS */
#endif /* USE_LOCKS */

#ifndef LOCK_AT_FORK
#define LOCK_AT_FORK 0
#endif

/* Declarations for bit scanning on win32 */
#if defined(_MSC_VER) && _MSC_VER>=1300
#ifndef BitScanForward /* Try to avoid pulling in WinNT.h */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
unsigned char _BitScanForward(unsigned long *index, unsigned long mask);
unsigned char _BitScanReverse(unsigned long *index, unsigned long mask);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#define BitScanForward _BitScanForward
#define BitScanReverse _BitScanReverse
#pragma intrinsic(_BitScanForward)
#pragma intrinsic(_BitScanReverse)
#endif /* BitScanForward */
#endif /* defined(_MSC_VER) && _MSC_VER>=1300 */

#ifndef WIN32
#ifndef malloc_getpagesize
#  ifdef _SC_PAGESIZE         /* some SVR4 systems omit an underscore */
#    ifndef _SC_PAGE_SIZE
#      define _SC_PAGE_SIZE _SC_PAGESIZE
#    endif
#  endif
#  ifdef _SC_PAGE_SIZE
#    define malloc_getpagesize sysconf(_SC_PAGE_SIZE)
#  else
#    if defined(BSD) || defined(DGUX) || defined(HAVE_GETPAGESIZE)
       extern size_t getpagesize();
#      define malloc_getpagesize getpagesize()
#    else
#      ifdef WIN32 /* use supplied emulation of getpagesize */
#        define malloc_getpagesize getpagesize()
#      else
#        ifndef LACKS_SYS_PARAM_H
#          include <sys/param.h>
#        endif
#        ifdef EXEC_PAGESIZE
#          define malloc_getpagesize EXEC_PAGESIZE
#        else
#          ifdef NBPG
#            ifndef CLSIZE
#              define malloc_getpagesize NBPG
#            else
#              define malloc_getpagesize (NBPG * CLSIZE)
#            endif
#          else
#            ifdef NBPC
#              define malloc_getpagesize NBPC
#            else
#              ifdef PAGESIZE
#                define malloc_getpagesize PAGESIZE
#              else /* just guess */
#                define malloc_getpagesize ((size_t)4096U)
#              endif
#            endif
#          endif
#        endif
#      endif
#    endif
#  endif
#endif
#endif

/* ------------------- size_t and alignment properties -------------------- */

/* The byte and bit size of a size_t */
#define SIZE_T_SIZE         (sizeof(size_t))
#define SIZE_T_BITSIZE      (sizeof(size_t) << 3)

/* Some constants coerced to size_t */
/* Annoying but necessary to avoid errors on some platforms */
#define SIZE_T_ZERO         ((size_t)0)
#define SIZE_T_ONE          ((size_t)1)
#define SIZE_T_TWO          ((size_t)2)
#define SIZE_T_FOUR         ((size_t)4)
#define TWO_SIZE_T_SIZES    (SIZE_T_SIZE<<1)
#define FOUR_SIZE_T_SIZES   (SIZE_T_SIZE<<2)
#define SIX_SIZE_T_SIZES    (FOUR_SIZE_T_SIZES+TWO_SIZE_T_SIZES)
#define HALF_MAX_SIZE_T     (MAX_SIZE_T / 2U)

/* The bit mask value corresponding to MALLOC_ALIGNMENT */
#define CHUNK_ALIGN_MASK    (MALLOC_ALIGNMENT - SIZE_T_ONE)

/* True if address a has acceptable alignment */
#define is_aligned(A)       (((size_t)((A)) & (CHUNK_ALIGN_MASK)) == 0)

/* the number of bytes to offset an address to align it */
#define align_offset(A)\
 ((((size_t)(A) & CHUNK_ALIGN_MASK) == 0)? 0 :\
  ((MALLOC_ALIGNMENT - ((size_t)(A) & CHUNK_ALIGN_MASK)) & CHUNK_ALIGN_MASK))

/* -------------------------- MMAP preliminaries ------------------------- */

/*
   If HAVE_MORECORE or HAVE_MMAP are false, we just define calls and
   checks to fail so compiler optimizer can delete code rather than
   using so many "#if"s.
*/


/* MORECORE and MMAP must return MFAIL on failure */
#define MFAIL                ((void*)(MAX_SIZE_T))
#define CMFAIL               ((char*)(MFAIL)) /* defined for convenience */

#if HAVE_MMAP

#ifndef WIN32
#define MUNMAP_DEFAULT(a, s)  munmap((a), (s))
#define MMAP_PROT            (PROT_READ|PROT_WRITE)
#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS        MAP_ANON
#endif /* MAP_ANON */
#ifdef MAP_ANONYMOUS
#define MMAP_FLAGS           (MAP_PRIVATE|MAP_ANONYMOUS)
#define MMAP_DEFAULT(s)       mmap(0, (s), MMAP_PROT, MMAP_FLAGS, -1, 0)
#else /* MAP_ANONYMOUS */
/*
   Nearly all versions of mmap support MAP_ANONYMOUS, so the following
   is unlikely to be needed, but is supplied just in case.
*/
#define MMAP_FLAGS           (MAP_PRIVATE)
static int dev_zero_fd = -1; /* Cached file descriptor for /dev/zero. */
#define MMAP_DEFAULT(s) ((dev_zero_fd < 0) ? \
           (dev_zero_fd = open("/dev/zero", O_RDWR), \
            mmap(0, (s), MMAP_PROT, MMAP_FLAGS, dev_zero_fd, 0)) : \
            mmap(0, (s), MMAP_PROT, MMAP_FLAGS, dev_zero_fd, 0))
#endif /* MAP_ANONYMOUS */

#define DIRECT_MMAP_DEFAULT(s) MMAP_DEFAULT(s)

#else /* WIN32 */

/* Win32 MMAP via VirtualAlloc */
static FORCEINLINE void* win32mmap(size_t size) {
  void* ptr = VirtualAlloc(0, size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  return (ptr != 0)? ptr: MFAIL;
}

/* For direct MMAP, use MEM_TOP_DOWN to minimize interference */
static FORCEINLINE void* win32direct_mmap(size_t size) {
  void* ptr = VirtualAlloc(0, size, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN,
                           PAGE_READWRITE);
  return (ptr != 0)? ptr: MFAIL;
}

/* This function supports releasing coalesed segments */
static FORCEINLINE int win32munmap(void* ptr, size_t size) {
  MEMORY_BASIC_INFORMATION minfo;
  char* cptr = (char*)ptr;
  while (size) {
    if (VirtualQuery(cptr, &minfo, sizeof(minfo)) == 0)
      return -1;
    if (minfo.BaseAddress != cptr || minfo.AllocationBase != cptr ||
        minfo.State != MEM_COMMIT || minfo.RegionSize > size)
      return -1;
    if (VirtualFree(cptr, 0, MEM_RELEASE) == 0)
      return -1;
    cptr += minfo.RegionSize;
    size -= minfo.RegionSize;
  }
  return 0;
}

#define MMAP_DEFAULT(s)             win32mmap(s)
#define MUNMAP_DEFAULT(a, s)        win32munmap((a), (s))
#define DIRECT_MMAP_DEFAULT(s)      win32direct_mmap(s)
#endif /* WIN32 */
#endif /* HAVE_MMAP */

#if HAVE_MREMAP
#ifndef WIN32
#define MREMAP_DEFAULT(addr, osz, nsz, mv) mremap((addr), (osz), (nsz), (mv))
#endif /* WIN32 */
#endif /* HAVE_MREMAP */

/**
 * Define CALL_MORECORE
 */
#if HAVE_MORECORE
    #ifdef MORECORE
        #define CALL_MORECORE(S)    MORECORE(S)
    #else  /* MORECORE */
        #define CALL_MORECORE(S)    MORECORE_DEFAULT(S)
    #endif /* MORECORE */
#else  /* HAVE_MORECORE */
    #define CALL_MORECORE(S)        MFAIL
#endif /* HAVE_MORECORE */

/**
 * Define CALL_MMAP/CALL_MUNMAP/CALL_DIRECT_MMAP
 */
#if HAVE_MMAP
    #define USE_MMAP_BIT            (SIZE_T_ONE)

    #ifdef MMAP
        #define CALL_MMAP(s)        MMAP(s)
    #else /* MMAP */
        #define CALL_MMAP(s)        MMAP_DEFAULT(s)
    #endif /* MMAP */
    #ifdef MUNMAP
        #define CALL_MUNMAP(a, s)   MUNMAP((a), (s))
    #else /* MUNMAP */
        #define CALL_MUNMAP(a, s)   MUNMAP_DEFAULT((a), (s))
    #endif /* MUNMAP */
    #ifdef DIRECT_MMAP
        #define CALL_DIRECT_MMAP(s) DIRECT_MMAP(s)
    #else /* DIRECT_MMAP */
        #define CALL_DIRECT_MMAP(s) DIRECT_MMAP_DEFAULT(s)
    #endif /* DIRECT_MMAP */
#else  /* HAVE_MMAP */
    #define USE_MMAP_BIT            (SIZE_T_ZERO)

    #define MMAP(s)                 MFAIL
    #define MUNMAP(a, s)            (-1)
    #define DIRECT_MMAP(s)          MFAIL
    #define CALL_DIRECT_MMAP(s)     DIRECT_MMAP(s)
    #define CALL_MMAP(s)            MMAP(s)
    #define CALL_MUNMAP(a, s)       MUNMAP((a), (s))
#endif /* HAVE_MMAP */

/**
 * Define CALL_MREMAP
 */
#if HAVE_MMAP && HAVE_MREMAP
    #ifdef MREMAP
        #define CALL_MREMAP(addr, osz, nsz, mv) MREMAP((addr), (osz), (nsz), (mv))
    #else /* MREMAP */
        #define CALL_MREMAP(addr, osz, nsz, mv) MREMAP_DEFAULT((addr), (osz), (nsz), (mv))
    #endif /* MREMAP */
#else  /* HAVE_MMAP && HAVE_MREMAP */
    #define CALL_MREMAP(addr, osz, nsz, mv)     MFAIL
#endif /* HAVE_MMAP && HAVE_MREMAP */

/* mstate bit set if continguous morecore disabled or failed */
#define USE_NONCONTIGUOUS_BIT (4U)

/* segment bit set in create_mspace_with_base */
#define EXTERN_BIT            (8U)


/* --------------------------- Lock preliminaries ------------------------ */

/*
  When locks are defined, there is one global lock, plus
  one per-mspace lock.

  The global lock_ensures that mparams.magic and other unique
  mparams values are initialized only once. It also protects
  sequences of calls to MORECORE.  In many cases sys_alloc requires
  two calls, that should not be interleaved with calls by other
  threads.  This does not protect against direct calls to MORECORE
  by other threads not using this lock, so there is still code to
  cope the best we can on interference.

  Per-mspace locks surround calls to malloc, free, etc.
  By default, locks are simple non-reentrant mutexes.

  Because lock-protected regions generally have bounded times, it is
  OK to use the supplied simple spinlocks. Spinlocks are likely to
  improve performance for lightly contended applications, but worsen
  performance under heavy contention.

  If USE_LOCKS is > 1, the definitions of lock routines here are
  bypassed, in which case you will need to define the type MLOCK_T,
  and at least INITIAL_LOCK, DESTROY_LOCK, ACQUIRE_LOCK, RELEASE_LOCK
  and TRY_LOCK.  You must also declare a
    static MLOCK_T malloc_global_mutex = { initialization values };.

*/

#if !USE_LOCKS
#define USE_LOCK_BIT               (0U)
#define INITIAL_LOCK(l)            (0)
#define DESTROY_LOCK(l)            (0)
#define ACQUIRE_MALLOC_GLOBAL_LOCK()
#define RELEASE_MALLOC_GLOBAL_LOCK()

#else
#if USE_LOCKS > 1
/* -----------------------  User-defined locks ------------------------ */
/* Define your own lock implementation here */
/* #define INITIAL_LOCK(lk)  ... */
/* #define DESTROY_LOCK(lk)  ... */
/* #define ACQUIRE_LOCK(lk)  ... */
/* #define RELEASE_LOCK(lk)  ... */
/* #define TRY_LOCK(lk) ... */
/* static MLOCK_T malloc_global_mutex = ... */

#elif USE_SPIN_LOCKS

/* First, define CAS_LOCK and CLEAR_LOCK on ints */
/* Note CAS_LOCK defined to return 0 on success */

#if defined(__GNUC__)&& (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 1))
#define CAS_LOCK(sl)     __sync_lock_test_and_set(sl, 1)
#define CLEAR_LOCK(sl)   __sync_lock_release(sl)

#elif (defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__)))
/* Custom spin locks for older gcc on x86 */
static FORCEINLINE int x86_cas_lock(int *sl) {
  int ret;
  int val = 1;
  int cmp = 0;
  __asm__ __volatile__  ("lock; cmpxchgl %1, %2"
                         : "=a" (ret)
                         : "r" (val), "m" (*(sl)), "0"(cmp)
                         : "memory", "cc");
  return ret;
}

static FORCEINLINE void x86_clear_lock(int* sl) {
  assert(*sl != 0);
  int prev = 0;
  int ret;
  __asm__ __volatile__ ("lock; xchgl %0, %1"
                        : "=r" (ret)
                        : "m" (*(sl)), "0"(prev)
                        : "memory");
}

#define CAS_LOCK(sl)     x86_cas_lock(sl)
#define CLEAR_LOCK(sl)   x86_clear_lock(sl)

#else /* Win32 MSC */
#define CAS_LOCK(sl)     interlockedexchange(sl, (LONG)1)
#define CLEAR_LOCK(sl)   interlockedexchange (sl, (LONG)0)

#endif /* ... gcc spins locks ... */

/* How to yield for a spin lock */
#define SPINS_PER_YIELD       63
#if defined(_MSC_VER)
#define SLEEP_EX_DURATION     50 /* delay for yield/sleep */
#define SPIN_LOCK_YIELD  SleepEx(SLEEP_EX_DURATION, FALSE)
#elif defined (__SVR4) && defined (__sun) /* solaris */
#define SPIN_LOCK_YIELD   thr_yield();
#elif !defined(LACKS_SCHED_H)
#define SPIN_LOCK_YIELD   sched_yield();
#else
#define SPIN_LOCK_YIELD
#endif /* ... yield ... */

#if !defined(USE_RECURSIVE_LOCKS) || USE_RECURSIVE_LOCKS == 0
/* Plain spin locks use single word (embedded in malloc_states) */
static int spin_acquire_lock(int *sl) {
  int spins = 0;
  while (*(volatile int *)sl != 0 || CAS_LOCK(sl)) {
    if ((++spins & SPINS_PER_YIELD) == 0) {
      SPIN_LOCK_YIELD;
    }
  }
  return 0;
}

#define MLOCK_T               int
#define TRY_LOCK(sl)          !CAS_LOCK(sl)
#define RELEASE_LOCK(sl)      CLEAR_LOCK(sl)
#define ACQUIRE_LOCK(sl)      (CAS_LOCK(sl)? spin_acquire_lock(sl) : 0)
#define INITIAL_LOCK(sl)      (*sl = 0)
#define DESTROY_LOCK(sl)      (0)
static MLOCK_T malloc_global_mutex = 0;

#else /* USE_RECURSIVE_LOCKS */
/* types for lock owners */
#ifdef WIN32
#define THREAD_ID_T           DWORD
#define CURRENT_THREAD        GetCurrentThreadId()
#define EQ_OWNER(X,Y)         ((X) == (Y))
#else
/*
  Note: the following assume that pthread_t is a type that can be
  initialized to (casted) zero. If this is not the case, you will need to
  somehow redefine these or not use spin locks.
*/
#define THREAD_ID_T           pthread_t
#define CURRENT_THREAD        pthread_self()
#define EQ_OWNER(X,Y)         pthread_equal(X, Y)
#endif

struct malloc_recursive_lock {
  int sl;
  unsigned int c;
  THREAD_ID_T threadid;
};

#define MLOCK_T  struct malloc_recursive_lock
static MLOCK_T malloc_global_mutex = { 0, 0, (THREAD_ID_T)0};

static FORCEINLINE void recursive_release_lock(MLOCK_T *lk) {
  assert(lk->sl != 0);
  if (--lk->c == 0) {
    CLEAR_LOCK(&lk->sl);
  }
}

static FORCEINLINE int recursive_acquire_lock(MLOCK_T *lk) {
  THREAD_ID_T mythreadid = CURRENT_THREAD;
  int spins = 0;
  for (;;) {
    if (*((volatile int *)(&lk->sl)) == 0) {
      if (!CAS_LOCK(&lk->sl)) {
        lk->threadid = mythreadid;
        lk->c = 1;
        return 0;
      }
    }
    else if (EQ_OWNER(lk->threadid, mythreadid)) {
      ++lk->c;
      return 0;
    }
    if ((++spins & SPINS_PER_YIELD) == 0) {
      SPIN_LOCK_YIELD;
    }
  }
}

static FORCEINLINE int recursive_try_lock(MLOCK_T *lk) {
  THREAD_ID_T mythreadid = CURRENT_THREAD;
  if (*((volatile int *)(&lk->sl)) == 0) {
    if (!CAS_LOCK(&lk->sl)) {
      lk->threadid = mythreadid;
      lk->c = 1;
      return 1;
    }
  }
  else if (EQ_OWNER(lk->threadid, mythreadid)) {
    ++lk->c;
    return 1;
  }
  return 0;
}

#define RELEASE_LOCK(lk)      recursive_release_lock(lk)
#define TRY_LOCK(lk)          recursive_try_lock(lk)
#define ACQUIRE_LOCK(lk)      recursive_acquire_lock(lk)
#define INITIAL_LOCK(lk)      ((lk)->threadid = (THREAD_ID_T)0, (lk)->sl = 0, (lk)->c = 0)
#define DESTROY_LOCK(lk)      (0)
#endif /* USE_RECURSIVE_LOCKS */

#elif defined(WIN32) /* Win32 critical sections */
#define MLOCK_T               CRITICAL_SECTION
#define ACQUIRE_LOCK(lk)      (EnterCriticalSection(lk), 0)
#define RELEASE_LOCK(lk)      LeaveCriticalSection(lk)
#define TRY_LOCK(lk)          TryEnterCriticalSection(lk)
#define INITIAL_LOCK(lk)      (!InitializeCriticalSectionAndSpinCount((lk), 0x80000000|4000))
#define DESTROY_LOCK(lk)      (DeleteCriticalSection(lk), 0)
#define NEED_GLOBAL_LOCK_INIT

static MLOCK_T malloc_global_mutex;
static volatile LONG malloc_global_mutex_status;

/* Use spin loop to initialize global lock */
static void init_malloc_global_mutex() {
  for (;;) {
    long stat = malloc_global_mutex_status;
    if (stat > 0)
      return;
    /* transition to < 0 while initializing, then to > 0) */
    if (stat == 0 &&
        interlockedcompareexchange(&malloc_global_mutex_status, (LONG)-1, (LONG)0) == 0) {
      InitializeCriticalSection(&malloc_global_mutex);
      interlockedexchange(&malloc_global_mutex_status, (LONG)1);
      return;
    }
    SleepEx(0, FALSE);
  }
}

#else /* pthreads-based locks */
#define MLOCK_T               pthread_mutex_t
#define ACQUIRE_LOCK(lk)      pthread_mutex_lock(lk)
#define RELEASE_LOCK(lk)      pthread_mutex_unlock(lk)
#define TRY_LOCK(lk)          (!pthread_mutex_trylock(lk))
#define INITIAL_LOCK(lk)      pthread_init_lock(lk)
#define DESTROY_LOCK(lk)      pthread_mutex_destroy(lk)

#if defined(USE_RECURSIVE_LOCKS) && USE_RECURSIVE_LOCKS != 0 && defined(linux) && !defined(PTHREAD_MUTEX_RECURSIVE)
/* Cope with old-style linux recursive lock initialization by adding */
/* skipped internal declaration from pthread.h */
extern int pthread_mutexattr_setkind_np __P ((pthread_mutexattr_t *__attr,
                                              int __kind));
#define PTHREAD_MUTEX_RECURSIVE PTHREAD_MUTEX_RECURSIVE_NP
#define pthread_mutexattr_settype(x,y) pthread_mutexattr_setkind_np(x,y)
#endif /* USE_RECURSIVE_LOCKS ... */

static MLOCK_T malloc_global_mutex = PTHREAD_MUTEX_INITIALIZER;

static int pthread_init_lock (MLOCK_T *lk) {
  pthread_mutexattr_t attr;
  if (pthread_mutexattr_init(&attr)) return 1;
#if defined(USE_RECURSIVE_LOCKS) && USE_RECURSIVE_LOCKS != 0
  if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) return 1;
#endif
  if (pthread_mutex_init(lk, &attr)) return 1;
  if (pthread_mutexattr_destroy(&attr)) return 1;
  return 0;
}

#endif /* ... lock types ... */

/* Common code for all lock types */
#define USE_LOCK_BIT               (2U)

#ifndef ACQUIRE_MALLOC_GLOBAL_LOCK
#define ACQUIRE_MALLOC_GLOBAL_LOCK()  ACQUIRE_LOCK(&malloc_global_mutex);
#endif

#ifndef RELEASE_MALLOC_GLOBAL_LOCK
#define RELEASE_MALLOC_GLOBAL_LOCK()  RELEASE_LOCK(&malloc_global_mutex);
#endif

#endif /* USE_LOCKS */

/* -----------------------  Chunk representations ------------------------ */

/*
  (The following includes lightly edited explanations by Colin Plumb.)

  The malloc_chunk declaration below is misleading (but accurate and
  necessary).  It declares a "view" into memory allowing access to
  necessary fields at known offsets from a given base.

  Chunks of memory are maintained using a `boundary tag' method as
  originally described by Knuth.  (See the paper by Paul Wilson
  ftp://ftp.cs.utexas.edu/pub/garbage/allocsrv.ps for a survey of such
  techniques.)  Sizes of free chunks are stored both in the front of
  each chunk and at the end.  This makes consolidating fragmented
  chunks into bigger chunks fast.  The head fields also hold bits
  representing whether chunks are free or in use.

  Here are some pictures to make it clearer.  They are "exploded" to
  show that the state of a chunk can be thought of as extending from
  the high 31 bits of the head field of its header through the
  prev_foot and PINUSE_BIT bit of the following chunk header.

  A chunk that's in use looks like:

   chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           | Size of previous chunk (if P = 0)                             |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |P|
         | Size of this chunk                                         1| +-+
   mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                                                               |
         +-                                                             -+
         |                                                               |
         +-                                                             -+
         |                                                               :
         +-      size - sizeof(size_t) available payload bytes          -+
         :                                                               |
 chunk-> +-                                                             -+
         |                                                               |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |1|
       | Size of next chunk (may or may not be in use)               | +-+
 mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    And if it's free, it looks like this:

   chunk-> +-                                                             -+
           | User payload (must be in use, or we would have merged!)       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |P|
         | Size of this chunk                                         0| +-+
   mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         | Next pointer                                                  |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         | Prev pointer                                                  |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                                                               :
         +-      size - sizeof(struct chunk) unused bytes               -+
         :                                                               |
 chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         | Size of this chunk                                            |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |0|
       | Size of next chunk (must be in use, or we would have merged)| +-+
 mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               :
       +- User payload                                                -+
       :                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                                                     |0|
                                                                     +-+
  Note that since we always merge adjacent free chunks, the chunks
  adjacent to a free chunk must be in use.

  Given a pointer to a chunk (which can be derived trivially from the
  payload pointer) we can, in O(1) time, find out whether the adjacent
  chunks are free, and if so, unlink them from the lists that they
  are on and merge them with the current chunk.

  Chunks always begin on even word boundaries, so the mem portion
  (which is returned to the user) is also on an even word boundary, and
  thus at least double-word aligned.

  The P (PINUSE_BIT) bit, stored in the unused low-order bit of the
  chunk size (which is always a multiple of two words), is an in-use
  bit for the *previous* chunk.  If that bit is *clear*, then the
  word before the current chunk size contains the previous chunk
  size, and can be used to find the front of the previous chunk.
  The very first chunk allocated always has this bit set, preventing
  access to non-existent (or non-owned) memory. If pinuse is set for
  any given chunk, then you CANNOT determine the size of the
  previous chunk, and might even get a memory addressing fault when
  trying to do so.

  The C (CINUSE_BIT) bit, stored in the unused second-lowest bit of
  the chunk size redundantly records whether the current chunk is
  inuse (unless the chunk is mmapped). This redundancy enables usage
  checks within free and realloc, and reduces indirection when freeing
  and consolidating chunks.

  Each freshly allocated chunk must have both cinuse and pinuse set.
  That is, each allocated chunk borders either a previously allocated
  and still in-use chunk, or the base of its memory arena. This is
  ensured by making all allocations from the `lowest' part of any
  found chunk.  Further, no free chunk physically borders another one,
  so each free chunk is known to be preceded and followed by either
  inuse chunks or the ends of memory.

  Note that the `foot' of the current chunk is actually represented
  as the prev_foot of the NEXT chunk. This makes it easier to
  deal with alignments etc but can be very confusing when trying
  to extend or adapt this code.

  The exceptions to all this are

     1. The special chunk `top' is the top-most available chunk (i.e.,
        the one bordering the end of available memory). It is treated
        specially.  Top is never included in any bin, is used only if
        no other chunk is available, and is released back to the
        system if it is very large (see M_TRIM_THRESHOLD).  In effect,
        the top chunk is treated as larger (and thus less well
        fitting) than any other available chunk.  The top chunk
        doesn't update its trailing size field since there is no next
        contiguous chunk that would have to index off it. However,
        space is still allocated for it (TOP_FOOT_SIZE) to enable
        separation or merging when space is extended.

     3. Chunks allocated via mmap, have both cinuse and pinuse bits
        cleared in their head fields.  Because they are allocated
        one-by-one, each must carry its own prev_foot field, which is
        also used to hold the offset this chunk has within its mmapped
        region, which is needed to preserve alignment. Each mmapped
        chunk is trailed by the first two fields of a fake next-chunk
        for sake of usage checks.

*/

struct malloc_chunk {
  size_t               prev_foot;  /* Size of previous chunk (if free).  */
  size_t               head;       /* Size and inuse bits. */
  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
};

typedef struct malloc_chunk  mchunk;
typedef struct malloc_chunk* mchunkptr;
typedef struct malloc_chunk* sbinptr;  /* The type of bins of chunks */
typedef unsigned int bindex_t;         /* Described below */
typedef unsigned int binmap_t;         /* Described below */
typedef unsigned int flag_t;           /* The type of various bit flag sets */

/* ------------------- Chunks sizes and alignments ----------------------- */

#define MCHUNK_SIZE         (sizeof(mchunk))

#if FOOTERS
#define CHUNK_OVERHEAD      (TWO_SIZE_T_SIZES)
#else /* FOOTERS */
#define CHUNK_OVERHEAD      (SIZE_T_SIZE)
#endif /* FOOTERS */

/* MMapped chunks need a second word of overhead ... */
#define MMAP_CHUNK_OVERHEAD (TWO_SIZE_T_SIZES)
/* ... and additional padding for fake next-chunk at foot */
#define MMAP_FOOT_PAD       (FOUR_SIZE_T_SIZES)

/* The smallest size we can malloc is an aligned minimal chunk */
#define MIN_CHUNK_SIZE\
  ((MCHUNK_SIZE + CHUNK_ALIGN_MASK) & ~CHUNK_ALIGN_MASK)

/* conversion from malloc headers to user pointers, and back */
#define chunk2mem(p)        ((void*)((char*)(p)       + TWO_SIZE_T_SIZES))
#define mem2chunk(mem)      ((mchunkptr)((char*)(mem) - TWO_SIZE_T_SIZES))
/* chunk associated with aligned address A */
#define align_as_chunk(A)   (mchunkptr)((A) + align_offset(chunk2mem(A)))

/* Bounds on request (not chunk) sizes. */
#define MAX_REQUEST         ((-MIN_CHUNK_SIZE) << 2)
#define MIN_REQUEST         (MIN_CHUNK_SIZE - CHUNK_OVERHEAD - SIZE_T_ONE)

/* pad request bytes into a usable size */
#define pad_request(req) \
   (((req) + CHUNK_OVERHEAD + CHUNK_ALIGN_MASK) & ~CHUNK_ALIGN_MASK)

/* pad request, checking for minimum (but not maximum) */
#define request2size(req) \
  (((req) < MIN_REQUEST)? MIN_CHUNK_SIZE : pad_request(req))


/* ------------------ Operations on head and foot fields ----------------- */

/*
  The head field of a chunk is or'ed with PINUSE_BIT when previous
  adjacent chunk in use, and or'ed with CINUSE_BIT if this chunk is in
  use, unless mmapped, in which case both bits are cleared.

  FLAG4_BIT is not used by this malloc, but might be useful in extensions.
*/

#define PINUSE_BIT          (SIZE_T_ONE)
#define CINUSE_BIT          (SIZE_T_TWO)
#define FLAG4_BIT           (SIZE_T_FOUR)
#define INUSE_BITS          (PINUSE_BIT|CINUSE_BIT)
#define FLAG_BITS           (PINUSE_BIT|CINUSE_BIT|FLAG4_BIT)

/* Head value for fenceposts */
#define FENCEPOST_HEAD      (INUSE_BITS|SIZE_T_SIZE)

/* extraction of fields from head words */
#define cinuse(p)           ((p)->head & CINUSE_BIT)
#define pinuse(p)           ((p)->head & PINUSE_BIT)
#define flag4inuse(p)       ((p)->head & FLAG4_BIT)
#define is_inuse(p)         (((p)->head & INUSE_BITS) != PINUSE_BIT)
#define is_mmapped(p)       (((p)->head & INUSE_BITS) == 0)

#define chunksize(p)        ((p)->head & ~(FLAG_BITS))

#define clear_pinuse(p)     ((p)->head &= ~PINUSE_BIT)
#define set_flag4(p)        ((p)->head |= FLAG4_BIT)
#define clear_flag4(p)      ((p)->head &= ~FLAG4_BIT)

/* Treat space at ptr +/- offset as a chunk */
#define chunk_plus_offset(p, s)  ((mchunkptr)(((char*)(p)) + (s)))
#define chunk_minus_offset(p, s) ((mchunkptr)(((char*)(p)) - (s)))

/* Ptr to next or previous physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr)( ((char*)(p)) + ((p)->head & ~FLAG_BITS)))
#define prev_chunk(p) ((mchunkptr)( ((char*)(p)) - ((p)->prev_foot) ))

/* extract next chunk's pinuse bit */
#define next_pinuse(p)  ((next_chunk(p)->head) & PINUSE_BIT)

/* Get/set size at footer */
#define get_foot(p, s)  (((mchunkptr)((char*)(p) + (s)))->prev_foot)
#define set_foot(p, s)  (((mchunkptr)((char*)(p) + (s)))->prev_foot = (s))

/* Set size, pinuse bit, and foot */
#define set_size_and_pinuse_of_free_chunk(p, s)\
  ((p)->head = (s|PINUSE_BIT), set_foot(p, s))

/* Set size, pinuse bit, foot, and clear next pinuse */
#define set_free_with_pinuse(p, s, n)\
  (clear_pinuse(n), set_size_and_pinuse_of_free_chunk(p, s))

/* Get the internal overhead associated with chunk p */
#define overhead_for(p)\
 (is_mmapped(p)? MMAP_CHUNK_OVERHEAD : CHUNK_OVERHEAD)

/* Return true if malloced space is not necessarily cleared */
#if MMAP_CLEARS
#define calloc_must_clear(p) (!is_mmapped(p))
#else /* MMAP_CLEARS */
#define calloc_must_clear(p) (1)
#endif /* MMAP_CLEARS */

/* ---------------------- Overlaid data structures ----------------------- */

/*
  When chunks are not in use, they are treated as nodes of either
  lists or trees.

  "Small"  chunks are stored in circular doubly-linked lists, and look
  like this:

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                         |P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .                                                               .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Larger chunks are kept in a form of bitwise digital trees (aka
  tries) keyed on chunksizes.  Because malloc_tree_chunks are only for
  free chunks greater than 256 bytes, their size doesn't impose any
  constraints on user chunk sizes.  Each node looks like:

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                         |P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk of same size        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk of same size       |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Pointer to left child (child[0])                  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Pointer to right child (child[1])                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Pointer to parent                                 |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             bin index of this chunk                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space                                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Each tree holding treenodes is a tree of unique chunk sizes.  Chunks
  of the same size are arranged in a circularly-linked list, with only
  the oldest chunk (the next to be used, in our FIFO ordering)
  actually in the tree.  (Tree members are distinguished by a non-null
  parent pointer.)  If a chunk with the same size an an existing node
  is inserted, it is linked off the existing node using pointers that
  work in the same way as fd/bk pointers of small chunks.

  Each tree contains a power of 2 sized range of chunk sizes (the
  smallest is 0x100 <= x < 0x180), which is is divided in half at each
  tree level, with the chunks in the smaller half of the range (0x100
  <= x < 0x140 for the top nose) in the left subtree and the larger
  half (0x140 <= x < 0x180) in the right subtree.  This is, of course,
  done by inspecting individual bits.

  Using these rules, each node's left subtree contains all smaller
  sizes than its right subtree.  However, the node at the root of each
  subtree has no particular ordering relationship to either.  (The
  dividing line between the subtree sizes is based on trie relation.)
  If we remove the last chunk of a given size from the interior of the
  tree, we need to replace it with a leaf node.  The tree ordering
  rules permit a node to be replaced by any leaf below it.

  The smallest chunk in a tree (a common operation in a best-fit
  allocator) can be found by walking a path to the leftmost leaf in
  the tree.  Unlike a usual binary tree, where we follow left child
  pointers until we reach a null, here we follow the right child
  pointer any time the left one is null, until we reach a leaf with
  both child pointers null. The smallest chunk in the tree will be
  somewhere along that path.

  The worst case number of steps to add, find, or remove a node is
  bounded by the number of bits differentiating chunks within
  bins. Under current bin calculations, this ranges from 6 up to 21
  (for 32 bit sizes) or up to 53 (for 64 bit sizes). The typical case
  is of course much better.
*/

struct malloc_tree_chunk {
  /* The first four fields must be compatible with malloc_chunk */
  size_t                    prev_foot;
  size_t                    head;
  struct malloc_tree_chunk* fd;
  struct malloc_tree_chunk* bk;

  struct malloc_tree_chunk* child[2];
  struct malloc_tree_chunk* parent;
  bindex_t                  index;
};

typedef struct malloc_tree_chunk  tchunk;
typedef struct malloc_tree_chunk* tchunkptr;
typedef struct malloc_tree_chunk* tbinptr; /* The type of bins of trees */

/* A little helper macro for trees */
#define leftmost_child(t) ((t)->child[0] != 0? (t)->child[0] : (t)->child[1])

/* ----------------------------- Segments -------------------------------- */

/*
  Each malloc space may include non-contiguous segments, held in a
  list headed by an embedded malloc_segment record representing the
  top-most space. Segments also include flags holding properties of
  the space. Large chunks that are directly allocated by mmap are not
  included in this list. They are instead independently created and
  destroyed without otherwise keeping track of them.

  Segment management mainly comes into play for spaces allocated by
  MMAP.  Any call to MMAP might or might not return memory that is
  adjacent to an existing segment.  MORECORE normally contiguously
  extends the current space, so this space is almost always adjacent,
  which is simpler and faster to deal with. (This is why MORECORE is
  used preferentially to MMAP when both are available -- see
  sys_alloc.)  When allocating using MMAP, we don't use any of the
  hinting mechanisms (inconsistently) supported in various
  implementations of unix mmap, or distinguish reserving from
  committing memory. Instead, we just ask for space, and exploit
  contiguity when we get it.  It is probably possible to do
  better than this on some systems, but no general scheme seems
  to be significantly better.

  Management entails a simpler variant of the consolidation scheme
  used for chunks to reduce fragmentation -- new adjacent memory is
  normally prepended or appended to an existing segment. However,
  there are limitations compared to chunk consolidation that mostly
  reflect the fact that segment processing is relatively infrequent
  (occurring only when getting memory from system) and that we
  don't expect to have huge numbers of segments:

  * Segments are not indexed, so traversal requires linear scans.  (It
    would be possible to index these, but is not worth the extra
    overhead and complexity for most programs on most platforms.)
  * New segments are only appended to old ones when holding top-most
    memory; if they cannot be prepended to others, they are held in
    different segments.

  Except for the top-most segment of an mstate, each segment record
  is kept at the tail of its segment. Segments are added by pushing
  segment records onto the list headed by &mstate.seg for the
  containing mstate.

  Segment flags control allocation/merge/deallocation policies:
  * If EXTERN_BIT set, then we did not allocate this segment,
    and so should not try to deallocate or merge with others.
    (This currently holds only for the initial segment passed
    into create_mspace_with_base.)
  * If USE_MMAP_BIT set, the segment may be merged with
    other surrounding mmapped segments and trimmed/de-allocated
    using munmap.
  * If neither bit is set, then the segment was obtained using
    MORECORE so can be merged with surrounding MORECORE'd segments
    and deallocated/trimmed using MORECORE with negative arguments.
*/

struct malloc_segment {
  char*        base;             /* base address */
  size_t       size;             /* allocated size */
  struct malloc_segment* next;   /* ptr to next segment */
  flag_t       sflags;           /* mmap and extern flag */
};

#define is_mmapped_segment(S)  ((S)->sflags & USE_MMAP_BIT)
#define is_extern_segment(S)   ((S)->sflags & EXTERN_BIT)

typedef struct malloc_segment  msegment;
typedef struct malloc_segment* msegmentptr;

/* ---------------------------- malloc_state ----------------------------- */

/*
   A malloc_state holds all of the bookkeeping for a space.
   The main fields are:

  Top
    The topmost chunk of the currently active segment. Its size is
    cached in topsize.  The actual size of topmost space is
    topsize+TOP_FOOT_SIZE, which includes space reserved for adding
    fenceposts and segment records if necessary when getting more
    space from the system.  The size at which to autotrim top is
    cached from mparams in trim_check, except that it is disabled if
    an autotrim fails.

  Designated victim (dv)
    This is the preferred chunk for servicing small requests that
    don't have exact fits.  It is normally the chunk split off most
    recently to service another small request.  Its size is cached in
    dvsize. The link fields of this chunk are not maintained since it
    is not kept in a bin.

  SmallBins
    An array of bin headers for free chunks.  These bins hold chunks
    with sizes less than MIN_LARGE_SIZE bytes. Each bin contains
    chunks of all the same size, spaced 8 bytes apart.  To simplify
    use in double-linked lists, each bin header acts as a malloc_chunk
    pointing to the real first node, if it exists (else pointing to
    itself).  This avoids special-casing for headers.  But to avoid
    waste, we allocate only the fd/bk pointers of bins, and then use
    repositioning tricks to treat these as the fields of a chunk.

  TreeBins
    Treebins are pointers to the roots of trees holding a range of
    sizes. There are 2 equally spaced treebins for each power of two
    from TREE_SHIFT to TREE_SHIFT+16. The last bin holds anything
    larger.

  Bin maps
    There is one bit map for small bins ("smallmap") and one for
    treebins ("treemap).  Each bin sets its bit when non-empty, and
    clears the bit when empty.  Bit operations are then used to avoid
    bin-by-bin searching -- nearly all "search" is done without ever
    looking at bins that won't be selected.  The bit maps
    conservatively use 32 bits per map word, even if on 64bit system.
    For a good description of some of the bit-based techniques used
    here, see Henry S. Warren Jr's book "Hacker's Delight" (and
    supplement at http://hackersdelight.org/). Many of these are
    intended to reduce the branchiness of paths through malloc etc, as
    well as to reduce the number of memory locations read or written.

  Segments
    A list of segments headed by an embedded malloc_segment record
    representing the initial space.

  Address check support
    The least_addr field is the least address ever obtained from
    MORECORE or MMAP. Attempted frees and reallocs of any address less
    than this are trapped (unless INSECURE is defined).

  Magic tag
    A cross-check field that should always hold same value as mparams.magic.

  Max allowed footprint
    The maximum allowed bytes to allocate from system (zero means no limit)

  Flags
    Bits recording whether to use MMAP, locks, or contiguous MORECORE

  Statistics
    Each space keeps track of current and maximum system memory
    obtained via MORECORE or MMAP.

  Trim support
    Fields holding the amount of unused topmost memory that should trigger
    trimming, and a counter to force periodic scanning to release unused
    non-topmost segments.

  Locking
    If USE_LOCKS is defined, the "mutex" lock is acquired and released
    around every public call using this mspace.

  Extension support
    A void* pointer and a size_t field that can be used to help implement
    extensions to this malloc.
*/

/* Bin types, widths and sizes */
#define NSMALLBINS        (32U)
#define NTREEBINS         (32U)
#define SMALLBIN_SHIFT    (3U)
#define SMALLBIN_WIDTH    (SIZE_T_ONE << SMALLBIN_SHIFT)
#define TREEBIN_SHIFT     (8U)
#define MIN_LARGE_SIZE    (SIZE_T_ONE << TREEBIN_SHIFT)
#define MAX_SMALL_SIZE    (MIN_LARGE_SIZE - SIZE_T_ONE)
#define MAX_SMALL_REQUEST (MAX_SMALL_SIZE - CHUNK_ALIGN_MASK - CHUNK_OVERHEAD)

struct malloc_state {
  binmap_t   smallmap;
  binmap_t   treemap;
  size_t     dvsize;
  size_t     topsize;
  char*      least_addr;
  mchunkptr  dv;
  mchunkptr  top;
  size_t     trim_check;
  size_t     release_checks;
  size_t     magic;
  mchunkptr  smallbins[(NSMALLBINS+1)*2];
  tbinptr    treebins[NTREEBINS];
  size_t     footprint;
  size_t     max_footprint;
  size_t     footprint_limit; /* zero means no limit */
  flag_t     mflags;
#if USE_LOCKS
  MLOCK_T    mutex;     /* locate lock among fields that rarely change */
#endif /* USE_LOCKS */
  msegment   seg;
  void*      extp;      /* Unused but available for extensions */
  size_t     exts;
};

typedef struct malloc_state*    mstate;

/* ------------- Global malloc_state and malloc_params ------------------- */

/*
  malloc_params holds global properties, including those that can be
  dynamically set using mallopt. There is a single instance, mparams,
  initialized in init_mparams. Note that the non-zeroness of "magic"
  also serves as an initialization flag.
*/

struct malloc_params {
  size_t magic;
  size_t page_size;
  size_t granularity;
  size_t mmap_threshold;
  size_t trim_threshold;
  flag_t default_mflags;
};

static struct malloc_params mparams;

/* Ensure mparams initialized */
#define ensure_initialization() (void)(mparams.magic != 0 || init_mparams())

#if !ONLY_MSPACES

/* The global malloc_state used for all non-"mspace" calls */
static struct malloc_state _gm_;
#define gm                 (&_gm_)
#define is_global(M)       ((M) == &_gm_)

#endif /* !ONLY_MSPACES */

#define is_initialized(M)  ((M)->top != 0)

/* -------------------------- system alloc setup ------------------------- */

/* Operations on mflags */

#define use_lock(M)           ((M)->mflags &   USE_LOCK_BIT)
#define enable_lock(M)        ((M)->mflags |=  USE_LOCK_BIT)
#if USE_LOCKS
#define disable_lock(M)       ((M)->mflags &= ~USE_LOCK_BIT)
#else
#define disable_lock(M)
#endif

#define use_mmap(M)           ((M)->mflags &   USE_MMAP_BIT)
#define enable_mmap(M)        ((M)->mflags |=  USE_MMAP_BIT)
#if HAVE_MMAP
#define disable_mmap(M)       ((M)->mflags &= ~USE_MMAP_BIT)
#else
#define disable_mmap(M)
#endif

#define use_noncontiguous(M)  ((M)->mflags &   USE_NONCONTIGUOUS_BIT)
#define disable_contiguous(M) ((M)->mflags |=  USE_NONCONTIGUOUS_BIT)

#define set_lock(M,L)\
 ((M)->mflags = (L)?\
  ((M)->mflags | USE_LOCK_BIT) :\
  ((M)->mflags & ~USE_LOCK_BIT))

/* page-align a size */
#define page_align(S)\
 (((S) + (mparams.page_size - SIZE_T_ONE)) & ~(mparams.page_size - SIZE_T_ONE))

/* granularity-align a size */
#define granularity_align(S)\
  (((S) + (mparams.granularity - SIZE_T_ONE))\
   & ~(mparams.granularity - SIZE_T_ONE))


/* For mmap, use granularity alignment on windows, else page-align */
#ifdef WIN32
#define mmap_align(S) granularity_align(S)
#else
#define mmap_align(S) page_align(S)
#endif

/* For sys_alloc, enough padding to ensure can malloc request on success */
#define SYS_ALLOC_PADDING (TOP_FOOT_SIZE + MALLOC_ALIGNMENT)

#define is_page_aligned(S)\
   (((size_t)(S) & (mparams.page_size - SIZE_T_ONE)) == 0)
#define is_granularity_aligned(S)\
   (((size_t)(S) & (mparams.granularity - SIZE_T_ONE)) == 0)

/*  True if segment S holds address A */
#define segment_holds(S, A)\
  ((char*)(A) >= S->base && (char*)(A) < S->base + S->size)

/* Return segment holding given address */
static msegmentptr segment_holding(mstate m, char* addr) {
  msegmentptr sp = &m->seg;
  for (;;) {
    if (addr >= sp->base && addr < sp->base + sp->size)
      return sp;
    if ((sp = sp->next) == 0)
      return 0;
  }
}

/* Return true if segment contains a segment link */
static int has_segment_link(mstate m, msegmentptr ss) {
  msegmentptr sp = &m->seg;
  for (;;) {
    if ((char*)sp >= ss->base && (char*)sp < ss->base + ss->size)
      return 1;
    if ((sp = sp->next) == 0)
      return 0;
  }
}

#ifndef MORECORE_CANNOT_TRIM
#define should_trim(M,s)  ((s) > (M)->trim_check)
#else  /* MORECORE_CANNOT_TRIM */
#define should_trim(M,s)  (0)
#endif /* MORECORE_CANNOT_TRIM */

/*
  TOP_FOOT_SIZE is padding at the end of a segment, including space
  that may be needed to place segment records and fenceposts when new
  noncontiguous segments are added.
*/
#define TOP_FOOT_SIZE\
  (align_offset(chunk2mem(0))+pad_request(sizeof(struct malloc_segment))+MIN_CHUNK_SIZE)


/* -------------------------------  Hooks -------------------------------- */

/*
  PREACTION should be defined to return 0 on success, and nonzero on
  failure. If you are not using locking, you can redefine these to do
  anything you like.
*/

#if USE_LOCKS
#define PREACTION(M)  ((use_lock(M))? ACQUIRE_LOCK(&(M)->mutex) : 0)
#define POSTACTION(M) { if (use_lock(M)) RELEASE_LOCK(&(M)->mutex); }
#else /* USE_LOCKS */

#ifndef PREACTION
#define PREACTION(M) (0)
#endif  /* PREACTION */

#ifndef POSTACTION
#define POSTACTION(M)
#endif  /* POSTACTION */

#endif /* USE_LOCKS */

/*
  CORRUPTION_ERROR_ACTION is triggered upon detected bad addresses.
  USAGE_ERROR_ACTION is triggered on detected bad frees and
  reallocs. The argument p is an address that might have triggered the
  fault. It is ignored by the two predefined actions, but might be
  useful in custom actions that try to help diagnose errors.
*/

#if PROCEED_ON_ERROR

/* A count of the number of corruption errors causing resets */
int malloc_corruption_error_count;

/* default corruption action */
static void reset_on_error(mstate m);

#define CORRUPTION_ERROR_ACTION(m)  reset_on_error(m)
#define USAGE_ERROR_ACTION(m, p)

#else /* PROCEED_ON_ERROR */

#ifndef CORRUPTION_ERROR_ACTION
#define CORRUPTION_ERROR_ACTION(m) ABORT
#endif /* CORRUPTION_ERROR_ACTION */

#ifndef USAGE_ERROR_ACTION
#define USAGE_ERROR_ACTION(m,p) ABORT
#endif /* USAGE_ERROR_ACTION */

#endif /* PROCEED_ON_ERROR */


/* -------------------------- Debugging setup ---------------------------- */

#if ! DEBUG

#define check_free_chunk(M,P)
#define check_inuse_chunk(M,P)
#define check_malloced_chunk(M,P,N)
#define check_mmapped_chunk(M,P)
#define check_malloc_state(M)
#define check_top_chunk(M,P)

#else /* DEBUG */
#define check_free_chunk(M,P)       do_check_free_chunk(M,P)
#define check_inuse_chunk(M,P)      do_check_inuse_chunk(M,P)
#define check_top_chunk(M,P)        do_check_top_chunk(M,P)
#define check_malloced_chunk(M,P,N) do_check_malloced_chunk(M,P,N)
#define check_mmapped_chunk(M,P)    do_check_mmapped_chunk(M,P)
#define check_malloc_state(M)       do_check_malloc_state(M)

static void   do_check_any_chunk(mstate m, mchunkptr p);
static void   do_check_top_chunk(mstate m, mchunkptr p);
static void   do_check_mmapped_chunk(mstate m, mchunkptr p);
static void   do_check_inuse_chunk(mstate m, mchunkptr p);
static void   do_check_free_chunk(mstate m, mchunkptr p);
static void   do_check_malloced_chunk(mstate m, void* mem, size_t s);
static void   do_check_tree(mstate m, tchunkptr t);
static void   do_check_treebin(mstate m, bindex_t i);
static void   do_check_smallbin(mstate m, bindex_t i);
static void   do_check_malloc_state(mstate m);
static int    bin_find(mstate m, mchunkptr x);
static size_t traverse_and_check(mstate m);
#endif /* DEBUG */

/* ---------------------------- Indexing Bins ---------------------------- */

#define is_small(s)         (((s) >> SMALLBIN_SHIFT) < NSMALLBINS)
#define small_index(s)      (bindex_t)((s)  >> SMALLBIN_SHIFT)
#define small_index2size(i) ((i)  << SMALLBIN_SHIFT)
#define MIN_SMALL_INDEX     (small_index(MIN_CHUNK_SIZE))

/* addressing by index. See above about smallbin repositioning */
#define smallbin_at(M, i)   ((sbinptr)((char*)&((M)->smallbins[(i)<<1])))
#define treebin_at(M,i)     (&((M)->treebins[i]))

/* assign tree index for size S to variable I. Use x86 asm if possible  */
#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
#define compute_tree_index(S, I)\
{\
  unsigned int X = S >> TREEBIN_SHIFT;\
  if (X == 0)\
    I = 0;\
  else if (X > 0xFFFF)\
    I = NTREEBINS-1;\
  else {\
    unsigned int K = (unsigned) sizeof(X)*__CHAR_BIT__ - 1 - (unsigned) __builtin_clz(X); \
    I =  (bindex_t)((K << 1) + ((S >> (K + (TREEBIN_SHIFT-1)) & 1)));\
  }\
}

#elif defined (__INTEL_COMPILER)
#define compute_tree_index(S, I)\
{\
  size_t X = S >> TREEBIN_SHIFT;\
  if (X == 0)\
    I = 0;\
  else if (X > 0xFFFF)\
    I = NTREEBINS-1;\
  else {\
    unsigned int K = _bit_scan_reverse (X); \
    I =  (bindex_t)((K << 1) + ((S >> (K + (TREEBIN_SHIFT-1)) & 1)));\
  }\
}

#elif defined(_MSC_VER) && _MSC_VER>=1300
#define compute_tree_index(S, I)\
{\
  size_t X = S >> TREEBIN_SHIFT;\
  if (X == 0)\
    I = 0;\
  else if (X > 0xFFFF)\
    I = NTREEBINS-1;\
  else {\
    unsigned int K;\
    _BitScanReverse((DWORD *) &K, (DWORD) X);\
    I =  (bindex_t)((K << 1) + ((S >> (K + (TREEBIN_SHIFT-1)) & 1)));\
  }\
}

#else /* GNUC */
#define compute_tree_index(S, I)\
{\
  size_t X = S >> TREEBIN_SHIFT;\
  if (X == 0)\
    I = 0;\
  else if (X > 0xFFFF)\
    I = NTREEBINS-1;\
  else {\
    unsigned int Y = (unsigned int)X;\
    unsigned int N = ((Y - 0x100) >> 16) & 8;\
    unsigned int K = (((Y <<= N) - 0x1000) >> 16) & 4;\
    N += K;\
    N += K = (((Y <<= K) - 0x4000) >> 16) & 2;\
    K = 14 - N + ((Y <<= K) >> 15);\
    I = (K << 1) + ((S >> (K + (TREEBIN_SHIFT-1)) & 1));\
  }\
}
#endif /* GNUC */

/* Bit representing maximum resolved size in a treebin at i */
#define bit_for_tree_index(i) \
   (i == NTREEBINS-1)? (SIZE_T_BITSIZE-1) : (((i) >> 1) + TREEBIN_SHIFT - 2)

/* Shift placing maximum resolved bit in a treebin at i as sign bit */
#define leftshift_for_tree_index(i) \
   ((i == NTREEBINS-1)? 0 : \
    ((SIZE_T_BITSIZE-SIZE_T_ONE) - (((i) >> 1) + TREEBIN_SHIFT - 2)))

/* The size of the smallest chunk held in bin with index i */
#define minsize_for_tree_index(i) \
   ((SIZE_T_ONE << (((i) >> 1) + TREEBIN_SHIFT)) |  \
   (((size_t)((i) & SIZE_T_ONE)) << (((i) >> 1) + TREEBIN_SHIFT - 1)))


/* ------------------------ Operations on bin maps ----------------------- */

/* bit corresponding to given index */
#define idx2bit(i)              ((binmap_t)(1) << (i))

/* Mark/Clear bits with given index */
#define mark_smallmap(M,i)      ((M)->smallmap |=  idx2bit(i))
#define clear_smallmap(M,i)     ((M)->smallmap &= ~idx2bit(i))
#define smallmap_is_marked(M,i) ((M)->smallmap &   idx2bit(i))

#define mark_treemap(M,i)       ((M)->treemap  |=  idx2bit(i))
#define clear_treemap(M,i)      ((M)->treemap  &= ~idx2bit(i))
#define treemap_is_marked(M,i)  ((M)->treemap  &   idx2bit(i))

/* isolate the least set bit of a bitmap */
#define least_bit(x)         ((x) & -(x))

/* mask with all bits to left of least bit of x on */
#define left_bits(x)         ((x<<1) | -(x<<1))

/* mask with all bits to left of or equal to least bit of x on */
#define same_or_left_bits(x) ((x) | -(x))

/* index corresponding to given bit. Use x86 asm if possible */

#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
#define compute_bit2idx(X, I)\
{\
  unsigned int J;\
  J = __builtin_ctz(X); \
  I = (bindex_t)J;\
}

#elif defined (__INTEL_COMPILER)
#define compute_bit2idx(X, I)\
{\
  unsigned int J;\
  J = _bit_scan_forward (X); \
  I = (bindex_t)J;\
}

#elif defined(_MSC_VER) && _MSC_VER>=1300
#define compute_bit2idx(X, I)\
{\
  unsigned int J;\
  _BitScanForward((DWORD *) &J, X);\
  I = (bindex_t)J;\
}

#elif USE_BUILTIN_FFS
#define compute_bit2idx(X, I) I = ffs(X)-1

#else
#define compute_bit2idx(X, I)\
{\
  unsigned int Y = X - 1;\
  unsigned int K = Y >> (16-4) & 16;\
  unsigned int N = K;        Y >>= K;\
  N += K = Y >> (8-3) &  8;  Y >>= K;\
  N += K = Y >> (4-2) &  4;  Y >>= K;\
  N += K = Y >> (2-1) &  2;  Y >>= K;\
  N += K = Y >> (1-0) &  1;  Y >>= K;\
  I = (bindex_t)(N + Y);\
}
#endif /* GNUC */


/* ----------------------- Runtime Check Support ------------------------- */

/*
  For security, the main invariant is that malloc/free/etc never
  writes to a static address other than malloc_state, unless static
  malloc_state itself has been corrupted, which cannot occur via
  malloc (because of these checks). In essence this means that we
  believe all pointers, sizes, maps etc held in malloc_state, but
  check all of those linked or offsetted from other embedded data
  structures.  These checks are interspersed with main code in a way
  that tends to minimize their run-time cost.

  When FOOTERS is defined, in addition to range checking, we also
  verify footer fields of inuse chunks, which can be used guarantee
  that the mstate controlling malloc/free is intact.  This is a
  streamlined version of the approach described by William Robertson
  et al in "Run-time Detection of Heap-based Overflows" LISA'03
  http://www.usenix.org/events/lisa03/tech/robertson.html The footer
  of an inuse chunk holds the xor of its mstate and a random seed,
  that is checked upon calls to free() and realloc().  This is
  (probabalistically) unguessable from outside the program, but can be
  computed by any code successfully malloc'ing any chunk, so does not
  itself provide protection against code that has already broken
  security through some other means.  Unlike Robertson et al, we
  always dynamically check addresses of all offset chunks (previous,
  next, etc). This turns out to be cheaper than relying on hashes.
*/

#if !INSECURE
/* Check if address a is at least as high as any from MORECORE or MMAP */
#define ok_address(M, a) ((char*)(a) >= (M)->least_addr)
/* Check if address of next chunk n is higher than base chunk p */
#define ok_next(p, n)    ((char*)(p) < (char*)(n))
/* Check if p has inuse status */
#define ok_inuse(p)     is_inuse(p)
/* Check if p has its pinuse bit on */
#define ok_pinuse(p)     pinuse(p)

#else /* !INSECURE */
#define ok_address(M, a) (1)
#define ok_next(b, n)    (1)
#define ok_inuse(p)      (1)
#define ok_pinuse(p)     (1)
#endif /* !INSECURE */

#if (FOOTERS && !INSECURE)
/* Check if (alleged) mstate m has expected magic field */
#define ok_magic(M)      ((M)->magic == mparams.magic)
#else  /* (FOOTERS && !INSECURE) */
#define ok_magic(M)      (1)
#endif /* (FOOTERS && !INSECURE) */

/* In gcc, use __builtin_expect to minimize impact of checks */
#if !INSECURE
#if defined(__GNUC__) && __GNUC__ >= 3
#define RTCHECK(e)  __builtin_expect(e, 1)
#else /* GNUC */
#define RTCHECK(e)  (e)
#endif /* GNUC */
#else /* !INSECURE */
#define RTCHECK(e)  (1)
#endif /* !INSECURE */

/* macros to set up inuse chunks with or without footers */

#if !FOOTERS

#define mark_inuse_foot(M,p,s)

/* Macros for setting head/foot of non-mmapped chunks */

/* Set cinuse bit and pinuse bit of next chunk */
#define set_inuse(M,p,s)\
  ((p)->head = (((p)->head & PINUSE_BIT)|s|CINUSE_BIT),\
  ((mchunkptr)(((char*)(p)) + (s)))->head |= PINUSE_BIT)

/* Set cinuse and pinuse of this chunk and pinuse of next chunk */
#define set_inuse_and_pinuse(M,p,s)\
  ((p)->head = (s|PINUSE_BIT|CINUSE_BIT),\
  ((mchunkptr)(((char*)(p)) + (s)))->head |= PINUSE_BIT)

/* Set size, cinuse and pinuse bit of this chunk */
#define set_size_and_pinuse_of_inuse_chunk(M, p, s)\
  ((p)->head = (s|PINUSE_BIT|CINUSE_BIT))

#else /* FOOTERS */

/* Set foot of inuse chunk to be xor of mstate and seed */
#define mark_inuse_foot(M,p,s)\
  (((mchunkptr)((char*)(p) + (s)))->prev_foot = ((size_t)(M) ^ mparams.magic))

#define get_mstate_for(p)\
  ((mstate)(((mchunkptr)((char*)(p) +\
    (chunksize(p))))->prev_foot ^ mparams.magic))

#define set_inuse(M,p,s)\
  ((p)->head = (((p)->head & PINUSE_BIT)|s|CINUSE_BIT),\
  (((mchunkptr)(((char*)(p)) + (s)))->head |= PINUSE_BIT), \
  mark_inuse_foot(M,p,s))

#define set_inuse_and_pinuse(M,p,s)\
  ((p)->head = (s|PINUSE_BIT|CINUSE_BIT),\
  (((mchunkptr)(((char*)(p)) + (s)))->head |= PINUSE_BIT),\
 mark_inuse_foot(M,p,s))

#define set_size_and_pinuse_of_inuse_chunk(M, p, s)\
  ((p)->head = (s|PINUSE_BIT|CINUSE_BIT),\
  mark_inuse_foot(M, p, s))

#endif /* !FOOTERS */

/* ---------------------------- setting mparams -------------------------- */

#if LOCK_AT_FORK
static void pre_fork(void)         { ACQUIRE_LOCK(&(gm)->mutex); }
static void post_fork_parent(void) { RELEASE_LOCK(&(gm)->mutex); }
static void post_fork_child(void)  { INITIAL_LOCK(&(gm)->mutex); }
#endif /* LOCK_AT_FORK */

/* Initialize mparams */
static int init_mparams(void) {
#ifdef NEED_GLOBAL_LOCK_INIT
  if (malloc_global_mutex_status <= 0)
    init_malloc_global_mutex();
#endif

  ACQUIRE_MALLOC_GLOBAL_LOCK();
  if (mparams.magic == 0) {
    size_t magic;
    size_t psize;
    size_t gsize;

#ifndef WIN32
    psize = malloc_getpagesize;
    gsize = ((DEFAULT_GRANULARITY != 0)? DEFAULT_GRANULARITY : psize);
#else /* WIN32 */
    {
      SYSTEM_INFO system_info;
      GetSystemInfo(&system_info);
      psize = system_info.dwPageSize;
      gsize = ((DEFAULT_GRANULARITY != 0)?
               DEFAULT_GRANULARITY : system_info.dwAllocationGranularity);
    }
#endif /* WIN32 */

    /* Sanity-check configuration:
       size_t must be unsigned and as wide as pointer type.
       ints must be at least 4 bytes.
       alignment must be at least 8.
       Alignment, min chunk size, and page size must all be powers of 2.
    */
    if ((sizeof(size_t) != sizeof(char*)) ||
        (MAX_SIZE_T < MIN_CHUNK_SIZE)  ||
        (sizeof(int) < 4)  ||
        (MALLOC_ALIGNMENT < (size_t)8U) ||
        ((MALLOC_ALIGNMENT & (MALLOC_ALIGNMENT-SIZE_T_ONE)) != 0) ||
        ((MCHUNK_SIZE      & (MCHUNK_SIZE-SIZE_T_ONE))      != 0) ||
        ((gsize            & (gsize-SIZE_T_ONE))            != 0) ||
        ((psize            & (psize-SIZE_T_ONE))            != 0))
      ABORT;
    mparams.granularity = gsize;
    mparams.page_size = psize;
    mparams.mmap_threshold = DEFAULT_MMAP_THRESHOLD;
    mparams.trim_threshold = DEFAULT_TRIM_THRESHOLD;
#if MORECORE_CONTIGUOUS
    mparams.default_mflags = USE_LOCK_BIT|USE_MMAP_BIT;
#else  /* MORECORE_CONTIGUOUS */
    mparams.default_mflags = USE_LOCK_BIT|USE_MMAP_BIT|USE_NONCONTIGUOUS_BIT;
#endif /* MORECORE_CONTIGUOUS */

#if !ONLY_MSPACES
    /* Set up lock for main malloc area */
    gm->mflags = mparams.default_mflags;
    (void)INITIAL_LOCK(&gm->mutex);
#endif
#if LOCK_AT_FORK
    pthread_atfork(&pre_fork, &post_fork_parent, &post_fork_child);
#endif

    {
#if USE_DEV_RANDOM
      int fd;
      unsigned char buf[sizeof(size_t)];
      /* Try to use /dev/urandom, else fall back on using time */
      if ((fd = open("/dev/urandom", O_RDONLY)) >= 0 &&
          read(fd, buf, sizeof(buf)) == sizeof(buf)) {
        magic = *((size_t *) buf);
        close(fd);
      }
      else
#endif /* USE_DEV_RANDOM */
#ifdef WIN32
      magic = (size_t)(GetTickCount() ^ (size_t)0x55555555U);
#elif defined(LACKS_TIME_H)
      magic = (size_t)&magic ^ (size_t)0x55555555U;
#else
      magic = (size_t)(time(0) ^ (size_t)0x55555555U);
#endif
      magic |= (size_t)8U;    /* ensure nonzero */
      magic &= ~(size_t)7U;   /* improve chances of fault for bad values */
      /* Until memory modes commonly available, use volatile-write */
      (*(volatile size_t *)(&(mparams.magic))) = magic;
    }
  }

  RELEASE_MALLOC_GLOBAL_LOCK();
  return 1;
}

/* support for mallopt */
static int change_mparam(int param_number, int value) {
  size_t val;
  ensure_initialization();
  val = (value == -1)? MAX_SIZE_T : (size_t)value;
  switch(param_number) {
  case M_TRIM_THRESHOLD:
    mparams.trim_threshold = val;
    return 1;
  case M_GRANULARITY:
    if (val >= mparams.page_size && ((val & (val-1)) == 0)) {
      mparams.granularity = val;
      return 1;
    }
    else
      return 0;
  case M_MMAP_THRESHOLD:
    mparams.mmap_threshold = val;
    return 1;
  default:
    return 0;
  }
}

#if DEBUG
/* ------------------------- Debugging Support --------------------------- */

/* Check properties of any chunk, whether free, inuse, mmapped etc  */
static void do_check_any_chunk(mstate m, mchunkptr p) {
  assert((is_aligned(chunk2mem(p))) || (p->head == FENCEPOST_HEAD));
  assert(ok_address(m, p));
}

/* Check properties of top chunk */
static void do_check_top_chunk(mstate m, mchunkptr p) {
  msegmentptr sp = segment_holding(m, (char*)p);
  size_t  sz = p->head & ~INUSE_BITS; /* third-lowest bit can be set! */
  assert(sp != 0);
  assert((is_aligned(chunk2mem(p))) || (p->head == FENCEPOST_HEAD));
  assert(ok_address(m, p));
  assert(sz == m->topsize);
  assert(sz > 0);
  assert(sz == ((sp->base + sp->size) - (char*)p) - TOP_FOOT_SIZE);
  assert(pinuse(p));
  assert(!pinuse(chunk_plus_offset(p, sz)));
}

/* Check properties of (inuse) mmapped chunks */
static void do_check_mmapped_chunk(mstate m, mchunkptr p) {
  size_t  sz = chunksize(p);
  size_t len = (sz + (p->prev_foot) + MMAP_FOOT_PAD);
  assert(is_mmapped(p));
  assert(use_mmap(m));
  assert((is_aligned(chunk2mem(p))) || (p->head == FENCEPOST_HEAD));
  assert(ok_address(m, p));
  assert(!is_small(sz));
  assert((len & (mparams.page_size-SIZE_T_ONE)) == 0);
  assert(chunk_plus_offset(p, sz)->head == FENCEPOST_HEAD);
  assert(chunk_plus_offset(p, sz+SIZE_T_SIZE)->head == 0);
}

/* Check properties of inuse chunks */
static void do_check_inuse_chunk(mstate m, mchunkptr p) {
  do_check_any_chunk(m, p);
  assert(is_inuse(p));
  assert(next_pinuse(p));
  /* If not pinuse and not mmapped, previous chunk has OK offset */
  assert(is_mmapped(p) || pinuse(p) || next_chunk(prev_chunk(p)) == p);
  if (is_mmapped(p))
    do_check_mmapped_chunk(m, p);
}

/* Check properties of free chunks */
static void do_check_free_chunk(mstate m, mchunkptr p) {
  size_t sz = chunksize(p);
  mchunkptr next = chunk_plus_offset(p, sz);
  do_check_any_chunk(m, p);
  assert(!is_inuse(p));
  assert(!next_pinuse(p));
  assert (!is_mmapped(p));
  if (p != m->dv && p != m->top) {
    if (sz >= MIN_CHUNK_SIZE) {
      assert((sz & CHUNK_ALIGN_MASK) == 0);
      assert(is_aligned(chunk2mem(p)));
      assert(next->prev_foot == sz);
      assert(pinuse(p));
      assert (next == m->top || is_inuse(next));
      assert(p->fd->bk == p);
      assert(p->bk->fd == p);
    }
    else  /* markers are always of size SIZE_T_SIZE */
      assert(sz == SIZE_T_SIZE);
  }
}

/* Check properties of malloced chunks at the point they are malloced */
static void do_check_malloced_chunk(mstate m, void* mem, size_t s) {
  if (mem != 0) {
    mchunkptr p = mem2chunk(mem);
    size_t sz = p->head & ~INUSE_BITS;
    do_check_inuse_chunk(m, p);
    assert((sz & CHUNK_ALIGN_MASK) == 0);
    assert(sz >= MIN_CHUNK_SIZE);
    assert(sz >= s);
    /* unless mmapped, size is less than MIN_CHUNK_SIZE more than request */
    assert(is_mmapped(p) || sz < (s + MIN_CHUNK_SIZE));
  }
}

/* Check a tree and its subtrees.  */
static void do_check_tree(mstate m, tchunkptr t) {
  tchunkptr head = 0;
  tchunkptr u = t;
  bindex_t tindex = t->index;
  size_t tsize = chunksize(t);
  bindex_t idx;
  compute_tree_index(tsize, idx);
  assert(tindex == idx);
  assert(tsize >= MIN_LARGE_SIZE);
  assert(tsize >= minsize_for_tree_index(idx));
  assert((idx == NTREEBINS-1) || (tsize < minsize_for_tree_index((idx+1))));

  do { /* traverse through chain of same-sized nodes */
    do_check_any_chunk(m, ((mchunkptr)u));
    assert(u->index == tindex);
    assert(chunksize(u) == tsize);
    assert(!is_inuse(u));
    assert(!next_pinuse(u));
    assert(u->fd->bk == u);
    assert(u->bk->fd == u);
    if (u->parent == 0) {
      assert(u->child[0] == 0);
      assert(u->child[1] == 0);
    }
    else {
      assert(head == 0); /* only one node on chain has parent */
      head = u;
      assert(u->parent != u);
      assert (u->parent->child[0] == u ||
              u->parent->child[1] == u ||
              *((tbinptr*)(u->parent)) == u);
      if (u->child[0] != 0) {
        assert(u->child[0]->parent == u);
        assert(u->child[0] != u);
        do_check_tree(m, u->child[0]);
      }
      if (u->child[1] != 0) {
        assert(u->child[1]->parent == u);
        assert(u->child[1] != u);
        do_check_tree(m, u->child[1]);
      }
      if (u->child[0] != 0 && u->child[1] != 0) {
        assert(chunksize(u->child[0]) < chunksize(u->child[1]));
      }
    }
    u = u->fd;
  } while (u != t);
  assert(head != 0);
}

/*  Check all the chunks in a treebin.  */
static void do_check_treebin(mstate m, bindex_t i) {
  tbinptr* tb = treebin_at(m, i);
  tchunkptr t = *tb;
  int empty = (m->treemap & (1U << i)) == 0;
  if (t == 0)
    assert(empty);
  if (!empty)
    do_check_tree(m, t);
}

/*  Check all the chunks in a smallbin.  */
static void do_check_smallbin(mstate m, bindex_t i) {
  sbinptr b = smallbin_at(m, i);
  mchunkptr p = b->bk;
  unsigned int empty = (m->smallmap & (1U << i)) == 0;
  if (p == b)
    assert(empty);
  if (!empty) {
    for (; p != b; p = p->bk) {
      size_t size = chunksize(p);
      mchunkptr q;
      /* each chunk claims to be free */
      do_check_free_chunk(m, p);
      /* chunk belongs in bin */
      assert(small_index(size) == i);
      assert(p->bk == b || chunksize(p->bk) == chunksize(p));
      /* chunk is followed by an inuse chunk */
      q = next_chunk(p);
      if (q->head != FENCEPOST_HEAD)
        do_check_inuse_chunk(m, q);
    }
  }
}

/* Find x in a bin. Used in other check functions. */
static int bin_find(mstate m, mchunkptr x) {
  size_t size = chunksize(x);
  if (is_small(size)) {
    bindex_t sidx = small_index(size);
    sbinptr b = smallbin_at(m, sidx);
    if (smallmap_is_marked(m, sidx)) {
      mchunkptr p = b;
      do {
        if (p == x)
          return 1;
      } while ((p = p->fd) != b);
    }
  }
  else {
    bindex_t tidx;
    compute_tree_index(size, tidx);
    if (treemap_is_marked(m, tidx)) {
      tchunkptr t = *treebin_at(m, tidx);
      size_t sizebits = size << leftshift_for_tree_index(tidx);
      while (t != 0 && chunksize(t) != size) {
        t = t->child[(sizebits >> (SIZE_T_BITSIZE-SIZE_T_ONE)) & 1];
        sizebits <<= 1;
      }
      if (t != 0) {
        tchunkptr u = t;
        do {
          if (u == (tchunkptr)x)
            return 1;
        } while ((u = u->fd) != t);
      }
    }
  }
  return 0;
}

/* Traverse each chunk and check it; return total */
static size_t traverse_and_check(mstate m) {
  size_t sum = 0;
  if (is_initialized(m)) {
    msegmentptr s = &m->seg;
    sum += m->topsize + TOP_FOOT_SIZE;
    while (s != 0) {
      mchunkptr q = align_as_chunk(s->base);
      mchunkptr lastq = 0;
      assert(pinuse(q));
      while (segment_holds(s, q) &&
             q != m->top && q->head != FENCEPOST_HEAD) {
        sum += chunksize(q);
        if (is_inuse(q)) {
          assert(!bin_find(m, q));
          do_check_inuse_chunk(m, q);
        }
        else {
          assert(q == m->dv || bin_find(m, q));
          assert(lastq == 0 || is_inuse(lastq)); /* Not 2 consecutive free */
          do_check_free_chunk(m, q);
        }
        lastq = q;
        q = next_chunk(q);
      }
      s = s->next;
    }
  }
  return sum;
}


/* Check all properties of malloc_state. */
static void do_check_malloc_state(mstate m) {
  bindex_t i;
  size_t total;
  /* check bins */
  for (i = 0; i < NSMALLBINS; ++i)
    do_check_smallbin(m, i);
  for (i = 0; i < NTREEBINS; ++i)
    do_check_treebin(m, i);

  if (m->dvsize != 0) { /* check dv chunk */
    do_check_any_chunk(m, m->dv);
    assert(m->dvsize == chunksize(m->dv));
    assert(m->dvsize >= MIN_CHUNK_SIZE);
    assert(bin_find(m, m->dv) == 0);
  }

  if (m->top != 0) {   /* check top chunk */
    do_check_top_chunk(m, m->top);
    /*assert(m->topsize == chunksize(m->top)); redundant */
    assert(m->topsize > 0);
    assert(bin_find(m, m->top) == 0);
  }

  total = traverse_and_check(m);
  assert(total <= m->footprint);
  assert(m->footprint <= m->max_footprint);
}
#endif /* DEBUG */

/* ----------------------------- statistics ------------------------------ */

#if !NO_MALLINFO
static struct mallinfo internal_mallinfo(mstate m) {
  struct mallinfo nm = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  ensure_initialization();
  if (!PREACTION(m)) {
    check_malloc_state(m);
    if (is_initialized(m)) {
      size_t nfree = SIZE_T_ONE; /* top always free */
      size_t mfree = m->topsize + TOP_FOOT_SIZE;
      size_t sum = mfree;
      msegmentptr s = &m->seg;
      while (s != 0) {
        mchunkptr q = align_as_chunk(s->base);
        while (segment_holds(s, q) &&
               q != m->top && q->head != FENCEPOST_HEAD) {
          size_t sz = chunksize(q);
          sum += sz;
          if (!is_inuse(q)) {
            mfree += sz;
            ++nfree;
          }
          q = next_chunk(q);
        }
        s = s->next;
      }

      nm.arena    = sum;
      nm.ordblks  = nfree;
      nm.hblkhd   = m->footprint - sum;
      nm.usmblks  = m->max_footprint;
      nm.uordblks = m->footprint - mfree;
      nm.fordblks = mfree;
      nm.keepcost = m->topsize;
    }

    POSTACTION(m);
  }
  return nm;
}
#endif /* !NO_MALLINFO */

#if !NO_MALLOC_STATS
static void internal_malloc_stats(mstate m) {
  ensure_initialization();
  if (!PREACTION(m)) {
    size_t maxfp = 0;
    size_t fp = 0;
    size_t used = 0;
    check_malloc_state(m);
    if (is_initialized(m)) {
      msegmentptr s = &m->seg;
      maxfp = m->max_footprint;
      fp = m->footprint;
      used = fp - (m->topsize + TOP_FOOT_SIZE);

      while (s != 0) {
        mchunkptr q = align_as_chunk(s->base);
        while (segment_holds(s, q) &&
               q != m->top && q->head != FENCEPOST_HEAD) {
          if (!is_inuse(q))
            used -= chunksize(q);
          q = next_chunk(q);
        }
        s = s->next;
      }
    }
    POSTACTION(m); /* drop lock */
    fprintf(stderr, "max system bytes = %10lu\n", (unsigned long)(maxfp));
    fprintf(stderr, "system bytes     = %10lu\n", (unsigned long)(fp));
    fprintf(stderr, "in use bytes     = %10lu\n", (unsigned long)(used));
  }
}
#endif /* NO_MALLOC_STATS */

/* ----------------------- Operations on smallbins ----------------------- */

/*
  Various forms of linking and unlinking are defined as macros.  Even
  the ones for trees, which are very long but have very short typical
  paths.  This is ugly but reduces reliance on inlining support of
  compilers.
*/

/* Link a free chunk into a smallbin  */
#define insert_small_chunk(M, P, S) {\
  bindex_t I  = small_index(S);\
  mchunkptr B = smallbin_at(M, I);\
  mchunkptr F = B;\
  assert(S >= MIN_CHUNK_SIZE);\
  if (!smallmap_is_marked(M, I))\
    mark_smallmap(M, I);\
  else if (RTCHECK(ok_address(M, B->fd)))\
    F = B->fd;\
  else {\
    CORRUPTION_ERROR_ACTION(M);\
  }\
  B->fd = P;\
  F->bk = P;\
  P->fd = F;\
  P->bk = B;\
}

/* Unlink a chunk from a smallbin  */
#define unlink_small_chunk(M, P, S) {\
  mchunkptr F = P->fd;\
  mchunkptr B = P->bk;\
  bindex_t I = small_index(S);\
  assert(P != B);\
  assert(P != F);\
  assert(chunksize(P) == small_index2size(I));\
  if (RTCHECK(F == smallbin_at(M,I) || (ok_address(M, F) && F->bk == P))) { \
    if (B == F) {\
      clear_smallmap(M, I);\
    }\
    else if (RTCHECK(B == smallbin_at(M,I) ||\
                     (ok_address(M, B) && B->fd == P))) {\
      F->bk = B;\
      B->fd = F;\
    }\
    else {\
      CORRUPTION_ERROR_ACTION(M);\
    }\
  }\
  else {\
    CORRUPTION_ERROR_ACTION(M);\
  }\
}

/* Unlink the first chunk from a smallbin */
#define unlink_first_small_chunk(M, B, P, I) {\
  mchunkptr F = P->fd;\
  assert(P != B);\
  assert(P != F);\
  assert(chunksize(P) == small_index2size(I));\
  if (B == F) {\
    clear_smallmap(M, I);\
  }\
  else if (RTCHECK(ok_address(M, F) && F->bk == P)) {\
    F->bk = B;\
    B->fd = F;\
  }\
  else {\
    CORRUPTION_ERROR_ACTION(M);\
  }\
}

/* Replace dv node, binning the old one */
/* Used only when dvsize known to be small */
#define replace_dv(M, P, S) {\
  size_t DVS = M->dvsize;\
  assert(is_small(DVS));\
  if (DVS != 0) {\
    mchunkptr DV = M->dv;\
    insert_small_chunk(M, DV, DVS);\
  }\
  M->dvsize = S;\
  M->dv = P;\
}

/* ------------------------- Operations on trees ------------------------- */

/* Insert chunk into tree */
#define insert_large_chunk(M, X, S) {\
  tbinptr* H;\
  bindex_t I;\
  compute_tree_index(S, I);\
  H = treebin_at(M, I);\
  X->index = I;\
  X->child[0] = X->child[1] = 0;\
  if (!treemap_is_marked(M, I)) {\
    mark_treemap(M, I);\
    *H = X;\
    X->parent = (tchunkptr)H;\
    X->fd = X->bk = X;\
  }\
  else {\
    tchunkptr T = *H;\
    size_t K = S << leftshift_for_tree_index(I);\
    for (;;) {\
      if (chunksize(T) != S) {\
        tchunkptr* C = &(T->child[(K >> (SIZE_T_BITSIZE-SIZE_T_ONE)) & 1]);\
        K <<= 1;\
        if (*C != 0)\
          T = *C;\
        else if (RTCHECK(ok_address(M, C))) {\
          *C = X;\
          X->parent = T;\
          X->fd = X->bk = X;\
          break;\
        }\
        else {\
          CORRUPTION_ERROR_ACTION(M);\
          break;\
        }\
      }\
      else {\
        tchunkptr F = T->fd;\
        if (RTCHECK(ok_address(M, T) && ok_address(M, F))) {\
          T->fd = F->bk = X;\
          X->fd = F;\
          X->bk = T;\
          X->parent = 0;\
          break;\
        }\
        else {\
          CORRUPTION_ERROR_ACTION(M);\
          break;\
        }\
      }\
    }\
  }\
}

/*
  Unlink steps:

  1. If x is a chained node, unlink it from its same-sized fd/bk links
     and choose its bk node as its replacement.
  2. If x was the last node of its size, but not a leaf node, it must
     be replaced with a leaf node (not merely one with an open left or
     right), to make sure that lefts and rights of descendents
     correspond properly to bit masks.  We use the rightmost descendent
     of x.  We could use any other leaf, but this is easy to locate and
     tends to counteract removal of leftmosts elsewhere, and so keeps
     paths shorter than minimally guaranteed.  This doesn't loop much
     because on average a node in a tree is near the bottom.
  3. If x is the base of a chain (i.e., has parent links) relink
     x's parent and children to x's replacement (or null if none).
*/

#define unlink_large_chunk(M, X) {\
  tchunkptr XP = X->parent;\
  tchunkptr R;\
  if (X->bk != X) {\
    tchunkptr F = X->fd;\
    R = X->bk;\
    if (RTCHECK(ok_address(M, F) && F->bk == X && R->fd == X)) {\
      F->bk = R;\
      R->fd = F;\
    }\
    else {\
      CORRUPTION_ERROR_ACTION(M);\
    }\
  }\
  else {\
    tchunkptr* RP;\
    if (((R = *(RP = &(X->child[1]))) != 0) ||\
        ((R = *(RP = &(X->child[0]))) != 0)) {\
      tchunkptr* CP;\
      while ((*(CP = &(R->child[1])) != 0) ||\
             (*(CP = &(R->child[0])) != 0)) {\
        R = *(RP = CP);\
      }\
      if (RTCHECK(ok_address(M, RP)))\
        *RP = 0;\
      else {\
        CORRUPTION_ERROR_ACTION(M);\
      }\
    }\
  }\
  if (XP != 0) {\
    tbinptr* H = treebin_at(M, X->index);\
    if (X == *H) {\
      if ((*H = R) == 0) \
        clear_treemap(M, X->index);\
    }\
    else if (RTCHECK(ok_address(M, XP))) {\
      if (XP->child[0] == X) \
        XP->child[0] = R;\
      else \
        XP->child[1] = R;\
    }\
    else\
      CORRUPTION_ERROR_ACTION(M);\
    if (R != 0) {\
      if (RTCHECK(ok_address(M, R))) {\
        tchunkptr C0, C1;\
        R->parent = XP;\
        if ((C0 = X->child[0]) != 0) {\
          if (RTCHECK(ok_address(M, C0))) {\
            R->child[0] = C0;\
            C0->parent = R;\
          }\
          else\
            CORRUPTION_ERROR_ACTION(M);\
        }\
        if ((C1 = X->child[1]) != 0) {\
          if (RTCHECK(ok_address(M, C1))) {\
            R->child[1] = C1;\
            C1->parent = R;\
          }\
          else\
            CORRUPTION_ERROR_ACTION(M);\
        }\
      }\
      else\
        CORRUPTION_ERROR_ACTION(M);\
    }\
  }\
}

/* Relays to large vs small bin operations */

#define insert_chunk(M, P, S)\
  if (is_small(S)) insert_small_chunk(M, P, S)\
  else { tchunkptr TP = (tchunkptr)(P); insert_large_chunk(M, TP, S); }

#define unlink_chunk(M, P, S)\
  if (is_small(S)) unlink_small_chunk(M, P, S)\
  else { tchunkptr TP = (tchunkptr)(P); unlink_large_chunk(M, TP); }


/* Relays to internal calls to malloc/free from realloc, memalign etc */

#if ONLY_MSPACES
#define internal_malloc(m, b) mspace_malloc(m, b)
#define internal_free(m, mem) mspace_free(m,mem);
#else /* ONLY_MSPACES */
#if MSPACES
#define internal_malloc(m, b)\
  ((m == gm)? dlmalloc(b) : mspace_malloc(m, b))
#define internal_free(m, mem)\
   if (m == gm) dlfree(mem); else mspace_free(m,mem);
#else /* MSPACES */
#define internal_malloc(m, b) dlmalloc(b)
#define internal_free(m, mem) dlfree(mem)
#endif /* MSPACES */
#endif /* ONLY_MSPACES */

/* -----------------------  Direct-mmapping chunks ----------------------- */

/*
  Directly mmapped chunks are set up with an offset to the start of
  the mmapped region stored in the prev_foot field of the chunk. This
  allows reconstruction of the required argument to MUNMAP when freed,
  and also allows adjustment of the returned chunk to meet alignment
  requirements (especially in memalign).
*/

/* Malloc using mmap */
static void* mmap_alloc(mstate m, size_t nb) {
  size_t mmsize = mmap_align(nb + SIX_SIZE_T_SIZES + CHUNK_ALIGN_MASK);
  if (m->footprint_limit != 0) {
    size_t fp = m->footprint + mmsize;
    if (fp <= m->footprint || fp > m->footprint_limit)
      return 0;
  }
  if (mmsize > nb) {     /* Check for wrap around 0 */
    char* mm = (char*)(CALL_DIRECT_MMAP(mmsize));
    if (mm != CMFAIL) {
      size_t offset = align_offset(chunk2mem(mm));
      size_t psize = mmsize - offset - MMAP_FOOT_PAD;
      mchunkptr p = (mchunkptr)(mm + offset);
      p->prev_foot = offset;
      p->head = psize;
      mark_inuse_foot(m, p, psize);
      chunk_plus_offset(p, psize)->head = FENCEPOST_HEAD;
      chunk_plus_offset(p, psize+SIZE_T_SIZE)->head = 0;

      if (m->least_addr == 0 || mm < m->least_addr)
        m->least_addr = mm;
      if ((m->footprint += mmsize) > m->max_footprint)
        m->max_footprint = m->footprint;
      assert(is_aligned(chunk2mem(p)));
      check_mmapped_chunk(m, p);
      return chunk2mem(p);
    }
  }
  return 0;
}

/* Realloc using mmap */
static mchunkptr mmap_resize(mstate m, mchunkptr oldp, size_t nb, int flags) {
  size_t oldsize = chunksize(oldp);
  (void)flags; /* placate people compiling -Wunused */
  if (is_small(nb)) /* Can't shrink mmap regions below small size */
    return 0;
  /* Keep old chunk if big enough but not too big */
  if (oldsize >= nb + SIZE_T_SIZE &&
      (oldsize - nb) <= (mparams.granularity << 1))
    return oldp;
  else {
    size_t offset = oldp->prev_foot;
    size_t oldmmsize = oldsize + offset + MMAP_FOOT_PAD;
    size_t newmmsize = mmap_align(nb + SIX_SIZE_T_SIZES + CHUNK_ALIGN_MASK);
    char* cp = (char*)CALL_MREMAP((char*)oldp - offset,
                                  oldmmsize, newmmsize, flags);
    if (cp != CMFAIL) {
      mchunkptr newp = (mchunkptr)(cp + offset);
      size_t psize = newmmsize - offset - MMAP_FOOT_PAD;
      newp->head = psize;
      mark_inuse_foot(m, newp, psize);
      chunk_plus_offset(newp, psize)->head = FENCEPOST_HEAD;
      chunk_plus_offset(newp, psize+SIZE_T_SIZE)->head = 0;

      if (cp < m->least_addr)
        m->least_addr = cp;
      if ((m->footprint += newmmsize - oldmmsize) > m->max_footprint)
        m->max_footprint = m->footprint;
      check_mmapped_chunk(m, newp);
      return newp;
    }
  }
  return 0;
}


/* -------------------------- mspace management -------------------------- */

/* Initialize top chunk and its size */
static void init_top(mstate m, mchunkptr p, size_t psize) {
  /* Ensure alignment */
  size_t offset = align_offset(chunk2mem(p));
  p = (mchunkptr)((char*)p + offset);
  psize -= offset;

  m->top = p;
  m->topsize = psize;
  p->head = psize | PINUSE_BIT;
  /* set size of fake trailing chunk holding overhead space only once */
  chunk_plus_offset(p, psize)->head = TOP_FOOT_SIZE;
  m->trim_check = mparams.trim_threshold; /* reset on each update */
}

/* Initialize bins for a new mstate that is otherwise zeroed out */
static void init_bins(mstate m) {
  /* Establish circular links for smallbins */
  bindex_t i;
  for (i = 0; i < NSMALLBINS; ++i) {
    sbinptr bin = smallbin_at(m,i);
    bin->fd = bin->bk = bin;
  }
}

#if PROCEED_ON_ERROR

/* default corruption action */
static void reset_on_error(mstate m) {
  int i;
  ++malloc_corruption_error_count;
  /* Reinitialize fields to forget about all memory */
  m->smallmap = m->treemap = 0;
  m->dvsize = m->topsize = 0;
  m->seg.base = 0;
  m->seg.size = 0;
  m->seg.next = 0;
  m->top = m->dv = 0;
  for (i = 0; i < NTREEBINS; ++i)
    *treebin_at(m, i) = 0;
  init_bins(m);
}
#endif /* PROCEED_ON_ERROR */

/* Allocate chunk and prepend remainder with chunk in successor base. */
static void* prepend_alloc(mstate m, char* newbase, char* oldbase,
                           size_t nb) {
  mchunkptr p = align_as_chunk(newbase);
  mchunkptr oldfirst = align_as_chunk(oldbase);
  size_t psize = (char*)oldfirst - (char*)p;
  mchunkptr q = chunk_plus_offset(p, nb);
  size_t qsize = psize - nb;
  set_size_and_pinuse_of_inuse_chunk(m, p, nb);

  assert((char*)oldfirst > (char*)q);
  assert(pinuse(oldfirst));
  assert(qsize >= MIN_CHUNK_SIZE);

  /* consolidate remainder with first chunk of old base */
  if (oldfirst == m->top) {
    size_t tsize = m->topsize += qsize;
    m->top = q;
    q->head = tsize | PINUSE_BIT;
    check_top_chunk(m, q);
  }
  else if (oldfirst == m->dv) {
    size_t dsize = m->dvsize += qsize;
    m->dv = q;
    set_size_and_pinuse_of_free_chunk(q, dsize);
  }
  else {
    if (!is_inuse(oldfirst)) {
      size_t nsize = chunksize(oldfirst);
      unlink_chunk(m, oldfirst, nsize);
      oldfirst = chunk_plus_offset(oldfirst, nsize);
      qsize += nsize;
    }
    set_free_with_pinuse(q, qsize, oldfirst);
    insert_chunk(m, q, qsize);
    check_free_chunk(m, q);
  }

  check_malloced_chunk(m, chunk2mem(p), nb);
  return chunk2mem(p);
}

/* Add a segment to hold a new noncontiguous region */
static void add_segment(mstate m, char* tbase, size_t tsize, flag_t mmapped) {
  /* Determine locations and sizes of segment, fenceposts, old top */
  char* old_top = (char*)m->top;
  msegmentptr oldsp = segment_holding(m, old_top);
  char* old_end = oldsp->base + oldsp->size;
  size_t ssize = pad_request(sizeof(struct malloc_segment));
  char* rawsp = old_end - (ssize + FOUR_SIZE_T_SIZES + CHUNK_ALIGN_MASK);
  size_t offset = align_offset(chunk2mem(rawsp));
  char* asp = rawsp + offset;
  char* csp = (asp < (old_top + MIN_CHUNK_SIZE))? old_top : asp;
  mchunkptr sp = (mchunkptr)csp;
  msegmentptr ss = (msegmentptr)(chunk2mem(sp));
  mchunkptr tnext = chunk_plus_offset(sp, ssize);
  mchunkptr p = tnext;
  int nfences = 0;

  /* reset top to new space */
  init_top(m, (mchunkptr)tbase, tsize - TOP_FOOT_SIZE);

  /* Set up segment record */
  assert(is_aligned(ss));
  set_size_and_pinuse_of_inuse_chunk(m, sp, ssize);
  *ss = m->seg; /* Push current record */
  m->seg.base = tbase;
  m->seg.size = tsize;
  m->seg.sflags = mmapped;
  m->seg.next = ss;

  /* Insert trailing fenceposts */
  for (;;) {
    mchunkptr nextp = chunk_plus_offset(p, SIZE_T_SIZE);
    p->head = FENCEPOST_HEAD;
    ++nfences;
    if ((char*)(&(nextp->head)) < old_end)
      p = nextp;
    else
      break;
  }
  assert(nfences >= 2);

  /* Insert the rest of old top into a bin as an ordinary free chunk */
  if (csp != old_top) {
    mchunkptr q = (mchunkptr)old_top;
    size_t psize = csp - old_top;
    mchunkptr tn = chunk_plus_offset(q, psize);
    set_free_with_pinuse(q, psize, tn);
    insert_chunk(m, q, psize);
  }

  check_top_chunk(m, m->top);
}

/* -------------------------- System allocation -------------------------- */

/* Get memory from system using MORECORE or MMAP */
static void* sys_alloc(mstate m, size_t nb) {
  char* tbase = CMFAIL;
  size_t tsize = 0;
  flag_t mmap_flag = 0;
  size_t asize; /* allocation size */

  ensure_initialization();

  /* Directly map large chunks, but only if already initialized */
  if (use_mmap(m) && nb >= mparams.mmap_threshold && m->topsize != 0) {
    void* mem = mmap_alloc(m, nb);
    if (mem != 0)
      return mem;
  }

  asize = granularity_align(nb + SYS_ALLOC_PADDING);
  if (asize <= nb)
    return 0; /* wraparound */
  if (m->footprint_limit != 0) {
    size_t fp = m->footprint + asize;
    if (fp <= m->footprint || fp > m->footprint_limit)
      return 0;
  }

  /*
    Try getting memory in any of three ways (in most-preferred to
    least-preferred order):
    1. A call to MORECORE that can normally contiguously extend memory.
       (disabled if not MORECORE_CONTIGUOUS or not HAVE_MORECORE or
       or main space is mmapped or a previous contiguous call failed)
    2. A call to MMAP new space (disabled if not HAVE_MMAP).
       Note that under the default settings, if MORECORE is unable to
       fulfill a request, and HAVE_MMAP is true, then mmap is
       used as a noncontiguous system allocator. This is a useful backup
       strategy for systems with holes in address spaces -- in this case
       sbrk cannot contiguously expand the heap, but mmap may be able to
       find space.
    3. A call to MORECORE that cannot usually contiguously extend memory.
       (disabled if not HAVE_MORECORE)

   In all cases, we need to request enough bytes from system to ensure
   we can malloc nb bytes upon success, so pad with enough space for
   top_foot, plus alignment-pad to make sure we don't lose bytes if
   not on boundary, and round this up to a granularity unit.
  */

  if (MORECORE_CONTIGUOUS && !use_noncontiguous(m)) {
    char* br = CMFAIL;
    size_t ssize = asize; /* sbrk call size */
    msegmentptr ss = (m->top == 0)? 0 : segment_holding(m, (char*)m->top);
    ACQUIRE_MALLOC_GLOBAL_LOCK();

    if (ss == 0) {  /* First time through or recovery */
      char* base = (char*)CALL_MORECORE(0);
      if (base != CMFAIL) {
        size_t fp;
        /* Adjust to end on a page boundary */
        if (!is_page_aligned(base))
          ssize += (page_align((size_t)base) - (size_t)base);
        fp = m->footprint + ssize; /* recheck limits */
        if (ssize > nb && ssize < HALF_MAX_SIZE_T &&
            (m->footprint_limit == 0 ||
             (fp > m->footprint && fp <= m->footprint_limit)) &&
            (br = (char*)(CALL_MORECORE(ssize))) == base) {
          tbase = base;
          tsize = ssize;
        }
      }
    }
    else {
      /* Subtract out existing available top space from MORECORE request. */
      ssize = granularity_align(nb - m->topsize + SYS_ALLOC_PADDING);
      /* Use mem here only if it did continuously extend old space */
      if (ssize < HALF_MAX_SIZE_T &&
          (br = (char*)(CALL_MORECORE(ssize))) == ss->base+ss->size) {
        tbase = br;
        tsize = ssize;
      }
    }

    if (tbase == CMFAIL) {    /* Cope with partial failure */
      if (br != CMFAIL) {    /* Try to use/extend the space we did get */
        if (ssize < HALF_MAX_SIZE_T &&
            ssize < nb + SYS_ALLOC_PADDING) {
          size_t esize = granularity_align(nb + SYS_ALLOC_PADDING - ssize);
          if (esize < HALF_MAX_SIZE_T) {
            char* end = (char*)CALL_MORECORE(esize);
            if (end != CMFAIL)
              ssize += esize;
            else {            /* Can't use; try to release */
              (void) CALL_MORECORE(-ssize);
              br = CMFAIL;
            }
          }
        }
      }
      if (br != CMFAIL) {    /* Use the space we did get */
        tbase = br;
        tsize = ssize;
      }
      else
        disable_contiguous(m); /* Don't try contiguous path in the future */
    }

    RELEASE_MALLOC_GLOBAL_LOCK();
  }

  if (HAVE_MMAP && tbase == CMFAIL) {  /* Try MMAP */
    char* mp = (char*)(CALL_MMAP(asize));
    if (mp != CMFAIL) {
      tbase = mp;
      tsize = asize;
      mmap_flag = USE_MMAP_BIT;
    }
  }

  if (HAVE_MORECORE && tbase == CMFAIL) { /* Try noncontiguous MORECORE */
    if (asize < HALF_MAX_SIZE_T) {
      char* br = CMFAIL;
      char* end = CMFAIL;
      ACQUIRE_MALLOC_GLOBAL_LOCK();
      br = (char*)(CALL_MORECORE(asize));
      end = (char*)(CALL_MORECORE(0));
      RELEASE_MALLOC_GLOBAL_LOCK();
      if (br != CMFAIL && end != CMFAIL && br < end) {
        size_t ssize = end - br;
        if (ssize > nb + TOP_FOOT_SIZE) {
          tbase = br;
          tsize = ssize;
        }
      }
    }
  }

  if (tbase != CMFAIL) {

    if ((m->footprint += tsize) > m->max_footprint)
      m->max_footprint = m->footprint;

    if (!is_initialized(m)) { /* first-time initialization */
      if (m->least_addr == 0 || tbase < m->least_addr)
        m->least_addr = tbase;
      m->seg.base = tbase;
      m->seg.size = tsize;
      m->seg.sflags = mmap_flag;
      m->magic = mparams.magic;
      m->release_checks = MAX_RELEASE_CHECK_RATE;
      init_bins(m);
#if !ONLY_MSPACES
      if (is_global(m))
        init_top(m, (mchunkptr)tbase, tsize - TOP_FOOT_SIZE);
      else
#endif
      {
        /* Offset top by embedded malloc_state */
        mchunkptr mn = next_chunk(mem2chunk(m));
        init_top(m, mn, (size_t)((tbase + tsize) - (char*)mn) -TOP_FOOT_SIZE);
      }
    }

    else {
      /* Try to merge with an existing segment */
      msegmentptr sp = &m->seg;
      /* Only consider most recent segment if traversal suppressed */
      while (sp != 0 && tbase != sp->base + sp->size)
        sp = (NO_SEGMENT_TRAVERSAL) ? 0 : sp->next;
      if (sp != 0 &&
          !is_extern_segment(sp) &&
          (sp->sflags & USE_MMAP_BIT) == mmap_flag &&
          segment_holds(sp, m->top)) { /* append */
        sp->size += tsize;
        init_top(m, m->top, m->topsize + tsize);
      }
      else {
        if (tbase < m->least_addr)
          m->least_addr = tbase;
        sp = &m->seg;
        while (sp != 0 && sp->base != tbase + tsize)
          sp = (NO_SEGMENT_TRAVERSAL) ? 0 : sp->next;
        if (sp != 0 &&
            !is_extern_segment(sp) &&
            (sp->sflags & USE_MMAP_BIT) == mmap_flag) {
          char* oldbase = sp->base;
          sp->base = tbase;
          sp->size += tsize;
          return prepend_alloc(m, tbase, oldbase, nb);
        }
        else
          add_segment(m, tbase, tsize, mmap_flag);
      }
    }

    if (nb < m->topsize) { /* Allocate from new or extended top space */
      size_t rsize = m->topsize -= nb;
      mchunkptr p = m->top;
      mchunkptr r = m->top = chunk_plus_offset(p, nb);
      r->head = rsize | PINUSE_BIT;
      set_size_and_pinuse_of_inuse_chunk(m, p, nb);
      check_top_chunk(m, m->top);
      check_malloced_chunk(m, chunk2mem(p), nb);
      return chunk2mem(p);
    }
  }

  MALLOC_FAILURE_ACTION;
  return 0;
}

/* -----------------------  system deallocation -------------------------- */

/* Unmap and unlink any mmapped segments that don't contain used chunks */
static size_t release_unused_segments(mstate m) {
  size_t released = 0;
  int nsegs = 0;
  msegmentptr pred = &m->seg;
  msegmentptr sp = pred->next;
  while (sp != 0) {
    char* base = sp->base;
    size_t size = sp->size;
    msegmentptr next = sp->next;
    ++nsegs;
    if (is_mmapped_segment(sp) && !is_extern_segment(sp)) {
      mchunkptr p = align_as_chunk(base);
      size_t psize = chunksize(p);
      /* Can unmap if first chunk holds entire segment and not pinned */
      if (!is_inuse(p) && (char*)p + psize >= base + size - TOP_FOOT_SIZE) {
        tchunkptr tp = (tchunkptr)p;
        assert(segment_holds(sp, (char*)sp));
        if (p == m->dv) {
          m->dv = 0;
          m->dvsize = 0;
        }
        else {
          unlink_large_chunk(m, tp);
        }
        if (CALL_MUNMAP(base, size) == 0) {
          released += size;
          m->footprint -= size;
          /* unlink obsoleted record */
          sp = pred;
          sp->next = next;
        }
        else { /* back out if cannot unmap */
          insert_large_chunk(m, tp, psize);
        }
      }
    }
    if (NO_SEGMENT_TRAVERSAL) /* scan only first segment */
      break;
    pred = sp;
    sp = next;
  }
  /* Reset check counter */
  m->release_checks = (((size_t) nsegs > (size_t) MAX_RELEASE_CHECK_RATE)?
                       (size_t) nsegs : (size_t) MAX_RELEASE_CHECK_RATE);
  return released;
}

static int sys_trim(mstate m, size_t pad) {
  size_t released = 0;
  ensure_initialization();
  if (pad < MAX_REQUEST && is_initialized(m)) {
    pad += TOP_FOOT_SIZE; /* ensure enough room for segment overhead */

    if (m->topsize > pad) {
      /* Shrink top space in granularity-size units, keeping at least one */
      size_t unit = mparams.granularity;
      size_t extra = ((m->topsize - pad + (unit - SIZE_T_ONE)) / unit -
                      SIZE_T_ONE) * unit;
      msegmentptr sp = segment_holding(m, (char*)m->top);

      if (!is_extern_segment(sp)) {
        if (is_mmapped_segment(sp)) {
          if (HAVE_MMAP &&
              sp->size >= extra &&
              !has_segment_link(m, sp)) { /* can't shrink if pinned */
            size_t newsize = sp->size - extra;
            (void)newsize; /* placate people compiling -Wunused-variable */
            /* Prefer mremap, fall back to munmap */
            if ((CALL_MREMAP(sp->base, sp->size, newsize, 0) != MFAIL) ||
                (CALL_MUNMAP(sp->base + newsize, extra) == 0)) {
              released = extra;
            }
          }
        }
        else if (HAVE_MORECORE) {
          if (extra >= HALF_MAX_SIZE_T) /* Avoid wrapping negative */
            extra = (HALF_MAX_SIZE_T) + SIZE_T_ONE - unit;
          ACQUIRE_MALLOC_GLOBAL_LOCK();
          {
            /* Make sure end of memory is where we last set it. */
            char* old_br = (char*)(CALL_MORECORE(0));
            if (old_br == sp->base + sp->size) {
              char* rel_br = (char*)(CALL_MORECORE(-extra));
              char* new_br = (char*)(CALL_MORECORE(0));
              if (rel_br != CMFAIL && new_br < old_br)
                released = old_br - new_br;
            }
          }
          RELEASE_MALLOC_GLOBAL_LOCK();
        }
      }

      if (released != 0) {
        sp->size -= released;
        m->footprint -= released;
        init_top(m, m->top, m->topsize - released);
        check_top_chunk(m, m->top);
      }
    }

    /* Unmap any unused mmapped segments */
    if (HAVE_MMAP)
      released += release_unused_segments(m);

    /* On failure, disable autotrim to avoid repeated failed future calls */
    if (released == 0 && m->topsize > m->trim_check)
      m->trim_check = MAX_SIZE_T;
  }

  return (released != 0)? 1 : 0;
}

/* Consolidate and bin a chunk. Differs from exported versions
   of free mainly in that the chunk need not be marked as inuse.
*/
static void dispose_chunk(mstate m, mchunkptr p, size_t psize) {
  mchunkptr next = chunk_plus_offset(p, psize);
  if (!pinuse(p)) {
    mchunkptr prev;
    size_t prevsize = p->prev_foot;
    if (is_mmapped(p)) {
      psize += prevsize + MMAP_FOOT_PAD;
      if (CALL_MUNMAP((char*)p - prevsize, psize) == 0)
        m->footprint -= psize;
      return;
    }
    prev = chunk_minus_offset(p, prevsize);
    psize += prevsize;
    p = prev;
    if (RTCHECK(ok_address(m, prev))) { /* consolidate backward */
      if (p != m->dv) {
        unlink_chunk(m, p, prevsize);
      }
      else if ((next->head & INUSE_BITS) == INUSE_BITS) {
        m->dvsize = psize;
        set_free_with_pinuse(p, psize, next);
        return;
      }
    }
    else {
      CORRUPTION_ERROR_ACTION(m);
      return;
    }
  }
  if (RTCHECK(ok_address(m, next))) {
    if (!cinuse(next)) {  /* consolidate forward */
      if (next == m->top) {
        size_t tsize = m->topsize += psize;
        m->top = p;
        p->head = tsize | PINUSE_BIT;
        if (p == m->dv) {
          m->dv = 0;
          m->dvsize = 0;
        }
        return;
      }
      else if (next == m->dv) {
        size_t dsize = m->dvsize += psize;
        m->dv = p;
        set_size_and_pinuse_of_free_chunk(p, dsize);
        return;
      }
      else {
        size_t nsize = chunksize(next);
        psize += nsize;
        unlink_chunk(m, next, nsize);
        set_size_and_pinuse_of_free_chunk(p, psize);
        if (p == m->dv) {
          m->dvsize = psize;
          return;
        }
      }
    }
    else {
      set_free_with_pinuse(p, psize, next);
    }
    insert_chunk(m, p, psize);
  }
  else {
    CORRUPTION_ERROR_ACTION(m);
  }
}

/* ---------------------------- malloc --------------------------- */

/* allocate a large request from the best fitting chunk in a treebin */
static void* tmalloc_large(mstate m, size_t nb) {
  tchunkptr v = 0;
  size_t rsize = -nb; /* Unsigned negation */
  tchunkptr t;
  bindex_t idx;
  compute_tree_index(nb, idx);
  if ((t = *treebin_at(m, idx)) != 0) {
    /* Traverse tree for this bin looking for node with size == nb */
    size_t sizebits = nb << leftshift_for_tree_index(idx);
    tchunkptr rst = 0;  /* The deepest untaken right subtree */
    for (;;) {
      tchunkptr rt;
      size_t trem = chunksize(t) - nb;
      if (trem < rsize) {
        v = t;
        if ((rsize = trem) == 0)
          break;
      }
      rt = t->child[1];
      t = t->child[(sizebits >> (SIZE_T_BITSIZE-SIZE_T_ONE)) & 1];
      if (rt != 0 && rt != t)
        rst = rt;
      if (t == 0) {
        t = rst; /* set t to least subtree holding sizes > nb */
        break;
      }
      sizebits <<= 1;
    }
  }
  if (t == 0 && v == 0) { /* set t to root of next non-empty treebin */
    binmap_t leftbits = left_bits(idx2bit(idx)) & m->treemap;
    if (leftbits != 0) {
      bindex_t i;
      binmap_t leastbit = least_bit(leftbits);
      compute_bit2idx(leastbit, i);
      t = *treebin_at(m, i);
    }
  }

  while (t != 0) { /* find smallest of tree or subtree */
    size_t trem = chunksize(t) - nb;
    if (trem < rsize) {
      rsize = trem;
      v = t;
    }
    t = leftmost_child(t);
  }

  /*  If dv is a better fit, return 0 so malloc will use it */
  if (v != 0 && rsize < (size_t)(m->dvsize - nb)) {
    if (RTCHECK(ok_address(m, v))) { /* split */
      mchunkptr r = chunk_plus_offset(v, nb);
      assert(chunksize(v) == rsize + nb);
      if (RTCHECK(ok_next(v, r))) {
        unlink_large_chunk(m, v);
        if (rsize < MIN_CHUNK_SIZE)
          set_inuse_and_pinuse(m, v, (rsize + nb));
        else {
          set_size_and_pinuse_of_inuse_chunk(m, v, nb);
          set_size_and_pinuse_of_free_chunk(r, rsize);
          insert_chunk(m, r, rsize);
        }
        return chunk2mem(v);
      }
    }
    CORRUPTION_ERROR_ACTION(m);
  }
  return 0;
}

/* allocate a small request from the best fitting chunk in a treebin */
static void* tmalloc_small(mstate m, size_t nb) {
  tchunkptr t, v;
  size_t rsize;
  bindex_t i;
  binmap_t leastbit = least_bit(m->treemap);
  compute_bit2idx(leastbit, i);
  v = t = *treebin_at(m, i);
  rsize = chunksize(t) - nb;

  while ((t = leftmost_child(t)) != 0) {
    size_t trem = chunksize(t) - nb;
    if (trem < rsize) {
      rsize = trem;
      v = t;
    }
  }

  if (RTCHECK(ok_address(m, v))) {
    mchunkptr r = chunk_plus_offset(v, nb);
    assert(chunksize(v) == rsize + nb);
    if (RTCHECK(ok_next(v, r))) {
      unlink_large_chunk(m, v);
      if (rsize < MIN_CHUNK_SIZE)
        set_inuse_and_pinuse(m, v, (rsize + nb));
      else {
        set_size_and_pinuse_of_inuse_chunk(m, v, nb);
        set_size_and_pinuse_of_free_chunk(r, rsize);
        replace_dv(m, r, rsize);
      }
      return chunk2mem(v);
    }
  }

  CORRUPTION_ERROR_ACTION(m);
  return 0;
}

#if !ONLY_MSPACES

void* dlmalloc(size_t bytes) {
  /*
     Basic algorithm:
     If a small request (< 256 bytes minus per-chunk overhead):
       1. If one exists, use a remainderless chunk in associated smallbin.
          (Remainderless means that there are too few excess bytes to
          represent as a chunk.)
       2. If it is big enough, use the dv chunk, which is normally the
          chunk adjacent to the one used for the most recent small request.
       3. If one exists, split the smallest available chunk in a bin,
          saving remainder in dv.
       4. If it is big enough, use the top chunk.
       5. If available, get memory from system and use it
     Otherwise, for a large request:
       1. Find the smallest available binned chunk that fits, and use it
          if it is better fitting than dv chunk, splitting if necessary.
       2. If better fitting than any binned chunk, use the dv chunk.
       3. If it is big enough, use the top chunk.
       4. If request size >= mmap threshold, try to directly mmap this chunk.
       5. If available, get memory from system and use it

     The ugly goto's here ensure that postaction occurs along all paths.
  */

#if USE_LOCKS
  ensure_initialization(); /* initialize in sys_alloc if not using locks */
#endif

  if (!PREACTION(gm)) {
    void* mem;
    size_t nb;
    if (bytes <= MAX_SMALL_REQUEST) {
      bindex_t idx;
      binmap_t smallbits;
      nb = (bytes < MIN_REQUEST)? MIN_CHUNK_SIZE : pad_request(bytes);
      idx = small_index(nb);
      smallbits = gm->smallmap >> idx;

      if ((smallbits & 0x3U) != 0) { /* Remainderless fit to a smallbin. */
        mchunkptr b, p;
        idx += ~smallbits & 1;       /* Uses next bin if idx empty */
        b = smallbin_at(gm, idx);
        p = b->fd;
        assert(chunksize(p) == small_index2size(idx));
        unlink_first_small_chunk(gm, b, p, idx);
        set_inuse_and_pinuse(gm, p, small_index2size(idx));
        mem = chunk2mem(p);
        check_malloced_chunk(gm, mem, nb);
        goto postaction;
      }

      else if (nb > gm->dvsize) {
        if (smallbits != 0) { /* Use chunk in next nonempty smallbin */
          mchunkptr b, p, r;
          size_t rsize;
          bindex_t i;
          binmap_t leftbits = (smallbits << idx) & left_bits(idx2bit(idx));
          binmap_t leastbit = least_bit(leftbits);
          compute_bit2idx(leastbit, i);
          b = smallbin_at(gm, i);
          p = b->fd;
          assert(chunksize(p) == small_index2size(i));
          unlink_first_small_chunk(gm, b, p, i);
          rsize = small_index2size(i) - nb;
          /* Fit here cannot be remainderless if 4byte sizes */
          if (SIZE_T_SIZE != 4 && rsize < MIN_CHUNK_SIZE)
            set_inuse_and_pinuse(gm, p, small_index2size(i));
          else {
            set_size_and_pinuse_of_inuse_chunk(gm, p, nb);
            r = chunk_plus_offset(p, nb);
            set_size_and_pinuse_of_free_chunk(r, rsize);
            replace_dv(gm, r, rsize);
          }
          mem = chunk2mem(p);
          check_malloced_chunk(gm, mem, nb);
          goto postaction;
        }

        else if (gm->treemap != 0 && (mem = tmalloc_small(gm, nb)) != 0) {
          check_malloced_chunk(gm, mem, nb);
          goto postaction;
        }
      }
    }
    else if (bytes >= MAX_REQUEST)
      nb = MAX_SIZE_T; /* Too big to allocate. Force failure (in sys alloc) */
    else {
      nb = pad_request(bytes);
      if (gm->treemap != 0 && (mem = tmalloc_large(gm, nb)) != 0) {
        check_malloced_chunk(gm, mem, nb);
        goto postaction;
      }
    }

    if (nb <= gm->dvsize) {
      size_t rsize = gm->dvsize - nb;
      mchunkptr p = gm->dv;
      if (rsize >= MIN_CHUNK_SIZE) { /* split dv */
        mchunkptr r = gm->dv = chunk_plus_offset(p, nb);
        gm->dvsize = rsize;
        set_size_and_pinuse_of_free_chunk(r, rsize);
        set_size_and_pinuse_of_inuse_chunk(gm, p, nb);
      }
      else { /* exhaust dv */
        size_t dvs = gm->dvsize;
        gm->dvsize = 0;
        gm->dv = 0;
        set_inuse_and_pinuse(gm, p, dvs);
      }
      mem = chunk2mem(p);
      check_malloced_chunk(gm, mem, nb);
      goto postaction;
    }

    else if (nb < gm->topsize) { /* Split top */
      size_t rsize = gm->topsize -= nb;
      mchunkptr p = gm->top;
      mchunkptr r = gm->top = chunk_plus_offset(p, nb);
      r->head = rsize | PINUSE_BIT;
      set_size_and_pinuse_of_inuse_chunk(gm, p, nb);
      mem = chunk2mem(p);
      check_top_chunk(gm, gm->top);
      check_malloced_chunk(gm, mem, nb);
      goto postaction;
    }

    mem = sys_alloc(gm, nb);

  postaction:
    POSTACTION(gm);
    return mem;
  }

  return 0;
}

/* ---------------------------- free --------------------------- */

void dlfree(void* mem) {
  /*
     Consolidate freed chunks with preceeding or succeeding bordering
     free chunks, if they exist, and then place in a bin.  Intermixed
     with special cases for top, dv, mmapped chunks, and usage errors.
  */

  if (mem != 0) {
    mchunkptr p  = mem2chunk(mem);
#if FOOTERS
    mstate fm = get_mstate_for(p);
    if (!ok_magic(fm)) {
      USAGE_ERROR_ACTION(fm, p);
      return;
    }
#else /* FOOTERS */
#define fm gm
#endif /* FOOTERS */
    if (!PREACTION(fm)) {
      check_inuse_chunk(fm, p);
      if (RTCHECK(ok_address(fm, p) && ok_inuse(p))) {
        size_t psize = chunksize(p);
        mchunkptr next = chunk_plus_offset(p, psize);
        if (!pinuse(p)) {
          size_t prevsize = p->prev_foot;
          if (is_mmapped(p)) {
            psize += prevsize + MMAP_FOOT_PAD;
            if (CALL_MUNMAP((char*)p - prevsize, psize) == 0)
              fm->footprint -= psize;
            goto postaction;
          }
          else {
            mchunkptr prev = chunk_minus_offset(p, prevsize);
            psize += prevsize;
            p = prev;
            if (RTCHECK(ok_address(fm, prev))) { /* consolidate backward */
              if (p != fm->dv) {
                unlink_chunk(fm, p, prevsize);
              }
              else if ((next->head & INUSE_BITS) == INUSE_BITS) {
                fm->dvsize = psize;
                set_free_with_pinuse(p, psize, next);
                goto postaction;
              }
            }
            else
              goto erroraction;
          }
        }

        if (RTCHECK(ok_next(p, next) && ok_pinuse(next))) {
          if (!cinuse(next)) {  /* consolidate forward */
            if (next == fm->top) {
              size_t tsize = fm->topsize += psize;
              fm->top = p;
              p->head = tsize | PINUSE_BIT;
              if (p == fm->dv) {
                fm->dv = 0;
                fm->dvsize = 0;
              }
              if (should_trim(fm, tsize))
                sys_trim(fm, 0);
              goto postaction;
            }
            else if (next == fm->dv) {
              size_t dsize = fm->dvsize += psize;
              fm->dv = p;
              set_size_and_pinuse_of_free_chunk(p, dsize);
              goto postaction;
            }
            else {
              size_t nsize = chunksize(next);
              psize += nsize;
              unlink_chunk(fm, next, nsize);
              set_size_and_pinuse_of_free_chunk(p, psize);
              if (p == fm->dv) {
                fm->dvsize = psize;
                goto postaction;
              }
            }
          }
          else
            set_free_with_pinuse(p, psize, next);

          if (is_small(psize)) {
            insert_small_chunk(fm, p, psize);
            check_free_chunk(fm, p);
          }
          else {
            tchunkptr tp = (tchunkptr)p;
            insert_large_chunk(fm, tp, psize);
            check_free_chunk(fm, p);
            if (--fm->release_checks == 0)
              release_unused_segments(fm);
          }
          goto postaction;
        }
      }
    erroraction:
      USAGE_ERROR_ACTION(fm, p);
    postaction:
      POSTACTION(fm);
    }
  }
#if !FOOTERS
#undef fm
#endif /* FOOTERS */
}

void* dlcalloc(size_t n_elements, size_t elem_size) {
  void* mem;
  size_t req = 0;
  if (n_elements != 0) {
    req = n_elements * elem_size;
    if (((n_elements | elem_size) & ~(size_t)0xffff) &&
        (req / n_elements != elem_size))
      req = MAX_SIZE_T; /* force downstream failure on overflow */
  }
  mem = dlmalloc(req);
  if (mem != 0 && calloc_must_clear(mem2chunk(mem)))
    memset(mem, 0, req);
  return mem;
}

#endif /* !ONLY_MSPACES */

/* ------------ Internal support for realloc, memalign, etc -------------- */

/* Try to realloc; only in-place unless can_move true */
static mchunkptr try_realloc_chunk(mstate m, mchunkptr p, size_t nb,
                                   int can_move) {
  mchunkptr newp = 0;
  size_t oldsize = chunksize(p);
  mchunkptr next = chunk_plus_offset(p, oldsize);
  if (RTCHECK(ok_address(m, p) && ok_inuse(p) &&
              ok_next(p, next) && ok_pinuse(next))) {
    if (is_mmapped(p)) {
      newp = mmap_resize(m, p, nb, can_move);
    }
    else if (oldsize >= nb) {             /* already big enough */
      size_t rsize = oldsize - nb;
      if (rsize >= MIN_CHUNK_SIZE) {      /* split off remainder */
        mchunkptr r = chunk_plus_offset(p, nb);
        set_inuse(m, p, nb);
        set_inuse(m, r, rsize);
        dispose_chunk(m, r, rsize);
      }
      newp = p;
    }
    else if (next == m->top) {  /* extend into top */
      if (oldsize + m->topsize > nb) {
        size_t newsize = oldsize + m->topsize;
        size_t newtopsize = newsize - nb;
        mchunkptr newtop = chunk_plus_offset(p, nb);
        set_inuse(m, p, nb);
        newtop->head = newtopsize |PINUSE_BIT;
        m->top = newtop;
        m->topsize = newtopsize;
        newp = p;
      }
    }
    else if (next == m->dv) { /* extend into dv */
      size_t dvs = m->dvsize;
      if (oldsize + dvs >= nb) {
        size_t dsize = oldsize + dvs - nb;
        if (dsize >= MIN_CHUNK_SIZE) {
          mchunkptr r = chunk_plus_offset(p, nb);
          mchunkptr n = chunk_plus_offset(r, dsize);
          set_inuse(m, p, nb);
          set_size_and_pinuse_of_free_chunk(r, dsize);
          clear_pinuse(n);
          m->dvsize = dsize;
          m->dv = r;
        }
        else { /* exhaust dv */
          size_t newsize = oldsize + dvs;
          set_inuse(m, p, newsize);
          m->dvsize = 0;
          m->dv = 0;
        }
        newp = p;
      }
    }
    else if (!cinuse(next)) { /* extend into next free chunk */
      size_t nextsize = chunksize(next);
      if (oldsize + nextsize >= nb) {
        size_t rsize = oldsize + nextsize - nb;
        unlink_chunk(m, next, nextsize);
        if (rsize < MIN_CHUNK_SIZE) {
          size_t newsize = oldsize + nextsize;
          set_inuse(m, p, newsize);
        }
        else {
          mchunkptr r = chunk_plus_offset(p, nb);
          set_inuse(m, p, nb);
          set_inuse(m, r, rsize);
          dispose_chunk(m, r, rsize);
        }
        newp = p;
      }
    }
  }
  else {
    USAGE_ERROR_ACTION(m, chunk2mem(p));
  }
  return newp;
}

static void* internal_memalign(mstate m, size_t alignment, size_t bytes) {
  void* mem = 0;
  if (alignment <  MIN_CHUNK_SIZE) /* must be at least a minimum chunk size */
    alignment = MIN_CHUNK_SIZE;
  if ((alignment & (alignment-SIZE_T_ONE)) != 0) {/* Ensure a power of 2 */
    size_t a = MALLOC_ALIGNMENT << 1;
    while (a < alignment) a <<= 1;
    alignment = a;
  }
  if (bytes >= MAX_REQUEST - alignment) {
    if (m != 0)  { /* Test isn't needed but avoids compiler warning */
      MALLOC_FAILURE_ACTION;
    }
  }
  else {
    size_t nb = request2size(bytes);
    size_t req = nb + alignment + MIN_CHUNK_SIZE - CHUNK_OVERHEAD;
    mem = internal_malloc(m, req);
    if (mem != 0) {
      mchunkptr p = mem2chunk(mem);
      if (PREACTION(m))
        return 0;
      if ((((size_t)(mem)) & (alignment - 1)) != 0) { /* misaligned */
        /*
          Find an aligned spot inside chunk.  Since we need to give
          back leading space in a chunk of at least MIN_CHUNK_SIZE, if
          the first calculation places us at a spot with less than
          MIN_CHUNK_SIZE leader, we can move to the next aligned spot.
          We've allocated enough total room so that this is always
          possible.
        */
        char* br = (char*)mem2chunk((size_t)(((size_t)((char*)mem + alignment -
                                                       SIZE_T_ONE)) &
                                             -alignment));
        char* pos = ((size_t)(br - (char*)(p)) >= MIN_CHUNK_SIZE)?
          br : br+alignment;
        mchunkptr newp = (mchunkptr)pos;
        size_t leadsize = pos - (char*)(p);
        size_t newsize = chunksize(p) - leadsize;

        if (is_mmapped(p)) { /* For mmapped chunks, just adjust offset */
          newp->prev_foot = p->prev_foot + leadsize;
          newp->head = newsize;
        }
        else { /* Otherwise, give back leader, use the rest */
          set_inuse(m, newp, newsize);
          set_inuse(m, p, leadsize);
          dispose_chunk(m, p, leadsize);
        }
        p = newp;
      }

      /* Give back spare room at the end */
      if (!is_mmapped(p)) {
        size_t size = chunksize(p);
        if (size > nb + MIN_CHUNK_SIZE) {
          size_t remainder_size = size - nb;
          mchunkptr remainder = chunk_plus_offset(p, nb);
          set_inuse(m, p, nb);
          set_inuse(m, remainder, remainder_size);
          dispose_chunk(m, remainder, remainder_size);
        }
      }

      mem = chunk2mem(p);
      assert (chunksize(p) >= nb);
      assert(((size_t)mem & (alignment - 1)) == 0);
      check_inuse_chunk(m, p);
      POSTACTION(m);
    }
  }
  return mem;
}

/*
  Common support for independent_X routines, handling
    all of the combinations that can result.
  The opts arg has:
    bit 0 set if all elements are same size (using sizes[0])
    bit 1 set if elements should be zeroed
*/
static void** ialloc(mstate m,
                     size_t n_elements,
                     size_t* sizes,
                     int opts,
                     void* chunks[]) {

  size_t    element_size;   /* chunksize of each element, if all same */
  size_t    contents_size;  /* total size of elements */
  size_t    array_size;     /* request size of pointer array */
  void*     mem;            /* malloced aggregate space */
  mchunkptr p;              /* corresponding chunk */
  size_t    remainder_size; /* remaining bytes while splitting */
  void**    marray;         /* either "chunks" or malloced ptr array */
  mchunkptr array_chunk;    /* chunk for malloced ptr array */
  flag_t    was_enabled;    /* to disable mmap */
  size_t    size;
  size_t    i;

  ensure_initialization();
  /* compute array length, if needed */
  if (chunks != 0) {
    if (n_elements == 0)
      return chunks; /* nothing to do */
    marray = chunks;
    array_size = 0;
  }
  else {
    /* if empty req, must still return chunk representing empty array */
    if (n_elements == 0)
      return (void**)internal_malloc(m, 0);
    marray = 0;
    array_size = request2size(n_elements * (sizeof(void*)));
  }

  /* compute total element size */
  if (opts & 0x1) { /* all-same-size */
    element_size = request2size(*sizes);
    contents_size = n_elements * element_size;
  }
  else { /* add up all the sizes */
    element_size = 0;
    contents_size = 0;
    for (i = 0; i != n_elements; ++i)
      contents_size += request2size(sizes[i]);
  }

  size = contents_size + array_size;

  /*
     Allocate the aggregate chunk.  First disable direct-mmapping so
     malloc won't use it, since we would not be able to later
     free/realloc space internal to a segregated mmap region.
  */
  was_enabled = use_mmap(m);
  disable_mmap(m);
  mem = internal_malloc(m, size - CHUNK_OVERHEAD);
  if (was_enabled)
    enable_mmap(m);
  if (mem == 0)
    return 0;

  if (PREACTION(m)) return 0;
  p = mem2chunk(mem);
  remainder_size = chunksize(p);

  assert(!is_mmapped(p));

  if (opts & 0x2) {       /* optionally clear the elements */
    memset((size_t*)mem, 0, remainder_size - SIZE_T_SIZE - array_size);
  }

  /* If not provided, allocate the pointer array as final part of chunk */
  if (marray == 0) {
    size_t  array_chunk_size;
    array_chunk = chunk_plus_offset(p, contents_size);
    array_chunk_size = remainder_size - contents_size;
    marray = (void**) (chunk2mem(array_chunk));
    set_size_and_pinuse_of_inuse_chunk(m, array_chunk, array_chunk_size);
    remainder_size = contents_size;
  }

  /* split out elements */
  for (i = 0; ; ++i) {
    marray[i] = chunk2mem(p);
    if (i != n_elements-1) {
      if (element_size != 0)
        size = element_size;
      else
        size = request2size(sizes[i]);
      remainder_size -= size;
      set_size_and_pinuse_of_inuse_chunk(m, p, size);
      p = chunk_plus_offset(p, size);
    }
    else { /* the final element absorbs any overallocation slop */
      set_size_and_pinuse_of_inuse_chunk(m, p, remainder_size);
      break;
    }
  }

#if DEBUG
  if (marray != chunks) {
    /* final element must have exactly exhausted chunk */
    if (element_size != 0) {
      assert(remainder_size == element_size);
    }
    else {
      assert(remainder_size == request2size(sizes[i]));
    }
    check_inuse_chunk(m, mem2chunk(marray));
  }
  for (i = 0; i != n_elements; ++i)
    check_inuse_chunk(m, mem2chunk(marray[i]));

#endif /* DEBUG */

  POSTACTION(m);
  return marray;
}

/* Try to free all pointers in the given array.
   Note: this could be made faster, by delaying consolidation,
   at the price of disabling some user integrity checks, We
   still optimize some consolidations by combining adjacent
   chunks before freeing, which will occur often if allocated
   with ialloc or the array is sorted.
*/
static size_t internal_bulk_free(mstate m, void* array[], size_t nelem) {
  size_t unfreed = 0;
  if (!PREACTION(m)) {
    void** a;
    void** fence = &(array[nelem]);
    for (a = array; a != fence; ++a) {
      void* mem = *a;
      if (mem != 0) {
        mchunkptr p = mem2chunk(mem);
        size_t psize = chunksize(p);
#if FOOTERS
        if (get_mstate_for(p) != m) {
          ++unfreed;
          continue;
        }
#endif
        check_inuse_chunk(m, p);
        *a = 0;
        if (RTCHECK(ok_address(m, p) && ok_inuse(p))) {
          void ** b = a + 1; /* try to merge with next chunk */
          mchunkptr next = next_chunk(p);
          if (b != fence && *b == chunk2mem(next)) {
            size_t newsize = chunksize(next) + psize;
            set_inuse(m, p, newsize);
            *b = chunk2mem(p);
          }
          else
            dispose_chunk(m, p, psize);
        }
        else {
          CORRUPTION_ERROR_ACTION(m);
          break;
        }
      }
    }
    if (should_trim(m, m->topsize))
      sys_trim(m, 0);
    POSTACTION(m);
  }
  return unfreed;
}

/* Traversal */
#if MALLOC_INSPECT_ALL
static void internal_inspect_all(mstate m,
                                 void(*handler)(void *start,
                                                void *end,
                                                size_t used_bytes,
                                                void* callback_arg),
                                 void* arg) {
  if (is_initialized(m)) {
    mchunkptr top = m->top;
    msegmentptr s;
    for (s = &m->seg; s != 0; s = s->next) {
      mchunkptr q = align_as_chunk(s->base);
      while (segment_holds(s, q) && q->head != FENCEPOST_HEAD) {
        mchunkptr next = next_chunk(q);
        size_t sz = chunksize(q);
        size_t used;
        void* start;
        if (is_inuse(q)) {
          used = sz - CHUNK_OVERHEAD; /* must not be mmapped */
          start = chunk2mem(q);
        }
        else {
          used = 0;
          if (is_small(sz)) {     /* offset by possible bookkeeping */
            start = (void*)((char*)q + sizeof(struct malloc_chunk));
          }
          else {
            start = (void*)((char*)q + sizeof(struct malloc_tree_chunk));
          }
        }
        if (start < (void*)next)  /* skip if all space is bookkeeping */
          handler(start, next, used, arg);
        if (q == top)
          break;
        q = next;
      }
    }
  }
}
#endif /* MALLOC_INSPECT_ALL */

/* ------------------ Exported realloc, memalign, etc -------------------- */

#if !ONLY_MSPACES

void* dlrealloc(void* oldmem, size_t bytes) {
  void* mem = 0;
  if (oldmem == 0) {
    mem = dlmalloc(bytes);
  }
  else if (bytes >= MAX_REQUEST) {
    MALLOC_FAILURE_ACTION;
  }
#ifdef REALLOC_ZERO_BYTES_FREES
  else if (bytes == 0) {
    dlfree(oldmem);
  }
#endif /* REALLOC_ZERO_BYTES_FREES */
  else {
    size_t nb = request2size(bytes);
    mchunkptr oldp = mem2chunk(oldmem);
#if ! FOOTERS
    mstate m = gm;
#else /* FOOTERS */
    mstate m = get_mstate_for(oldp);
    if (!ok_magic(m)) {
      USAGE_ERROR_ACTION(m, oldmem);
      return 0;
    }
#endif /* FOOTERS */
    if (!PREACTION(m)) {
      mchunkptr newp = try_realloc_chunk(m, oldp, nb, 1);
      POSTACTION(m);
      if (newp != 0) {
        check_inuse_chunk(m, newp);
        mem = chunk2mem(newp);
      }
      else {
        mem = internal_malloc(m, bytes);
        if (mem != 0) {
          size_t oc = chunksize(oldp) - overhead_for(oldp);
          memcpy(mem, oldmem, (oc < bytes)? oc : bytes);
          internal_free(m, oldmem);
        }
      }
    }
  }
  return mem;
}

void* dlrealloc_in_place(void* oldmem, size_t bytes) {
  void* mem = 0;
  if (oldmem != 0) {
    if (bytes >= MAX_REQUEST) {
      MALLOC_FAILURE_ACTION;
    }
    else {
      size_t nb = request2size(bytes);
      mchunkptr oldp = mem2chunk(oldmem);
#if ! FOOTERS
      mstate m = gm;
#else /* FOOTERS */
      mstate m = get_mstate_for(oldp);
      if (!ok_magic(m)) {
        USAGE_ERROR_ACTION(m, oldmem);
        return 0;
      }
#endif /* FOOTERS */
      if (!PREACTION(m)) {
        mchunkptr newp = try_realloc_chunk(m, oldp, nb, 0);
        POSTACTION(m);
        if (newp == oldp) {
          check_inuse_chunk(m, newp);
          mem = oldmem;
        }
      }
    }
  }
  return mem;
}

void* dlmemalign(size_t alignment, size_t bytes) {
  if (alignment <= MALLOC_ALIGNMENT) {
    return dlmalloc(bytes);
  }
  return internal_memalign(gm, alignment, bytes);
}

int dlposix_memalign(void** pp, size_t alignment, size_t bytes) {
  void* mem = 0;
  if (alignment == MALLOC_ALIGNMENT)
    mem = dlmalloc(bytes);
  else {
    size_t d = alignment / sizeof(void*);
    size_t r = alignment % sizeof(void*);
    if (r != 0 || d == 0 || (d & (d-SIZE_T_ONE)) != 0)
      return EINVAL;
    else if (bytes <= MAX_REQUEST - alignment) {
      if (alignment <  MIN_CHUNK_SIZE)
        alignment = MIN_CHUNK_SIZE;
      mem = internal_memalign(gm, alignment, bytes);
    }
  }
  if (mem == 0)
    return ENOMEM;
  else {
    *pp = mem;
    return 0;
  }
}

void* dlvalloc(size_t bytes) {
  size_t pagesz;
  ensure_initialization();
  pagesz = mparams.page_size;
  return dlmemalign(pagesz, bytes);
}

void* dlpvalloc(size_t bytes) {
  size_t pagesz;
  ensure_initialization();
  pagesz = mparams.page_size;
  return dlmemalign(pagesz, (bytes + pagesz - SIZE_T_ONE) & ~(pagesz - SIZE_T_ONE));
}

void** dlindependent_calloc(size_t n_elements, size_t elem_size,
                            void* chunks[]) {
  size_t sz = elem_size; /* serves as 1-element array */
  return ialloc(gm, n_elements, &sz, 3, chunks);
}

void** dlindependent_comalloc(size_t n_elements, size_t sizes[],
                              void* chunks[]) {
  return ialloc(gm, n_elements, sizes, 0, chunks);
}

size_t dlbulk_free(void* array[], size_t nelem) {
  return internal_bulk_free(gm, array, nelem);
}

#if MALLOC_INSPECT_ALL
void dlmalloc_inspect_all(void(*handler)(void *start,
                                         void *end,
                                         size_t used_bytes,
                                         void* callback_arg),
                          void* arg) {
  ensure_initialization();
  if (!PREACTION(gm)) {
    internal_inspect_all(gm, handler, arg);
    POSTACTION(gm);
  }
}
#endif /* MALLOC_INSPECT_ALL */

int dlmalloc_trim(size_t pad) {
  int result = 0;
  ensure_initialization();
  if (!PREACTION(gm)) {
    result = sys_trim(gm, pad);
    POSTACTION(gm);
  }
  return result;
}

size_t dlmalloc_footprint(void) {
  return gm->footprint;
}

size_t dlmalloc_max_footprint(void) {
  return gm->max_footprint;
}

size_t dlmalloc_footprint_limit(void) {
  size_t maf = gm->footprint_limit;
  return maf == 0 ? MAX_SIZE_T : maf;
}

size_t dlmalloc_set_footprint_limit(size_t bytes) {
  size_t result;  /* invert sense of 0 */
  if (bytes == 0)
    result = granularity_align(1); /* Use minimal size */
  if (bytes == MAX_SIZE_T)
    result = 0;                    /* disable */
  else
    result = granularity_align(bytes);
  return gm->footprint_limit = result;
}

#if !NO_MALLINFO
struct mallinfo dlmallinfo(void) {
  return internal_mallinfo(gm);
}
#endif /* NO_MALLINFO */

#if !NO_MALLOC_STATS
void dlmalloc_stats() {
  internal_malloc_stats(gm);
}
#endif /* NO_MALLOC_STATS */

int dlmallopt(int param_number, int value) {
  return change_mparam(param_number, value);
}

size_t dlmalloc_usable_size(void* mem) {
  if (mem != 0) {
    mchunkptr p = mem2chunk(mem);
    if (is_inuse(p))
      return chunksize(p) - overhead_for(p);
  }
  return 0;
}

#endif /* !ONLY_MSPACES */

/* ----------------------------- user mspaces ---------------------------- */

#if MSPACES

static mstate init_user_mstate(char* tbase, size_t tsize) {
  size_t msize = pad_request(sizeof(struct malloc_state));
  mchunkptr mn;
  mchunkptr msp = align_as_chunk(tbase);
  mstate m = (mstate)(chunk2mem(msp));
  memset(m, 0, msize);
  (void)INITIAL_LOCK(&m->mutex);
  msp->head = (msize|INUSE_BITS);
  m->seg.base = m->least_addr = tbase;
  m->seg.size = m->footprint = m->max_footprint = tsize;
  m->magic = mparams.magic;
  m->release_checks = MAX_RELEASE_CHECK_RATE;
  m->mflags = mparams.default_mflags;
  m->extp = 0;
  m->exts = 0;
  disable_contiguous(m);
  init_bins(m);
  mn = next_chunk(mem2chunk(m));
  init_top(m, mn, (size_t)((tbase + tsize) - (char*)mn) - TOP_FOOT_SIZE);
  check_top_chunk(m, m->top);
  return m;
}

mspace create_mspace(size_t capacity, int locked) {
  mstate m = 0;
  size_t msize;
  ensure_initialization();
  msize = pad_request(sizeof(struct malloc_state));
  if (capacity < (size_t) -(msize + TOP_FOOT_SIZE + mparams.page_size)) {
    size_t rs = ((capacity == 0)? mparams.granularity :
                 (capacity + TOP_FOOT_SIZE + msize));
    size_t tsize = granularity_align(rs);
    char* tbase = (char*)(CALL_MMAP(tsize));
    if (tbase != CMFAIL) {
      m = init_user_mstate(tbase, tsize);
      m->seg.sflags = USE_MMAP_BIT;
      set_lock(m, locked);
    }
  }
  return (mspace)m;
}

mspace create_mspace_with_base(void* base, size_t capacity, int locked) {
  mstate m = 0;
  size_t msize;
  ensure_initialization();
  msize = pad_request(sizeof(struct malloc_state));
  if (capacity > msize + TOP_FOOT_SIZE &&
      capacity < (size_t) -(msize + TOP_FOOT_SIZE + mparams.page_size)) {
    m = init_user_mstate((char*)base, capacity);
    m->seg.sflags = EXTERN_BIT;
    set_lock(m, locked);
  }
  return (mspace)m;
}

int mspace_track_large_chunks(mspace msp, int enable) {
  int ret = 0;
  mstate ms = (mstate)msp;
  if (!PREACTION(ms)) {
    if (!use_mmap(ms)) {
      ret = 1;
    }
    if (!enable) {
      enable_mmap(ms);
    } else {
      disable_mmap(ms);
    }
    POSTACTION(ms);
  }
  return ret;
}

size_t destroy_mspace(mspace msp) {
  size_t freed = 0;
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    msegmentptr sp = &ms->seg;
    (void)DESTROY_LOCK(&ms->mutex); /* destroy before unmapped */
    while (sp != 0) {
      char* base = sp->base;
      size_t size = sp->size;
      flag_t flag = sp->sflags;
      (void)base; /* placate people compiling -Wunused-variable */
      sp = sp->next;
      if ((flag & USE_MMAP_BIT) && !(flag & EXTERN_BIT) &&
          CALL_MUNMAP(base, size) == 0)
        freed += size;
    }
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return freed;
}

/*
  mspace versions of routines are near-clones of the global
  versions. This is not so nice but better than the alternatives.
*/

void* mspace_malloc(mspace msp, size_t bytes) {
  mstate ms = (mstate)msp;
  if (!ok_magic(ms)) {
    USAGE_ERROR_ACTION(ms,ms);
    return 0;
  }
  if (!PREACTION(ms)) {
    void* mem;
    size_t nb;
    if (bytes <= MAX_SMALL_REQUEST) {
      bindex_t idx;
      binmap_t smallbits;
      nb = (bytes < MIN_REQUEST)? MIN_CHUNK_SIZE : pad_request(bytes);
      idx = small_index(nb);
      smallbits = ms->smallmap >> idx;

      if ((smallbits & 0x3U) != 0) { /* Remainderless fit to a smallbin. */
        mchunkptr b, p;
        idx += ~smallbits & 1;       /* Uses next bin if idx empty */
        b = smallbin_at(ms, idx);
        p = b->fd;
        assert(chunksize(p) == small_index2size(idx));
        unlink_first_small_chunk(ms, b, p, idx);
        set_inuse_and_pinuse(ms, p, small_index2size(idx));
        mem = chunk2mem(p);
        check_malloced_chunk(ms, mem, nb);
        goto postaction;
      }

      else if (nb > ms->dvsize) {
        if (smallbits != 0) { /* Use chunk in next nonempty smallbin */
          mchunkptr b, p, r;
          size_t rsize;
          bindex_t i;
          binmap_t leftbits = (smallbits << idx) & left_bits(idx2bit(idx));
          binmap_t leastbit = least_bit(leftbits);
          compute_bit2idx(leastbit, i);
          b = smallbin_at(ms, i);
          p = b->fd;
          assert(chunksize(p) == small_index2size(i));
          unlink_first_small_chunk(ms, b, p, i);
          rsize = small_index2size(i) - nb;
          /* Fit here cannot be remainderless if 4byte sizes */
          if (SIZE_T_SIZE != 4 && rsize < MIN_CHUNK_SIZE)
            set_inuse_and_pinuse(ms, p, small_index2size(i));
          else {
            set_size_and_pinuse_of_inuse_chunk(ms, p, nb);
            r = chunk_plus_offset(p, nb);
            set_size_and_pinuse_of_free_chunk(r, rsize);
            replace_dv(ms, r, rsize);
          }
          mem = chunk2mem(p);
          check_malloced_chunk(ms, mem, nb);
          goto postaction;
        }

        else if (ms->treemap != 0 && (mem = tmalloc_small(ms, nb)) != 0) {
          check_malloced_chunk(ms, mem, nb);
          goto postaction;
        }
      }
    }
    else if (bytes >= MAX_REQUEST)
      nb = MAX_SIZE_T; /* Too big to allocate. Force failure (in sys alloc) */
    else {
      nb = pad_request(bytes);
      if (ms->treemap != 0 && (mem = tmalloc_large(ms, nb)) != 0) {
        check_malloced_chunk(ms, mem, nb);
        goto postaction;
      }
    }

    if (nb <= ms->dvsize) {
      size_t rsize = ms->dvsize - nb;
      mchunkptr p = ms->dv;
      if (rsize >= MIN_CHUNK_SIZE) { /* split dv */
        mchunkptr r = ms->dv = chunk_plus_offset(p, nb);
        ms->dvsize = rsize;
        set_size_and_pinuse_of_free_chunk(r, rsize);
        set_size_and_pinuse_of_inuse_chunk(ms, p, nb);
      }
      else { /* exhaust dv */
        size_t dvs = ms->dvsize;
        ms->dvsize = 0;
        ms->dv = 0;
        set_inuse_and_pinuse(ms, p, dvs);
      }
      mem = chunk2mem(p);
      check_malloced_chunk(ms, mem, nb);
      goto postaction;
    }

    else if (nb < ms->topsize) { /* Split top */
      size_t rsize = ms->topsize -= nb;
      mchunkptr p = ms->top;
      mchunkptr r = ms->top = chunk_plus_offset(p, nb);
      r->head = rsize | PINUSE_BIT;
      set_size_and_pinuse_of_inuse_chunk(ms, p, nb);
      mem = chunk2mem(p);
      check_top_chunk(ms, ms->top);
      check_malloced_chunk(ms, mem, nb);
      goto postaction;
    }

    mem = sys_alloc(ms, nb);

  postaction:
    POSTACTION(ms);
    return mem;
  }

  return 0;
}

void mspace_free(mspace msp, void* mem) {
  if (mem != 0) {
    mchunkptr p  = mem2chunk(mem);
#if FOOTERS
    mstate fm = get_mstate_for(p);
    (void)msp; /* placate people compiling -Wunused */
#else /* FOOTERS */
    mstate fm = (mstate)msp;
#endif /* FOOTERS */
    if (!ok_magic(fm)) {
      USAGE_ERROR_ACTION(fm, p);
      return;
    }
    if (!PREACTION(fm)) {
      check_inuse_chunk(fm, p);
      if (RTCHECK(ok_address(fm, p) && ok_inuse(p))) {
        size_t psize = chunksize(p);
        mchunkptr next = chunk_plus_offset(p, psize);
        if (!pinuse(p)) {
          size_t prevsize = p->prev_foot;
          if (is_mmapped(p)) {
            psize += prevsize + MMAP_FOOT_PAD;
            if (CALL_MUNMAP((char*)p - prevsize, psize) == 0)
              fm->footprint -= psize;
            goto postaction;
          }
          else {
            mchunkptr prev = chunk_minus_offset(p, prevsize);
            psize += prevsize;
            p = prev;
            if (RTCHECK(ok_address(fm, prev))) { /* consolidate backward */
              if (p != fm->dv) {
                unlink_chunk(fm, p, prevsize);
              }
              else if ((next->head & INUSE_BITS) == INUSE_BITS) {
                fm->dvsize = psize;
                set_free_with_pinuse(p, psize, next);
                goto postaction;
              }
            }
            else
              goto erroraction;
          }
        }

        if (RTCHECK(ok_next(p, next) && ok_pinuse(next))) {
          if (!cinuse(next)) {  /* consolidate forward */
            if (next == fm->top) {
              size_t tsize = fm->topsize += psize;
              fm->top = p;
              p->head = tsize | PINUSE_BIT;
              if (p == fm->dv) {
                fm->dv = 0;
                fm->dvsize = 0;
              }
              if (should_trim(fm, tsize))
                sys_trim(fm, 0);
              goto postaction;
            }
            else if (next == fm->dv) {
              size_t dsize = fm->dvsize += psize;
              fm->dv = p;
              set_size_and_pinuse_of_free_chunk(p, dsize);
              goto postaction;
            }
            else {
              size_t nsize = chunksize(next);
              psize += nsize;
              unlink_chunk(fm, next, nsize);
              set_size_and_pinuse_of_free_chunk(p, psize);
              if (p == fm->dv) {
                fm->dvsize = psize;
                goto postaction;
              }
            }
          }
          else
            set_free_with_pinuse(p, psize, next);

          if (is_small(psize)) {
            insert_small_chunk(fm, p, psize);
            check_free_chunk(fm, p);
          }
          else {
            tchunkptr tp = (tchunkptr)p;
            insert_large_chunk(fm, tp, psize);
            check_free_chunk(fm, p);
            if (--fm->release_checks == 0)
              release_unused_segments(fm);
          }
          goto postaction;
        }
      }
    erroraction:
      USAGE_ERROR_ACTION(fm, p);
    postaction:
      POSTACTION(fm);
    }
  }
}

void* mspace_calloc(mspace msp, size_t n_elements, size_t elem_size) {
  void* mem;
  size_t req = 0;
  mstate ms = (mstate)msp;
  if (!ok_magic(ms)) {
    USAGE_ERROR_ACTION(ms,ms);
    return 0;
  }
  if (n_elements != 0) {
    req = n_elements * elem_size;
    if (((n_elements | elem_size) & ~(size_t)0xffff) &&
        (req / n_elements != elem_size))
      req = MAX_SIZE_T; /* force downstream failure on overflow */
  }
  mem = internal_malloc(ms, req);
  if (mem != 0 && calloc_must_clear(mem2chunk(mem)))
    memset(mem, 0, req);
  return mem;
}

void* mspace_realloc(mspace msp, void* oldmem, size_t bytes) {
  void* mem = 0;
  if (oldmem == 0) {
    mem = mspace_malloc(msp, bytes);
  }
  else if (bytes >= MAX_REQUEST) {
    MALLOC_FAILURE_ACTION;
  }
#ifdef REALLOC_ZERO_BYTES_FREES
  else if (bytes == 0) {
    mspace_free(msp, oldmem);
  }
#endif /* REALLOC_ZERO_BYTES_FREES */
  else {
    size_t nb = request2size(bytes);
    mchunkptr oldp = mem2chunk(oldmem);
#if ! FOOTERS
    mstate m = (mstate)msp;
#else /* FOOTERS */
    mstate m = get_mstate_for(oldp);
    if (!ok_magic(m)) {
      USAGE_ERROR_ACTION(m, oldmem);
      return 0;
    }
#endif /* FOOTERS */
    if (!PREACTION(m)) {
      mchunkptr newp = try_realloc_chunk(m, oldp, nb, 1);
      POSTACTION(m);
      if (newp != 0) {
        check_inuse_chunk(m, newp);
        mem = chunk2mem(newp);
      }
      else {
        mem = mspace_malloc(m, bytes);
        if (mem != 0) {
          size_t oc = chunksize(oldp) - overhead_for(oldp);
          memcpy(mem, oldmem, (oc < bytes)? oc : bytes);
          mspace_free(m, oldmem);
        }
      }
    }
  }
  return mem;
}

void* mspace_realloc_in_place(mspace msp, void* oldmem, size_t bytes) {
  void* mem = 0;
  if (oldmem != 0) {
    if (bytes >= MAX_REQUEST) {
      MALLOC_FAILURE_ACTION;
    }
    else {
      size_t nb = request2size(bytes);
      mchunkptr oldp = mem2chunk(oldmem);
#if ! FOOTERS
      mstate m = (mstate)msp;
#else /* FOOTERS */
      mstate m = get_mstate_for(oldp);
      (void)msp; /* placate people compiling -Wunused */
      if (!ok_magic(m)) {
        USAGE_ERROR_ACTION(m, oldmem);
        return 0;
      }
#endif /* FOOTERS */
      if (!PREACTION(m)) {
        mchunkptr newp = try_realloc_chunk(m, oldp, nb, 0);
        POSTACTION(m);
        if (newp == oldp) {
          check_inuse_chunk(m, newp);
          mem = oldmem;
        }
      }
    }
  }
  return mem;
}

void* mspace_memalign(mspace msp, size_t alignment, size_t bytes) {
  mstate ms = (mstate)msp;
  if (!ok_magic(ms)) {
    USAGE_ERROR_ACTION(ms,ms);
    return 0;
  }
  if (alignment <= MALLOC_ALIGNMENT)
    return mspace_malloc(msp, bytes);
  return internal_memalign(ms, alignment, bytes);
}

void** mspace_independent_calloc(mspace msp, size_t n_elements,
                                 size_t elem_size, void* chunks[]) {
  size_t sz = elem_size; /* serves as 1-element array */
  mstate ms = (mstate)msp;
  if (!ok_magic(ms)) {
    USAGE_ERROR_ACTION(ms,ms);
    return 0;
  }
  return ialloc(ms, n_elements, &sz, 3, chunks);
}

void** mspace_independent_comalloc(mspace msp, size_t n_elements,
                                   size_t sizes[], void* chunks[]) {
  mstate ms = (mstate)msp;
  if (!ok_magic(ms)) {
    USAGE_ERROR_ACTION(ms,ms);
    return 0;
  }
  return ialloc(ms, n_elements, sizes, 0, chunks);
}

size_t mspace_bulk_free(mspace msp, void* array[], size_t nelem) {
  return internal_bulk_free((mstate)msp, array, nelem);
}

#if MALLOC_INSPECT_ALL
void mspace_inspect_all(mspace msp,
                        void(*handler)(void *start,
                                       void *end,
                                       size_t used_bytes,
                                       void* callback_arg),
                        void* arg) {
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    if (!PREACTION(ms)) {
      internal_inspect_all(ms, handler, arg);
      POSTACTION(ms);
    }
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
}
#endif /* MALLOC_INSPECT_ALL */

int mspace_trim(mspace msp, size_t pad) {
  int result = 0;
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    if (!PREACTION(ms)) {
      result = sys_trim(ms, pad);
      POSTACTION(ms);
    }
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return result;
}

#if !NO_MALLOC_STATS
void mspace_malloc_stats(mspace msp) {
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    internal_malloc_stats(ms);
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
}
#endif /* NO_MALLOC_STATS */

size_t mspace_footprint(mspace msp) {
  size_t result = 0;
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    result = ms->footprint;
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return result;
}

size_t mspace_max_footprint(mspace msp) {
  size_t result = 0;
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    result = ms->max_footprint;
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return result;
}

size_t mspace_footprint_limit(mspace msp) {
  size_t result = 0;
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    size_t maf = ms->footprint_limit;
    result = (maf == 0) ? MAX_SIZE_T : maf;
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return result;
}

size_t mspace_set_footprint_limit(mspace msp, size_t bytes) {
  size_t result = 0;
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    if (bytes == 0)
      result = granularity_align(1); /* Use minimal size */
    if (bytes == MAX_SIZE_T)
      result = 0;                    /* disable */
    else
      result = granularity_align(bytes);
    ms->footprint_limit = result;
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return result;
}

#if !NO_MALLINFO
struct mallinfo mspace_mallinfo(mspace msp) {
  mstate ms = (mstate)msp;
  if (!ok_magic(ms)) {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return internal_mallinfo(ms);
}
#endif /* NO_MALLINFO */

size_t mspace_usable_size(const void* mem) {
  if (mem != 0) {
    mchunkptr p = mem2chunk(mem);
    if (is_inuse(p))
      return chunksize(p) - overhead_for(p);
  }
  return 0;
}

int mspace_mallopt(int param_number, int value) {
  return change_mparam(param_number, value);
}

#endif /* MSPACES */


/* -------------------- Alternative MORECORE functions ------------------- */

/*
  Guidelines for creating a custom version of MORECORE:

  * For best performance, MORECORE should allocate in multiples of pagesize.
  * MORECORE may allocate more memory than requested. (Or even less,
      but this will usually result in a malloc failure.)
  * MORECORE must not allocate memory when given argument zero, but
      instead return one past the end address of memory from previous
      nonzero call.
  * For best performance, consecutive calls to MORECORE with positive
      arguments should return increasing addresses, indicating that
      space has been contiguously extended.
  * Even though consecutive calls to MORECORE need not return contiguous
      addresses, it must be OK for malloc'ed chunks to span multiple
      regions in those cases where they do happen to be contiguous.
  * MORECORE need not handle negative arguments -- it may instead
      just return MFAIL when given negative arguments.
      Negative arguments are always multiples of pagesize. MORECORE
      must not misinterpret negative args as large positive unsigned
      args. You can suppress all such calls from even occurring by defining
      MORECORE_CANNOT_TRIM,

  As an example alternative MORECORE, here is a custom allocator
  kindly contributed for pre-OSX macOS.  It uses virtually but not
  necessarily physically contiguous non-paged memory (locked in,
  present and won't get swapped out).  You can use it by uncommenting
  this section, adding some #includes, and setting up the appropriate
  defines above:

      #define MORECORE osMoreCore

  There is also a shutdown routine that should somehow be called for
  cleanup upon program exit.

  #define MAX_POOL_ENTRIES 100
  #define MINIMUM_MORECORE_SIZE  (64 * 1024U)
  static int next_os_pool;
  void *our_os_pools[MAX_POOL_ENTRIES];

  void *osMoreCore(int size)
  {
    void *ptr = 0;
    static void *sbrk_top = 0;

    if (size > 0)
    {
      if (size < MINIMUM_MORECORE_SIZE)
         size = MINIMUM_MORECORE_SIZE;
      if (CurrentExecutionLevel() == kTaskLevel)
         ptr = PoolAllocateResident(size + RM_PAGE_SIZE, 0);
      if (ptr == 0)
      {
        return (void *) MFAIL;
      }
      // save ptrs so they can be freed during cleanup
      our_os_pools[next_os_pool] = ptr;
      next_os_pool++;
      ptr = (void *) ((((size_t) ptr) + RM_PAGE_MASK) & ~RM_PAGE_MASK);
      sbrk_top = (char *) ptr + size;
      return ptr;
    }
    else if (size < 0)
    {
      // we don't currently support shrink behavior
      return (void *) MFAIL;
    }
    else
    {
      return sbrk_top;
    }
  }

  // cleanup any allocated memory pools
  // called as last thing before shutting down driver

  void osCleanupMem(void)
  {
    void **ptr;

    for (ptr = our_os_pools; ptr < &our_os_pools[MAX_POOL_ENTRIES]; ptr++)
      if (*ptr)
      {
         PoolDeallocate(*ptr);
         *ptr = 0;
      }
  }

*/


/* -----------------------------------------------------------------------
History:
    v2.8.6 Wed Aug 29 06:57:58 2012  Doug Lea
      * fix bad comparison in dlposix_memalign
      * don't reuse adjusted asize in sys_alloc
      * add LOCK_AT_FORK -- thanks to Kirill Artamonov for the suggestion
      * reduce compiler warnings -- thanks to all who reported/suggested these

    v2.8.5 Sun May 22 10:26:02 2011  Doug Lea  (dl at gee)
      * Always perform unlink checks unless INSECURE
      * Add posix_memalign.
      * Improve realloc to expand in more cases; expose realloc_in_place.
        Thanks to Peter Buhr for the suggestion.
      * Add footprint_limit, inspect_all, bulk_free. Thanks
        to Barry Hayes and others for the suggestions.
      * Internal refactorings to avoid calls while holding locks
      * Use non-reentrant locks by default. Thanks to Roland McGrath
        for the suggestion.
      * Small fixes to mspace_destroy, reset_on_error.
      * Various configuration extensions/changes. Thanks
         to all who contributed these.

    V2.8.4a Thu Apr 28 14:39:43 2011 (dl at gee.cs.oswego.edu)
      * Update Creative Commons URL

    V2.8.4 Wed May 27 09:56:23 2009  Doug Lea  (dl at gee)
      * Use zeros instead of prev foot for is_mmapped
      * Add mspace_track_large_chunks; thanks to Jean Brouwers
      * Fix set_inuse in internal_realloc; thanks to Jean Brouwers
      * Fix insufficient sys_alloc padding when using 16byte alignment
      * Fix bad error check in mspace_footprint
      * Adaptations for ptmalloc; thanks to Wolfram Gloger.
      * Reentrant spin locks; thanks to Earl Chew and others
      * Win32 improvements; thanks to Niall Douglas and Earl Chew
      * Add NO_SEGMENT_TRAVERSAL and MAX_RELEASE_CHECK_RATE options
      * Extension hook in malloc_state
      * Various small adjustments to reduce warnings on some compilers
      * Various configuration extensions/changes for more platforms. Thanks
         to all who contributed these.

    V2.8.3 Thu Sep 22 11:16:32 2005  Doug Lea  (dl at gee)
      * Add max_footprint functions
      * Ensure all appropriate literals are size_t
      * Fix conditional compilation problem for some #define settings
      * Avoid concatenating segments with the one provided
        in create_mspace_with_base
      * Rename some variables to avoid compiler shadowing warnings
      * Use explicit lock initialization.
      * Better handling of sbrk interference.
      * Simplify and fix segment insertion, trimming and mspace_destroy
      * Reinstate REALLOC_ZERO_BYTES_FREES option from 2.7.x
      * Thanks especially to Dennis Flanagan for help on these.

    V2.8.2 Sun Jun 12 16:01:10 2005  Doug Lea  (dl at gee)
      * Fix memalign brace error.

    V2.8.1 Wed Jun  8 16:11:46 2005  Doug Lea  (dl at gee)
      * Fix improper #endif nesting in C++
      * Add explicit casts needed for C++

    V2.8.0 Mon May 30 14:09:02 2005  Doug Lea  (dl at gee)
      * Use trees for large bins
      * Support mspaces
      * Use segments to unify sbrk-based and mmap-based system allocation,
        removing need for emulation on most platforms without sbrk.
      * Default safety checks
      * Optional footer checks. Thanks to William Robertson for the idea.
      * Internal code refactoring
      * Incorporate suggestions and platform-specific changes.
        Thanks to Dennis Flanagan, Colin Plumb, Niall Douglas,
        Aaron Bachmann,  Emery Berger, and others.
      * Speed up non-fastbin processing enough to remove fastbins.
      * Remove useless cfree() to avoid conflicts with other apps.
      * Remove internal memcpy, memset. Compilers handle builtins better.
      * Remove some options that no one ever used and rename others.

    V2.7.2 Sat Aug 17 09:07:30 2002  Doug Lea  (dl at gee)
      * Fix malloc_state bitmap array misdeclaration

    V2.7.1 Thu Jul 25 10:58:03 2002  Doug Lea  (dl at gee)
      * Allow tuning of FIRST_SORTED_BIN_SIZE
      * Use PTR_UINT as type for all ptr->int casts. Thanks to John Belmonte.
      * Better detection and support for non-contiguousness of MORECORE.
        Thanks to Andreas Mueller, Conal Walsh, and Wolfram Gloger
      * Bypass most of malloc if no frees. Thanks To Emery Berger.
      * Fix freeing of old top non-contiguous chunk im sysmalloc.
      * Raised default trim and map thresholds to 256K.
      * Fix mmap-related #defines. Thanks to Lubos Lunak.
      * Fix copy macros; added LACKS_FCNTL_H. Thanks to Neal Walfield.
      * Branch-free bin calculation
      * Default trim and mmap thresholds now 256K.

    V2.7.0 Sun Mar 11 14:14:06 2001  Doug Lea  (dl at gee)
      * Introduce independent_comalloc and independent_calloc.
        Thanks to Michael Pachos for motivation and help.
      * Make optional .h file available
      * Allow > 2GB requests on 32bit systems.
      * new WIN32 sbrk, mmap, munmap, lock code from <Walter@GeNeSys-e.de>.
        Thanks also to Andreas Mueller <a.mueller at paradatec.de>,
        and Anonymous.
      * Allow override of MALLOC_ALIGNMENT (Thanks to Ruud Waij for
        helping test this.)
      * memalign: check alignment arg
      * realloc: don't try to shift chunks backwards, since this
        leads to  more fragmentation in some programs and doesn't
        seem to help in any others.
      * Collect all cases in malloc requiring system memory into sysmalloc
      * Use mmap as backup to sbrk
      * Place all internal state in malloc_state
      * Introduce fastbins (although similar to 2.5.1)
      * Many minor tunings and cosmetic improvements
      * Introduce USE_PUBLIC_MALLOC_WRAPPERS, USE_MALLOC_LOCK
      * Introduce MALLOC_FAILURE_ACTION, MORECORE_CONTIGUOUS
        Thanks to Tony E. Bennett <tbennett@nvidia.com> and others.
      * Include errno.h to support default failure action.

    V2.6.6 Sun Dec  5 07:42:19 1999  Doug Lea  (dl at gee)
      * return null for negative arguments
      * Added Several WIN32 cleanups from Martin C. Fong <mcfong at yahoo.com>
         * Add 'LACKS_SYS_PARAM_H' for those systems without 'sys/param.h'
          (e.g. WIN32 platforms)
         * Cleanup header file inclusion for WIN32 platforms
         * Cleanup code to avoid Microsoft Visual C++ compiler complaints
         * Add 'USE_DL_PREFIX' to quickly allow co-existence with existing
           memory allocation routines
         * Set 'malloc_getpagesize' for WIN32 platforms (needs more work)
         * Use 'assert' rather than 'ASSERT' in WIN32 code to conform to
           usage of 'assert' in non-WIN32 code
         * Improve WIN32 'sbrk()' emulation's 'findRegion()' routine to
           avoid infinite loop
      * Always call 'fREe()' rather than 'free()'

    V2.6.5 Wed Jun 17 15:57:31 1998  Doug Lea  (dl at gee)
      * Fixed ordering problem with boundary-stamping

    V2.6.3 Sun May 19 08:17:58 1996  Doug Lea  (dl at gee)
      * Added pvalloc, as recommended by H.J. Liu
      * Added 64bit pointer support mainly from Wolfram Gloger
      * Added anonymously donated WIN32 sbrk emulation
      * Malloc, calloc, getpagesize: add optimizations from Raymond Nijssen
      * malloc_extend_top: fix mask error that caused wastage after
        foreign sbrks
      * Add linux mremap support code from HJ Liu

    V2.6.2 Tue Dec  5 06:52:55 1995  Doug Lea  (dl at gee)
      * Integrated most documentation with the code.
      * Add support for mmap, with help from
        Wolfram Gloger (Gloger@lrz.uni-muenchen.de).
      * Use last_remainder in more cases.
      * Pack bins using idea from  colin@nyx10.cs.du.edu
      * Use ordered bins instead of best-fit threshhold
      * Eliminate block-local decls to simplify tracing and debugging.
      * Support another case of realloc via move into top
      * Fix error occuring when initial sbrk_base not word-aligned.
      * Rely on page size for units instead of SBRK_UNIT to
        avoid surprises about sbrk alignment conventions.
      * Add mallinfo, mallopt. Thanks to Raymond Nijssen
        (raymond@es.ele.tue.nl) for the suggestion.
      * Add `pad' argument to malloc_trim and top_pad mallopt parameter.
      * More precautions for cases where other routines call sbrk,
        courtesy of Wolfram Gloger (Gloger@lrz.uni-muenchen.de).
      * Added macros etc., allowing use in linux libc from
        H.J. Lu (hjl@gnu.ai.mit.edu)
      * Inverted this history list

    V2.6.1 Sat Dec  2 14:10:57 1995  Doug Lea  (dl at gee)
      * Re-tuned and fixed to behave more nicely with V2.6.0 changes.
      * Removed all preallocation code since under current scheme
        the work required to undo bad preallocations exceeds
        the work saved in good cases for most test programs.
      * No longer use return list or unconsolidated bins since
        no scheme using them consistently outperforms those that don't
        given above changes.
      * Use best fit for very large chunks to prevent some worst-cases.
      * Added some support for debugging

    V2.6.0 Sat Nov  4 07:05:23 1995  Doug Lea  (dl at gee)
      * Removed footers when chunks are in use. Thanks to
        Paul Wilson (wilson@cs.texas.edu) for the suggestion.

    V2.5.4 Wed Nov  1 07:54:51 1995  Doug Lea  (dl at gee)
      * Added malloc_trim, with help from Wolfram Gloger
        (wmglo@Dent.MED.Uni-Muenchen.DE).

    V2.5.3 Tue Apr 26 10:16:01 1994  Doug Lea  (dl at g)

    V2.5.2 Tue Apr  5 16:20:40 1994  Doug Lea  (dl at g)
      * realloc: try to expand in both directions
      * malloc: swap order of clean-bin strategy;
      * realloc: only conditionally expand backwards
      * Try not to scavenge used bins
      * Use bin counts as a guide to preallocation
      * Occasionally bin return list chunks in first scan
      * Add a few optimizations from colin@nyx10.cs.du.edu

    V2.5.1 Sat Aug 14 15:40:43 1993  Doug Lea  (dl at g)
      * faster bin computation & slightly different binning
      * merged all consolidations to one part of malloc proper
         (eliminating old malloc_find_space & malloc_clean_bin)
      * Scan 2 returns chunks (not just 1)
      * Propagate failure in realloc if malloc returns 0
      * Add stuff to allow compilation on non-ANSI compilers
          from kpv@research.att.com

    V2.5 Sat Aug  7 07:41:59 1993  Doug Lea  (dl at g.oswego.edu)
      * removed potential for odd address access in prev_chunk
      * removed dependency on getpagesize.h
      * misc cosmetics and a bit more internal documentation
      * anticosmetics: mangled names in macros to evade debugger strangeness
      * tested on sparc, hp-700, dec-mips, rs6000
          with gcc & native cc (hp, dec only) allowing
          Detlefs & Zorn comparison study (in SIGPLAN Notices.)

    Trial version Fri Aug 28 13:14:29 1992  Doug Lea  (dl at g.oswego.edu)
      * Based loosely on libg++-1.2X malloc. (It retains some of the overall
         structure of old version,  but most details differ.)

*/
#pragma endregion DLMALLOC_C
#ifdef DEBUG
#undef DEBUG   /* only needed if the dlmalloc build defined it as a macro */
#endif

#define DLMALLOC_POOL_MB 64
#define DLMALLOC_POOL_BYTES ((size_t)DLMALLOC_POOL_MB * 1024 * 1024)

alignas(16) static uint8_t dlmalloc_pool_buffer[DLMALLOC_POOL_BYTES];
static mspace dlmalloc_msp = NULL;

static inline void ensure_dlmalloc_initialized(void){
	if(dlmalloc_msp == NULL){
		dlmalloc_msp = create_mspace_with_base(dlmalloc_pool_buffer, DLMALLOC_POOL_BYTES, 0);
		if(dlmalloc_msp == NULL){
			ERROR("create_mspace_with_base failed");
		}
	}
}

void* mymalloc(size_t size){
	if(size == 0){
		return NULL;
	}
	ensure_dlmalloc_initialized();
	void* ptr = mspace_malloc(dlmalloc_msp, size);
	if(ptr == NULL){
		myerrno = ENOMEM;
		ERROR("dlmalloc out of memory (requested size %zu)", size);
	}
	return ptr;
}

void myfree(void* p){
	if(p == NULL){
		return;
	}
	ensure_dlmalloc_initialized();
	mspace_free(dlmalloc_msp, p);
}

void* myrealloc(void* ptr, size_t size){
	if(ptr == NULL){
		return mymalloc(size);
	}
	if(size == 0){
		myfree(ptr);
		return NULL;
	}
	ensure_dlmalloc_initialized();
	void* new_ptr = mspace_realloc(dlmalloc_msp, ptr, size);
	if(new_ptr == NULL){
		myerrno = ENOMEM;
		ERROR("dlmalloc realloc out of memory (requested size %zu)", size);
	}
	return new_ptr;
}
#endif

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
		char* str = mymalloc(payload_length + 1);
		memcpy(str, ((uint8_t*)tcp->payload) + FIXED_OPTIONS_LENGTH, payload_length);
		str[payload_length] = 0;
		for(int i=0; i<payload_length; i++){
			if(( !(str[i] >= 'A' && str[i] <= 'Z') && !(str[i] >= 'a' && str[i] <= 'z') && !(str[i] >= '0' && str[i] <= '9') && !(str[i] == '/'||str[i] == '.'||str[i] == ':'))){
				str[i] = ' ';
			}
		}
		LOG_FIELD("payload_str", "\"%s\"", str);
		myfree(str);
	}
	#endif
	int ts_index = search_tcp_option(tcp, OPT_KIND_TIMESTAMPS);
	if(ts_index>=0){
		uint32_t ts_val = ntohl(*(uint32_t*) (tcp->payload+ts_index+2));
		uint32_t ts_recent = ntohl(*(uint32_t*) (tcp->payload+ts_index+6));
		LOG_FIELD("ts_val", "%"PRIu32, ts_val);
		LOG_FIELD("ts_recent", "%"PRIu32, ts_recent);
	}
	int sack_index = search_tcp_option(tcp, OPT_KIND_SACK);
	if(sack_index >= 0){
		int sack_payload_length = tcp->payload[sack_index+1] - 2;
		if(sack_payload_length > 0){
			// https://claude.ai/share/76bf04ae-943b-4d07-a91f-602af38c8d41
			int sack_entries_count = sack_payload_length / 8;
			// LOG_FIELD writes the key; then we write the JSON array value manually via LOG_TEXT
			LOG_FIELD("sack_blocks", ""); // emits: "sack_blocks": 
			LOG_TEXT("[");
			for(int entry = 0; entry < sack_entries_count; entry++){
				uint32_t left  = ntohl(*((uint32_t*)(tcp->payload + sack_index + 2 + entry*8)));
				uint32_t right = ntohl(*((uint32_t*)(tcp->payload + sack_index + 2 + entry*8 + 4)));
				if(entry > 0) LOG_TEXT(", ");
				fprintf(log_file, "{\"left\": %"PRIu32", \"right\": %"PRIu32", \"length\": %"PRIu32"}", left, right, right-left);
			}
			LOG_TEXT("]");
		}
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


void check_rx_buffer_drops(char* str) {
    struct tpacket_stats stats;
    socklen_t len = sizeof(stats);

    if (getsockopt(unique_raw_socket_fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len) < 0) {
        perror("getsockopt PACKET_STATISTICS");
        return;
    }
	if(stats.tp_drops > 0){
		ERROR("Packet(s) dropped in the kernel receive buffer (position %s) [Received %u Dropped %u]", str ? str : "NULL", stats.tp_packets, stats.tp_drops);
	}
}


#pragma region STARTUP_FUNCTIONS
void raw_socket_setup(){
	unique_raw_socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (-1 == unique_raw_socket_fd) { 
		perror("Socket raw failed"); 
		exit(EXIT_FAILURE);
	}


	int rcvbuf;
	socklen_t alen = sizeof(rcvbuf);

	rcvbuf = REQUESTED_KERNEL_RX_BUF_SIZE;
	if (setsockopt(unique_raw_socket_fd, SOL_SOCKET, SO_RCVBUFFORCE,
				&rcvbuf, sizeof(rcvbuf)) < 0) {
		perror("setsockopt SO_RCVBUFFORCE");
		exit(EXIT_FAILURE);
	}

	alen = sizeof(rcvbuf);
	if (getsockopt(unique_raw_socket_fd, SOL_SOCKET, SO_RCVBUF,
               &rcvbuf, &alen) < 0) {
		perror("getsockopt SO_RCVBUF");
		exit(EXIT_FAILURE);
	}
	
	if(rcvbuf < REQUESTED_KERNEL_RX_BUF_SIZE){
		ERROR("raw_socket_setup kernel rx buffer size granted %d < requested %d", rcvbuf, REQUESTED_KERNEL_RX_BUF_SIZE);
	}




	

    int sndbuf;
    socklen_t slen = sizeof(sndbuf);

    sndbuf = REQUESTED_KERNEL_TX_BUF_SIZE; 
    if (setsockopt(unique_raw_socket_fd, SOL_SOCKET, SO_SNDBUFFORCE,
                &sndbuf, sizeof(sndbuf)) < 0) {
        perror("setsockopt SO_SNDBUFFORCE");
		exit(EXIT_FAILURE);
    }

    slen = sizeof(sndbuf);
    if (getsockopt(unique_raw_socket_fd, SOL_SOCKET, SO_SNDBUF,
               &sndbuf, &slen) < 0) {
        perror("getsockopt SO_SNDBUF");
        exit(EXIT_FAILURE);
    }

	if(sndbuf < REQUESTED_KERNEL_TX_BUF_SIZE){
		ERROR("raw_socket_setup kernel tx buffer size granted %d < requested %d", sndbuf, REQUESTED_KERNEL_TX_BUF_SIZE);
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
	network_interface_index = if_nametoindex(INTERFACE_NAME);
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
	
	char* gw_str = mymalloc(1024);
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
	myfree(gw_str);
	pclose(gw_file);

	if(close(temp_socket) == -1){
		perror("temp_socket close\n");
		exit(EXIT_FAILURE);
	}
}
#pragma endregion STARTUP_FUNCTIONS





#pragma region RAW_SOCKET_ACCESS
// returns -1 if not found, >= 0 index otherwise
int search_mac_cache(uint8_t* ip){
	int i;
	for(i=0;i<MAX_ARP && (arpcache[i].key!=0);i++){
		if(!memcmp(&arpcache[i].key,gateway,4)) 
			break;
	}
	if(arpcache[i].key != 0){
		return i;
	}
	return -1;
}
void resolve_gateway_mac(){
	#ifndef LOCAL_SERVER
	resolve_gateway_mac_requested = true;
	while(search_mac_cache(gateway) < 0){
		pause();
	}
	#endif
}
int resolve_mac(unsigned int destip, unsigned char * destmac){
	#ifdef LOCAL_SERVER
	memset(destmac, 0, 6);
	return 0;
	#endif
	int len,n,i;
	struct sockaddr_ll sll;
	clock_t start;
	unsigned char pkt[1500];
	struct ethernet_frame *eth;
	struct arp_packet *arp;
	i = search_mac_cache((uint8_t*)&destip);
	if(i >= 0){ //If found return 
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
	sll.sll_ifindex = network_interface_index;

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
		i = search_mac_cache((uint8_t*)&destip);
		if(i >= 0){ //If found return 
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
		DEBUG("DROP!");
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

long sendto_call_time = 0;
long eim_time = 0;
void send_ip(unsigned char * payload, unsigned char * targetip, int payloadlen, unsigned char proto){
	struct timespec t0, t1;
	int i,t,len ;
	struct sockaddr_ll sll;
	unsigned char destmac[6];
	unsigned char packet[2000];
	struct ethernet_frame * eth = (struct ethernet_frame *) packet;
	struct ip_datagram * ip = (struct ip_datagram *) eth->payload; 

	if(proto == TCP_PROTO){
		if(drop_packet((struct tcp_segment*)payload)){
			DEBUG("Packet dropped! <======================");
			// print_ip(payload);
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
	clock_gettime(CLOCK_REALTIME, &t0);
	sll.sll_ifindex = network_interface_index;

	clock_gettime(CLOCK_REALTIME, &t1);
	eim_time = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);

	const int num_bytes_sendto = 14+20+payloadlen;

	clock_gettime(CLOCK_REALTIME, &t0);
	errno = 0;
	t=sendto(unique_raw_socket_fd, packet,num_bytes_sendto, 0, (struct sockaddr *)&sll,len);
	if(t != num_bytes_sendto){
		int tmp_errno = errno;
		perror("sendto");
		ERROR("t %d != num_bytes_sendto %d errno %d%s", t, num_bytes_sendto, tmp_errno, tmp_errno==EAGAIN?" (EAGAIN)":"");
	}
	clock_gettime(CLOCK_REALTIME, &t1);
	sendto_call_time = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);
}
#pragma endregion RAW_SOCKET_ACCESS








// see update_tcp_header for backlog_entry_index
void prepare_tcp(int s, int backlog_entry_index, uint16_t flags /*Host order*/, uint8_t* payload, int payloadlen, uint8_t* options, int optlen){
	assert_handler_lock_acquired("prepare_tcp");
	struct tcpctrlblk* tcb = fdinfo[s].tcb;

	if(backlog_entry_index >= 0){
		if(tcb->st != TCB_ST_LISTEN){
			ERROR("prepare_tcp backlog_entry_index %d >= 0 with main TCB state not listen", backlog_entry_index);
		}
		tcb = &(fdinfo[s].channel_backlog[backlog_entry_index]);
	}
	if(tcb->st == 0 || tcb->st == TCB_ST_LISTEN || tcb->st == TCB_ST_LISTEN){
		ERROR("prepare_tcp incompatible tcb state %d", tcb->st);
	}

	struct txcontrolbuf * txcb = (struct txcontrolbuf*) mymalloc(sizeof(struct txcontrolbuf));
	if(fdinfo[s].l_port == 0 || tcb->r_port == 0){
		ERROR("prepare_tcp invalid port l %u r %u\n", htons(fdinfo[s].l_port), htons(tcb->r_port));
	}

	txcb->txtime = -MAX_TIMEOUT;
	txcb->payloadlen = payloadlen;
	txcb->fin = flags & FIN;
	txcb->dummy_payload = flags & DMP;
	txcb->totlen = payloadlen + 20 + FIXED_OPTIONS_LENGTH;
	txcb->retry = 0;
	struct tcp_segment * tcp = txcb->segment = (struct tcp_segment *) mymalloc(sizeof(struct tcp_segment));
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
	tcb->sequence += payloadlen + (txcb->fin ? 1 : 0);

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
	if((tcb->unack == NULL || tcb->unack_tail == NULL) && tcb->unack != tcb->unack_tail){
		ERROR("update_SACK_option inconsistent unack queue state");
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
		if(sack_blocks[num_block][0] <= tcb->cumulativeack){
			ERROR("sack fill sequence before cumulativeack?");
		}
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

void update_tcp_header(int s /* main TCB file descriptor */, int backlog_entry_index /* >= 0 for sockets in the backlog of fdinfo entry s; -1 otherwise */, struct txcontrolbuf *txctrl){
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

	if(backlog_entry_index >= 0){
		if(tcb->st != TCB_ST_LISTEN){
			ERROR("update_tcp_header backlog_entry_index %d >= 0 with main TCB state not listen", backlog_entry_index);
		}
		tcb = &(fdinfo[s].channel_backlog[backlog_entry_index]);

		// We take everything from the backlog TCB, apart from the local address of the pseudo header which is taken from fdinfo
	}

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
void fast_send_tcp(int s, int backlog_entry_index, uint16_t flags /*Host order*/, uint8_t* options, int optlen){
	assert_handler_lock_acquired("fast_send_tcp");
	struct tcpctrlblk*tcb = fdinfo[s].tcb;

	if(backlog_entry_index != -1){
		if(tcb->st != TCB_ST_LISTEN){
			ERROR("fast_send_tcp backlog_entry_index %d >= 0 with main TCB state not listen", backlog_entry_index);
		}
		tcb = &(fdinfo[s].channel_backlog[backlog_entry_index]);
	}

	//struct txcontrolbuf * txcb = (struct txcontrolbuf*) mymalloc(sizeof( struct txcontrolbuf));
	if(fdinfo[s].l_port == 0 || tcb->r_port == 0){
		ERROR("fast_send_tcp invalid port l %u r %u\n", htons(fdinfo[s].l_port), htons(tcb->r_port));
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
	
	struct tcp_segment segment_in_stack;
	struct tcp_segment * tcp = &segment_in_stack;
	tcp->s_port = fdinfo[s].l_port;
	tcp->d_port = tcb->r_port;
	// tcp->seq = htonl(tcb->seq_offs+tcb->sequence);
	tcp->seq = htonl(tcb->highest_sent_sequence_number);
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





void fast_retransmit_holes(struct tcpctrlblk* tcb){
	if(tcb == NULL){
		ERROR("fast_retransmit_holes NULL tcb");
	}
	
	bool there_is_hole = false;
	struct txcontrolbuf* iter = tcb->txfirst;
	while(iter != NULL && iter->next != NULL){
		if(iter->segment == NULL && iter->next->segment != NULL){
			there_is_hole = true;
			break;
		}
		iter = iter->next;
	}
	/*
	// No longer needed since SACK drops only segment part and not whole txcontrolbuf entry; this condition would be caught in the previous loop
	if(!there_is_hole && tcb->txlast != NULL && tcb->txlast->seq + tcb->txlast->payloadlen != tcb->seq_offs+tcb->sequence){
		there_is_hole = true;
	}
	*/
	if(!there_is_hole){
		return;
	}
	
	if(tcb->txfirst == NULL || tcb->txlast == NULL){
		ERROR("fast_retransmit_holes txfirst / txlast NULL");
	}
	/*
	struct txcontrolbuf* unacked_region_start = tcb->txfirst;
	if(tcb->txlast->seq + tcb->txlast->payloadlen != tcb->seq_offs+tcb->sequence){
		// Tail hole: everything that is currently in the TX queue needs to be retransmitted
		unacked_region_start = NULL; // We transmit until the cursor is == NULL (so it traversed the whole tx queue)
	}else{
		if(tcb->txfirst->next == NULL){
			ERROR("fast_retransmit_holes unexpected tx queue of length one"); // either there is no hole, or we have a tail hole, but that check was already done
		}
		while(true){ // There will always be a hole (otherwise, this will make me notice!)
			struct txcontrolbuf* region_end = unacked_region_start->next;
			bool found_next_hole = false;
			while(region_end != NULL && region_end->next != NULL){
				if(region_end->seq + region_end->payloadlen != region_end->next->seq){
					// This is the end of the region! We have found a hole
					unacked_region_start = region_end->next;
					found_next_hole = true;
					break;
				}
				region_end = region_end->next;
			}

			// This "!" is intentional: we exit from the loop only when there is no next hole, so we retransmit what is in all holes, not only in the first one
			if(!found_next_hole){
				break; // Exit from the infinite loop
			}
		}
		// unacked_region_start now has the correct value
	}
	*/
	struct txcontrolbuf* unacked_region_start = NULL;
	bool last_was_SACK = true;
	struct txcontrolbuf* cursor = tcb->txfirst;
	while(cursor != NULL){
		if(cursor->segment == NULL){
			unacked_region_start = NULL;
			last_was_SACK = true;
		}else{
			if(last_was_SACK){
				unacked_region_start = cursor;
			}
			last_was_SACK = false;
		}
		cursor = cursor->next;
	}
	for(struct txcontrolbuf* cursor = tcb->txfirst; cursor != unacked_region_start; cursor = cursor->next){
		if(cursor->segment != NULL){
			cursor->txtime = 0;
		}
	}
}

void congctrl_fsm(struct tcpctrlblk * tcb, int event, struct tcp_segment * tcp, int streamsegmentsize, int acked_size){
	if(event == FSM_EVENT_PKT_RCV){
		bool dmp = tcp->d_offs_res & (DMP >> 8);
		if(streamsegmentsize > 0 && !dmp){
			// This segment carries application data; it is not useful for congestion control (right?)
			return;
		}
		if(streamsegmentsize == 0 && dmp){
			ERROR("congctrl_fsm invalid dmp segment (len 0)");
		}


		// Consistency check: ensure that DMP packets contain the MS option
		int sid = -1;
		// We don't care about ssn
		int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
		if(ms_index >= 0){
			sid = (tcp->payload[ms_index+2]>>2) & 0x1F;
		}
		if(dmp && sid == -1){
			ERROR("congctrl_fsm invalid dmp segment (no sid)");
		}


		bool is_sack = false;
		int sack_index = search_tcp_option(tcp, OPT_KIND_SACK);
		if(sack_index >= 0){
			uint8_t sack_length = tcp->payload[sack_index+1];
			if(sack_length != 2){
				is_sack = true;
			}
		}
		bool is_repeated_ack = (tcb->last_ack==tcp->ack);
		bool is_dupack = is_sack && is_repeated_ack;
		
		switch( tcb->cong_st ){
			case CONGCTRL_ST_SLOW_START:
				if(is_dupack){
					tcb->repeated_acks++;
					DEBUG("DUPACK #%d", tcb->repeated_acks);
				}else{
					tcb->repeated_acks = 0;
				}
				if (tcb->repeated_acks == FAST_RETX_DUPACK_THRESH){
					DEBUG("%d DUPACKS: SS -> FAST", tcb->repeated_acks);
					LOG_MESSAGE("DUPACK: SS -> FAST");
					if(tcb->txfirst!= NULL){
						struct txcontrolbuf * txcb;
						tcb->ssthreshold = MAX(tcb->cgwin/2,2*tcb->payload_mss);

						fast_retransmit_holes(tcb);

						tcb->cong_st=CONGCTRL_ST_FAST_RECOV;
					}
				}else{
					tcb->cgwin += acked_size; // We use ABC (Appropriate Byte Counting) for cwnd increase
					if(tcb->cgwin > tcb->ssthreshold) {
						DEBUG("Tresh: SS -> AVOID");
						LOG_MESSAGE("Tresh: SS -> AVOID");
						tcb->cong_st = CONGCTRL_ST_CONG_AVOID;
						tcb->repeated_acks = 0;
					}
				}
				break;
			case CONGCTRL_ST_CONG_AVOID: 

				if(is_dupack){
					tcb->repeated_acks++;
					DEBUG("DUPACK #%d", tcb->repeated_acks);
				}else{
					tcb->repeated_acks = 0;
				}
				
				if (tcb->repeated_acks == FAST_RETX_DUPACK_THRESH){
					DEBUG("%d DUPACKS: AVOID -> FAST", tcb->repeated_acks);
					LOG_MESSAGE("DUPACK: AVOID -> FAST");
					if(tcb->txfirst!= NULL){
						struct txcontrolbuf * txcb;
						tcb->ssthreshold = MAX(tcb->cgwin/2,2*tcb->payload_mss);

						fast_retransmit_holes(tcb);

						tcb->cong_st=CONGCTRL_ST_FAST_RECOV;
					}
				}
				else {// normal CONG AVOID 
					tcb->cgwin += (acked_size)*(tcb->payload_mss)/tcb->cgwin; // We use ABC (Appropriate Byte Counting) for cwnd increase
					if (tcb->cgwin<tcb->payload_mss){
						tcb->cgwin = tcb->payload_mss;
					}
				}
				break;

			case CONGCTRL_ST_FAST_RECOV:
				if(!is_repeated_ack){
					DEBUG("ACK: FAST -> AVOID");
					LOG_MESSAGE("ACK: FAST -> AVOID");
					tcb->cgwin = tcb->ssthreshold;
					tcb->lta = 0;
					tcb->cong_st = CONGCTRL_ST_CONG_AVOID;
					tcb->repeated_acks=0;
				}
				break;
        }

		tcb->last_ack = tcp->ack; //in network order

	} else if (event == FSM_EVENT_TIMEOUT) {
		DEBUG("TIMEOUT! %lli -> %lli %"PRIu64, tcb->timeout, MIN( MAX_TIMEOUT , tcb->timeout*2 ), tick);
		LOG_MESSAGE("TIMEOUT!");

		tcb->ssthreshold = MAX(tcb->cgwin/2,2*tcb->payload_mss);

		tcb->cgwin = INIT_CGWIN * tcb->payload_mss;
		tcb->timeout = MIN( MAX_TIMEOUT , tcb->timeout*2 );
		tcb->rtt_e = 0; /* RFC 6298 Note 2 page 6 */
		tcb->cong_st = CONGCTRL_ST_SLOW_START;
		DEBUG("Timeout: X -> SS");

		struct txcontrolbuf* cursor = tcb->txfirst->next;
		while(cursor != NULL){
			if(cursor->txtime >= 0 && cursor->segment != NULL){
				cursor->txtime = -MAX_TIMEOUT;
				cursor->retry = 0;
			}
			cursor = cursor->next;
		}
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

	struct channel_rx_queue_node* to_return = mymalloc(sizeof(struct channel_rx_queue_node));
	to_return->prev = prev;
	to_return->next = next;
	to_return->channel_offset = channel_offset;
	to_return->total_segment_length = htons(ip->totlen) - (ip->ver_ihl&0xF)*4;
	to_return->sid = sid;
	to_return->lss = lss;
	to_return->payload_length = to_return->total_segment_length - (tcp->d_offs_res>>4)*4;
	to_return->dummy_payload = tcp->d_offs_res & 0x01;
	to_return->fin = tcp->flags & FIN;
	if((to_return->payload_length <= 0 || to_return->total_segment_length <= 0) && !to_return->fin){
		/*
		The case == 0 is used to ensure that we are not inserting a segment with no payload (like a DupACK) in the queue. This should be avoided
		in the caller function, and we should never get here.
		The case < 0 is used to try to catch errors related to invalid pointers passed to this function. 
		*/
		ERROR("create_channel_rx_queue_node invalid length payload %d segment %d", to_return->payload_length, to_return->total_segment_length);
	}
	to_return->segment = mymalloc(to_return->total_segment_length);
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
	
	struct stream_rx_queue_node* to_return = (struct stream_rx_queue_node*) mymalloc(sizeof(struct stream_rx_queue_node));
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



bool does_stream_have_hole(int s, int sid){
	if(s < MIN_FD || s >= MAX_FD){
		ERROR("does_stream_have_hole invalid fd %d", s);
	}
	struct tcpctrlblk* tcb = fdinfo[s].tcb;
	if(tcb == NULL){
		ERROR("does_stream_have_hole tcb NULL");
	}
	if(sid < 0){
		ERROR("does_stream_have_hole sid %d < 0", sid);
	}
	if(tcb->stream_state[sid] != STREAM_STATE_OPENED){
		ERROR("does_stream_have_hole invalid stream state %d", tcb->stream_state[sid]);
	}

	struct txcontrolbuf* iter = tcb->txfirst;
	bool found_non_sacked = false;
	while(iter != NULL){
		if(iter->sid == sid){
			bool is_sacked = (iter->segment == NULL);
			if(!is_sacked){
				found_non_sacked = true;
			}else{
				if(found_non_sacked){
					// This segment is SACKed but a segment before this was not SACKed so we have a hole
					return true; // this stream has a hole
				}
			}
		}
		iter = iter->next;
	}

	return false; // this stream does not have a hole
}

void stream_holes_scheduler(int s){
	if(s < MIN_FD || s >= MAX_FD){
		ERROR("stream_holes_scheduler invalid fd %d", s);
	}
	struct tcpctrlblk* tcb = fdinfo[s].tcb;
	if(tcb == NULL){
		ERROR("stream_holes_scheduler tcb NULL");
	}
	const int max_payload_length = TCP_MSS - FIXED_OPTIONS_LENGTH;
	uint8_t temp_payload_buf[max_payload_length];


	int sids_list[TOT_SID];
	int sids_list_length = 0;
	static int circular_start_sid = 0;

	// Only insert opened streams in the list
	for (int i = 0; i < TOT_SID; i++) {
		int sid = (circular_start_sid + i) % TOT_SID;
		if (tcb->stream_state[sid] == STREAM_STATE_OPENED) {
			sids_list[sids_list_length] = sid;
			sids_list_length++;
		}
	}
	circular_start_sid = (circular_start_sid + 1) % TOT_SID;

	// Move all the sids that have at least 1 hole to the end of the list
	int temp_list[TOT_SID];
	int without_holes_counter = 0;
	int with_holes_counter = 0;

	for (int sid_list_i = 0; sid_list_i < sids_list_length; sid_list_i++) {
		int sid = sids_list[sid_list_i];

		// Does this sid have a hole?
		const bool hole = does_stream_have_hole(s, sid);
		if (hole) {
			temp_list[sids_list_length - 1 - with_holes_counter] = sid;  // Place hole streams from the back
			with_holes_counter++;
		} else {
			temp_list[without_holes_counter] = sid; // Place normal streams from the front
			without_holes_counter++;
		}
	}
	if(without_holes_counter + with_holes_counter != sids_list_length){
		ERROR("Error during holes reordering %d + %d != %d", without_holes_counter, with_holes_counter, sids_list_length);
	}
    for (int i = 0; i < without_holes_counter; i++) {
        sids_list[i] = temp_list[i];
    }
    for (int i = 0; i < with_holes_counter; i++) {
        sids_list[without_holes_counter + i] = temp_list[sids_list_length - 1 - i];
    }


	for(int sid_list_i = 0; sid_list_i < sids_list_length; sid_list_i++){
		int sid = sids_list[sid_list_i];

		// We can transmit some more data on the stream
		int available_bytes = TX_BUFFER_SIZE-tcb->txfree[sid];

		int cong_control_allowed_bytes = MAX(tcb->cgwin+tcb->lta - tcb->flightsize, 0);

		int flow_control_allowed_bytes = tcb->scheduler_tokens[sid];

		if((available_bytes == 0 || cong_control_allowed_bytes == 0 || flow_control_allowed_bytes == 0) && tcb->write_side_close_state[sid] != WR_CLOSE_ST_LSS_REQUESTED){
			// We can do nothing for this stream
			// we cannot send data, and we cannot enqueue the LSS(/FIN), so we skip it
			continue;
		}

		LOG_SCHEDULER_BYTES(sid, available_bytes, flow_control_allowed_bytes, cong_control_allowed_bytes);
		int current_transfer_bytes = MIN(available_bytes, MIN(cong_control_allowed_bytes, flow_control_allowed_bytes));

		bool small_in_flight = false;
		if(current_transfer_bytes > 0){
			// Nagle check
			struct txcontrolbuf* tx_cursor = tcb->txfirst;
			while(tx_cursor != NULL){
				if(tx_cursor->sid == sid && !(tx_cursor->dummy_payload)){
					if(tx_cursor->segment != NULL){ // We ignore SACKed segments for Nagle on a stream
						if(tx_cursor->payloadlen > 0 && tx_cursor->payloadlen != max_payload_length){
							small_in_flight = true;
							break;
						}
					}
				}
				tx_cursor = tx_cursor->next;
			}
		}


		

		while(current_transfer_bytes > 0){
			int payload_length = MIN(current_transfer_bytes, max_payload_length);
			if(payload_length < max_payload_length && small_in_flight){
				break;
			}

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
			tcb->scheduler_tokens[sid] -= payload_length;

			if(!tcb->ms_option_enabled){
				prepare_tcp(s, -1, ACK, temp_payload_buf, payload_length, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
			}else{
				int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
				uint8_t opt[sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS)];
				memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
				
				// Stream update
				opt[2] = sid<<2 | (((tcb->next_ssn[sid])>>8) & 0x03);
				opt[3] = (tcb->next_ssn[sid]) & 0xFF;
				update_next_ssn(&(tcb->next_ssn[sid]));

				prepare_tcp(s, -1, ACK, temp_payload_buf, payload_length, opt, optlen);
			}
		}

		if(tcb->write_side_close_state[sid] == WR_CLOSE_ST_LSS_REQUESTED){
			if(tcb->txfree[sid] == TX_BUFFER_SIZE){
				if(!tcb->ms_option_enabled){
					prepare_tcp(s, -1, ACK | FIN, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
				}else{
					// Enqueue LSS segment
					int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
					uint8_t opt[sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS)];
					memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
					
					// Stream update
					opt[2] = (0b1 << 7) | sid<<2 | ((tcb->next_ssn[sid] >> 8)&0x3);
					opt[3] = (tcb->next_ssn[sid])&0xFF;
					update_next_ssn(&(tcb->next_ssn[sid]));

					uint8_t dummy_payload[1] = {0}; // value doesn't matter

					prepare_tcp(s, -1, ACK | DMP, dummy_payload, 1, opt, optlen);
				}

				tcb->write_side_close_state[sid] = WR_CLOSE_ST_LSS_TXED;
			}
		}
	}
}



// Abstract scheduler stub to call one of the different scheduler implementations
void scheduler(int s /* socket fd */){
	assert_handler_lock_acquired("scheduler");
	stream_holes_scheduler(s);
}

bool is_dmp_ack_needed(struct tcpctrlblk* tcb, int sid){
	if(tcb == NULL){
		ERROR("is_dmp_ack_needed tcb NULL");
	}
	if(sid < 0 || sid > MAX_SID){
		ERROR("is_dmp_ack_needed invalid sid %d", sid);
	}
	// This is an easy policy.
	// We could also check from the start to the end to see if we find any segment yet to be transmitted for the same SID
	// that would for sure be transmitted before the new one
	// Note: If we do this optimization, it must have been never transmitted, it is not enough that it is about to be transmitted now
	// because otherwise it could be acked in the meanwhile and the DMP ack would never be TXed
	return tcb->txfirst == NULL || tcb->txlast->retry != 0 || tcb->txlast->sid != sid;
}




bool port_in_use(unsigned short port){
	int s;
	for (s=MIN_FD; s<MAX_FD; s++){
		if(fdinfo[s].st != FDINFO_ST_FREE && fdinfo[s].st != FDINFO_ST_UNBOUND){
			if(fdinfo[s].l_port == htons(port)){
				return true;
			}
		}
	}
	return false;
}


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
	if(s < MIN_FD || s >= MAX_FD){
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
	for(i=MIN_FD; i<MAX_FD && fdinfo[i].st!=FDINFO_ST_FREE;i++){}
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
	if(s < MIN_FD || s >= MAX_FD){
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

			struct tcpctrlblk* tcb = fdinfo[s].tcb = (struct tcpctrlblk*) mymalloc(sizeof(struct tcpctrlblk));
			bzero(tcb, sizeof(struct tcpctrlblk));
			fdinfo[s].st = FDINFO_ST_TCB_CREATED;
			fdinfo[s].sid = 0;
			tcb->st = TCB_ST_CLOSED;

			tcb->seq_offs=gen_sequence_offset();
			tcb->ack_offs=0;
			tcb->stream_end=0xFFFFFFFF; //Max file
			tcb->mss = TCP_MSS;
			tcb->payload_mss = tcb->mss - FIXED_OPTIONS_LENGTH;
			tcb->highest_sent_sequence_number = tcb->sequence = 0;
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
			tcb->requested_acks = 0;

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
				tcb->scheduler_tokens[i] = 0; // This will be initialized with the reception of the SYN+ACK
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
			const int opt_len = 19;
			uint8_t opt_ptr[19];

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
			prepare_tcp(s, -1, SYN,NULL,0,opt_ptr,opt_len);

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
					
					// At this point the connection is a good candidate: search for a myfree stream
					for(int stream = 0; stream < TOT_SID; stream++){
						if(tcb->stream_state[stream] == STREAM_STATE_UNUSED){
							// Free stream found
							fdinfo[s].st = FDINFO_ST_TCB_CREATED;
							fdinfo[s].tcb = tcb;
							fdinfo[s].sid = stream;
							fdinfo[s].l_addr = fdinfo[other_s].l_addr;
							fdinfo[s].l_port = fdinfo[other_s].l_port;
							fdinfo[s].tcb->stream_state[stream] = STREAM_STATE_OPENED;
							fdinfo[s].tcb->scheduler_tokens[stream] = fdinfo[s].tcb->init_radwin;
							fdinfo[s].tcb->txfree[stream] = TX_BUFFER_SIZE;
							fdinfo[s].tcb->tx_buffer_occupied_region_start[stream] = fdinfo[s].tcb->tx_buffer_occupied_region_end[stream] = 0;
							if(fdinfo[s].tcb->stream_tx_buffer[stream] != NULL){
								ERROR("stream_tx_buffer != NULL before mymalloc");
							}
							fdinfo[s].tcb->stream_tx_buffer[stream] = mymalloc(TX_BUFFER_SIZE);
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
									myfree(tmp->segment);
								}
								myfree(tmp);
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
			struct tcpctrlblk* tcb = fdinfo[s].tcb = (struct tcpctrlblk*) mymalloc(sizeof(struct tcpctrlblk));
			bzero(tcb, sizeof(struct tcpctrlblk));
			fdinfo[s].st = FDINFO_ST_TCB_CREATED;
			fdinfo[s].sid = 0;
			tcb->st = TCB_ST_CLOSED;

			tcb->seq_offs=gen_sequence_offset();
			tcb->ack_offs=0;
			tcb->stream_end=0xFFFFFFFF;
			tcb->mss = TCP_MSS;
			tcb->payload_mss = tcb->mss - FIXED_OPTIONS_LENGTH;
			tcb->highest_sent_sequence_number = tcb->sequence = 0;
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
			tcb->requested_acks = 0;

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
				tcb->scheduler_tokens[i] = 0; // This will be initialized with the reception of the SYN+ACK
				tcb->txfree[i] = 0;
				tcb->tx_buffer_occupied_region_start[i] = tcb->tx_buffer_occupied_region_end[i] = 0;
				tcb->next_ssn[i] = 0;
				tcb->next_rx_ssn[i] = 0;
				tcb->stream_fsm_timer[i] = 0;
				tcb->write_side_close_state[i] = WR_CLOSE_ST_OPEN;
				tcb->lss_received[i] = tcb->lss_consumed[i] = false;
			}


			// send SYN with MS option
			const int opt_len = 23;
			uint8_t opt_ptr[23];

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
			prepare_tcp(s, -1, SYN,NULL,0,opt_ptr,opt_len);

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
					myfree(tcb->txfirst->segment);
					myfree(tcb->txfirst);
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

					tcb->init_radwin = tcb->scheduler_tokens[0] = inflate_window_scale(ntohs(tcp->window), tcb->in_window_scale_factor);
					tcb->txfree[0] = TX_BUFFER_SIZE;
					tcb->tx_buffer_occupied_region_start[0] = tcb->tx_buffer_occupied_region_end[0] = 0;
					if(tcb->stream_tx_buffer[0] != NULL){
						ERROR("stream_tx_buffer != NULL before mymalloc");
					}
					tcb->stream_tx_buffer[0] = mymalloc(TX_BUFFER_SIZE);
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
					prepare_tcp(s, -1, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));

					tcb->st = TCB_ST_ESTABLISHED;
					hs_time_tot  += get_timestamp_ms() - hs_time_start;
				}
			}
			break;
		case TCB_ST_LISTEN:
			if(event == FSM_EVENT_PKT_RCV){
				if((!(tcp->flags & SYN)) && (tcp->flags & ACK)){
					// ACK of the 3 way handshake: Find the corresponding entry in the backlog, and transition it from SYN_RECEIVED to ESTABLISHED

					int backlog_index;
					for(backlog_index = 0; backlog_index < fdinfo[s].backlog_length; backlog_index++){
						tcb = &(fdinfo[s].channel_backlog[backlog_index]);
						if(tcb->st == TCB_ST_SYN_RECEIVED && (tcp->s_port == tcb->r_port) && (ip->srcaddr == tcb->r_addr)){
							// found matching backlog entry

							// the current pointer "tcb" will be used for the remaining part of the code
							break;
						}
					}
					if(backlog_index == fdinfo[s].backlog_length){
						// no backlog entry found
						break;
					}

					if(htonl(tcp->ack) == tcb->seq_offs + 1){
						// Passive open connection establishment
						myfree(tcb->txfirst->segment);
						myfree(tcb->txfirst);
						tcb->txfirst = tcb->txlast = NULL;
						tcb->seq_offs++;
						tcb->ack_offs=htonl(tcp->seq);
						tcb->st = TCB_ST_ESTABLISHED;
						
						if(fdinfo[s].backlog_length == fdinfo[s].ready_channels){
							// The incoming connection (MS or not) cannot be accepted
							fast_send_tcp(s, -1, RST, NULL, 0); // What should the destination address and port be?
							ERROR("TODO reset TCB");
						}
						fdinfo[s].ready_channels++;
						fdinfo[s].ready_streams++; // Stream 0 is counted but is not inserted in the stream backlog

						/* Initialization of the stream-specific fields and buffers */

						tcb->stream_state[0] = STREAM_STATE_READY;
						tcb->stream_tx_buffer[0] = mymalloc(TX_BUFFER_SIZE);
						tcb->stream_rx_queue[0] = tcb->stream_rx_queue_tail[0] = NULL;
						//tcb->adwin[0] = RX_VIRTUAL_BUFFER_SIZE; // For stream 0 this is initialized when the SYN is received
						tcb->scheduler_tokens[0] = inflate_window_scale(ntohs(tcp->window), tcb->in_window_scale_factor);
						tcb->txfree[0] = TX_BUFFER_SIZE;
						tcb->tx_buffer_occupied_region_start[0] = tcb->tx_buffer_occupied_region_end[0] = 0;
						tcb->next_ssn[0] = 1; // SSN 0 already sent (SYN)

						tcb->next_rx_ssn[0] = 1; // SSN 0 already received (SYN+ACK)
						tcb->stream_fsm_timer[0] = 0;
						for(int i = 1; i<TOT_SID; i++){ // Initialize as unused all the streams after SID 0
							tcb->stream_state[i] = STREAM_STATE_UNUSED;
							tcb->stream_tx_buffer[i] = NULL;
							tcb->stream_rx_queue[i] = tcb->stream_rx_queue_tail[i] = NULL;
							tcb->adwin[i] = RX_VIRTUAL_BUFFER_SIZE; // RX buffer size
							tcb->scheduler_tokens[i] = 0; // Initialized when the stream is created, based on the remote window for that stream
							tcb->txfree[i] = 0;
							tcb->tx_buffer_occupied_region_start[i] = tcb->tx_buffer_occupied_region_end[i] = 0;
							tcb->next_ssn[i] = 0;
							tcb->next_rx_ssn[i] = 0;
							tcb->stream_fsm_timer[i] = 0;
							tcb->write_side_close_state[i] = WR_CLOSE_ST_OPEN;
							tcb->lss_received[i] = tcb->lss_consumed[i] = false;
						}
						tcb->listening_fd = s;
					}


					break;
				}

				if(!(tcp->flags & SYN)){
					break;
				}

				// The packet is a SYN: create a backlog entry for the new connection, and set it to state SYN_RECEIVED


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




				// End of SYN segment parsing: now we can duplicate the TCB and modify the one in the backlog

				int cursor_index;
				for(cursor_index = 0; cursor_index < fdinfo[s].backlog_length && fdinfo[s].channel_backlog[cursor_index].st != 0; cursor_index++); // Empty entries are bzero-ed, so they will have state 0
				if(cursor_index == fdinfo[s].backlog_length){
					ERROR("insufficient backlog size; the connection request should be ignored or RSTed");
				}
				struct tcpctrlblk* backlog_tcb = fdinfo[s].channel_backlog + cursor_index; // myfree tcb in the backlog
				memcpy(backlog_tcb, tcb, sizeof(struct tcpctrlblk));

				tcb = backlog_tcb;


				DEBUG("TCB duplicated in backlog entry %d", cursor_index);

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

				tcb->st = TCB_ST_SYN_RECEIVED; // state of the TCB in the backlog. The listening socket TCB remains in state LISTEN


				int opt_len;
				uint8_t opt_ptr[23];
				if(tcb->ms_option_enabled){
					opt_len = 23;

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
				//ERROR("Non va bene! Il segmento va aggiunto alla coda del TCB nella backlog, non a quello in stato LISTEN");
				prepare_tcp(s, cursor_index, SYN|ACK, NULL, 0, opt_ptr, opt_len);
			}
			break;
		case TCB_ST_ESTABLISHED:
			if(event ==FSM_EVENT_PKT_RCV && (tcp->flags & SYN)){
				// The SYN+ACK has been retransmitted (ignored)
				break;
			}else if(event == FSM_EVENT_STREAM_TIMEOUT){
				int sid = fdinfo[s].sid;
				int ssn = fdinfo[s].tcb->next_ssn[sid];
				const int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
				uint8_t opt[optlen];
				memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
				
				// Stream update
				opt[2] = sid<<2 | ssn >> 8;
				opt[3] = ssn & 0xFF;

				update_next_ssn(&(fdinfo[s].tcb->next_ssn[sid]));

				uint8_t dummy_payload[1] = {0}; // value doesn't matter

				prepare_tcp(s, -1, ACK | DMP, dummy_payload, 1, opt, optlen);

				break;
			} else if(event == FSM_EVENT_PKT_RCV){
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

							tcb->scheduler_tokens[sid] = inflate_window_scale(ntohs(tcp->window), tcb->in_window_scale_factor);
							tcb->txfree[sid] = TX_BUFFER_SIZE;
							tcb->tx_buffer_occupied_region_start[sid] = tcb->tx_buffer_occupied_region_end[sid] = 0;
							if(tcb->stream_tx_buffer[sid] != NULL){
								ERROR("stream_tx_buffer != NULL before mymalloc");
							}
							tcb->stream_tx_buffer[sid] = mymalloc(TX_BUFFER_SIZE);
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
							cursor->next = (struct stream_backlog_node*) mymalloc(sizeof(struct stream_backlog_node));
							cursor->next->sid = sid;
							cursor->next->tcb = tcb;
							cursor->next->next = NULL;
							fdinfo[tcb->listening_fd].ready_streams++;
						}
					}
				}
				if(tcp->flags & FIN){
					if(tcb->ms_option_enabled){
						// With MS-TCP, we send the FIN+ACK immediately
						prepare_tcp(s, -1, FIN|ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
						tcb->st = TCB_ST_LAST_ACK;
						DEBUG("TCB_ST_ESTABLISHED -> TCB_ST_LAST_ACK");
						LOG_MESSAGE("TCB_ST_ESTABLISHED -> TCB_ST_LAST_ACK");
					}else{
						ERROR("Transition TCB_ST_ESTABLISHED -> TCB_STATE_CLOSE_WAIT not yet handled for non-MS connections");
					}
				}
			}else if(event == FSM_EVENT_DO_CHANNEL_CLOSE){
				prepare_tcp(s, -1, FIN|ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
				tcb->st = TCB_ST_FIN_WAIT_1;
				DEBUG("TCB_ST_ESTABLISHED -> TCB_ST_FIN_WAIT_1");
				LOG_MESSAGE("TCB_ST_ESTABLISHED -> TCB_ST_FIN_WAIT_1");
				break;
			}
			break;
		case TCB_ST_FIN_WAIT_1:
			if(event == FSM_EVENT_PKT_RCV){
				if(tcb->txlast == NULL){
					ERROR("TX queue empty but we are still in TCB_ST_FIN_WAIT_1");
				}
				if(tcb->txlast->segment == NULL){
					ERROR("txlast should not be acked/sacked in TCB_ST_FIN_WAIT_1");
				}
				if(!(tcb->txlast->fin)){
					ERROR("txlast should be the FIN in TCB_ST_FIN_WAIT_1");
				}
				if(tcb->txlast->payloadlen != 0){
					ERROR("txlast should be 0-length in TCB_ST_FIN_WAIT_1");
				}
				bool fin_acked = (tcp->ack == htonl(ntohl(tcb->txlast->segment->seq)+1));
				bool fin_received = ((tcp->flags)&FIN);
				DEBUG("FSM_EVENT_PKT_RCV TCB_ST_FIN_WAIT_1 fin_acked %d fin_received %d", fin_acked, fin_received);
				if(fin_acked && fin_received){
					// Direct transition to TIME_WAIT (RFC 9293, 3.3.2, Note 2)
					tcb->fsm_timer = tick + tcb->timeout * 4;
					tcb->st = TCB_ST_TIME_WAIT;
					DEBUG("TCB_ST_FIN_WAIT_1 -> TCB_ST_TIME_WAIT");
					LOG_MESSAGE("TCB_ST_FIN_WAIT_1 -> TCB_ST_TIME_WAIT");
				}else if(fin_acked && !fin_received){
					tcb->st = TCB_ST_FIN_WAIT_2;
					DEBUG("TCB_ST_FIN_WAIT_1 -> TCB_ST_FIN_WAIT_2");
					LOG_MESSAGE("TCB_ST_FIN_WAIT_1 -> TCB_ST_FIN_WAIT_2");
				}else if(fin_received && !fin_acked){
					if(tcb->ms_option_enabled){
						ERROR("Transition FIN_WAIT_1 to CLOSING cannot happen with MSTCP");
					}
					tcb->st = TCB_ST_CLOSING;
					DEBUG("TCB_ST_FIN_WAIT_1 -> TCB_ST_CLOSING");
					LOG_MESSAGE("TCB_ST_FIN_WAIT_1 -> TCB_ST_CLOSING");
				}else{
					// stay in FIN_WAIT_1
				}
			}
			break;
		case TCB_ST_FIN_WAIT_2:
			if(event == FSM_EVENT_PKT_RCV){
				bool fin_received = ((tcp->flags)&FIN);
				if(fin_received){
					tcb->fsm_timer = tick + tcb->timeout * 4;
					tcb->st = TCB_ST_TIME_WAIT;
					DEBUG("TCB_ST_FIN_WAIT_2 -> TCB_ST_TIME_WAIT (timeout %d)", tcb->timeout * 4);
					LOG_MESSAGE("TCB_ST_FIN_WAIT_2 -> TCB_ST_TIME_WAIT");
				}
			}
			break;
		case TCB_ST_LAST_ACK:
			if(event == FSM_EVENT_PKT_RCV){
				bool fin_acked = (tcp->ack == htonl(ntohl(tcb->txlast->segment->seq)+1));
				if(fin_acked){
					// Go into time wait, but exit immediately
					// This is to avoid duplication of the TIME_WAIT cleanup code, but there should be no
					// timeout in this case according to RFC 9293
					tcb->fsm_timer = tick + 0;
					tcb->st = TCB_ST_TIME_WAIT;
					DEBUG("TCB_ST_LAST_ACK -> TCB_ST_TIME_WAIT (timeout 0)");
					LOG_MESSAGE("TCB_ST_LAST_ACK -> TCB_ST_TIME_WAIT");
				}
			}
		case TCB_ST_TIME_WAIT:
			if(event == FSM_EVENT_TIMEOUT){
				// TX queue (segment may be NULL)
				while(tcb->txfirst != NULL){
					struct txcontrolbuf* next = tcb->txfirst->next;
					if(tcb->txfirst->segment != NULL){
						myfree(tcb->txfirst->segment);
					}
					myfree(tcb->txfirst);
					tcb->txfirst = next;
				}

				// Channel RX queue (segment is NULL if it was moved to a stream queue)
				while(tcb->unack != NULL){
					struct channel_rx_queue_node* next = tcb->unack->next;
					if(tcb->unack->segment != NULL){
						myfree(tcb->unack->segment);
					}
					myfree(tcb->unack);
					tcb->unack = next;
				}

				// Per-stream resources
				for(int sid = 0; sid <= MAX_SID; sid++){

					// Stream RX queue
					while(tcb->stream_rx_queue[sid] != NULL){
						struct stream_rx_queue_node* next = tcb->stream_rx_queue[sid]->next;
						if(tcb->stream_rx_queue[sid]->segment != NULL){
							myfree(tcb->stream_rx_queue[sid]->segment);
						}
						myfree(tcb->stream_rx_queue[sid]);
						tcb->stream_rx_queue[sid] = next;
					}

					if(tcb->stream_tx_buffer[sid] != NULL){
						myfree(tcb->stream_tx_buffer[sid]);
						tcb->stream_tx_buffer[sid] = NULL;
					}
				}

				// Passive side: check that there is nothing in the ready backlog for the current tcb
				if(!tcb->is_active_side){
					if(tcb->listening_fd < MIN_FD || tcb->listening_fd >= MAX_FD){
						ERROR("invalid tcb->listening_fd during TCB_ST_TIME_WAIT cleanup");
					}
					struct stream_backlog_node* prev = &(fdinfo[tcb->listening_fd].stream_backlog_head);
					while(prev->next != NULL){
						if(prev->next->tcb == tcb){
							ERROR("there should not be any ready stream for the closing TCB in TCB_ST_TIME_WAIT cleanup");
						}else{
							prev = prev->next;
						}
					}
				}

				// Release every fd that shares this TCB
				for(int f = MIN_FD; f < MAX_FD; f++){
					if(fdinfo[f].st == FDINFO_ST_TCB_CREATED && fdinfo[f].tcb == tcb){
						bzero(&fdinfo[f], sizeof(struct socket_info)); // st = FDINFO_ST_FREE (0)
						fdinfo[f].st=FDINFO_ST_FREE;
					}
				}

				// Free the TCB itself
				myfree(tcb);

				DEBUG("TCB_ST_TIME_WAIT TIMEOUT: connection closed, resources freed");
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
	if ( s < MIN_FD || s >= MAX_FD){
		myerrno = EBADF; 
		return -1;
	}

	if(myconnect_mode == MYCONNECT_MODE_BLOCKING){
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
	fdinfo[s].tcb = (struct tcpctrlblk *) mymalloc(sizeof(struct tcpctrlblk));
	bzero(fdinfo[s].tcb,sizeof(struct tcpctrlblk));
	fdinfo[s].st = FDINFO_ST_TCB_CREATED;
	fdinfo[s].tcb->st = TCB_ST_LISTEN;
	fdinfo[s].tcb->is_active_side = false;
	fdinfo[s].tcb->listening_fd = s;
	fdinfo[s].channel_backlog = (struct tcpctrlblk*) mymalloc(bl * sizeof(struct tcpctrlblk));
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
		for(free_fd=MIN_FD; free_fd<MAX_FD && fdinfo[free_fd].st!=FDINFO_ST_FREE; free_fd++); // Searching for myfree fd
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
			struct tcpctrlblk* tcb = (struct tcpctrlblk*) mymalloc(sizeof(struct tcpctrlblk));
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

			prepare_tcp(free_fd, -1, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
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
		myfree(first);

		prepare_tcp(free_fd, -1,  ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
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
			myfree(dmp_node->segment);
			myfree(dmp_node);
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
				myfree(dmp_node->segment);
				myfree(dmp_node);

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
			// myfree dmp_node and its segment
			myfree(dmp_node->segment);
			myfree(dmp_node);

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

			// myfree dmp_node and its segment
			myfree(dmp_node->segment);
			myfree(dmp_node);
		}
	}
	if(adwin_increased){
		if(!tcb->ms_option_enabled){
			fast_send_tcp(s, -1, ACK, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
		}else{
			if(is_dmp_ack_needed(tcb, sid)){
				const int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
				uint8_t opt[optlen];
				memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
				
				// Stream update
				opt[2] = sid<<2 | (tcb->next_ssn[sid] >> 8)&0x3;
				opt[3] = (tcb->next_ssn[sid])&0xFF;
				update_next_ssn(&(tcb->next_ssn[sid]));

				uint8_t dummy_payload[1] = {0}; // value doesn't matter

				prepare_tcp(s, -1, ACK | DMP, dummy_payload, 1, opt, optlen);
			}
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

void prepare_sid_for_reuse(struct tcpctrlblk* tcb, int sid){
	if(!(tcb->write_side_close_state[sid] == WR_CLOSE_ST_LSS_ACKED && tcb->lss_received[sid])){
		ERROR("prepare_sid_for_reuse sid %d not ready for reuse (%d %d)", sid, tcb->write_side_close_state[sid] == WR_CLOSE_ST_LSS_ACKED, tcb->lss_received[sid]);
	}
	/*
	We do not go throught STREAM_STATE_CLOSED. Another solution could be to go to state STREAM_STATE_CLOSED here, set a timer, and after that timer
	elapses reset the stream and prepare it for reuse. With the current version of the program there is only the close() operation, so there is no risk
	that if the LSS has been received the other peer is still reading or using the structures for this stream.
	*/
	while(tcb->stream_rx_queue[sid] != NULL){
		struct stream_rx_queue_node* tmp = tcb->stream_rx_queue[sid];
		tcb->stream_rx_queue[sid] = tcb->stream_rx_queue[sid]->next;
		if(!tmp->dummy_payload){
			ERROR("non-DMP remaining segment during prepare_sid_for_reuse flush");
		}
		if(tmp->segment != NULL){
			myfree(tmp->segment);
		}
		myfree(tmp);
	}

	tcb->stream_state[sid] = STREAM_STATE_UNUSED;
	tcb->adwin[sid] = RX_VIRTUAL_BUFFER_SIZE; // RX Buffer Size
	tcb->scheduler_tokens[sid] = tcb->init_radwin; 
	if(tcb->stream_tx_buffer[sid] != NULL){
		myfree(tcb->stream_tx_buffer[sid]);
		tcb->stream_tx_buffer[sid] = NULL;
	}
	tcb->txfree[sid] = TX_BUFFER_SIZE;
	tcb->tx_buffer_occupied_region_start[sid] = tcb->tx_buffer_occupied_region_end[sid] = 0;
	tcb->stream_fsm_timer[sid] = 0;

	//DEBUG("Stream %d ready for reuse", sid);
}

bool all_streams_unused(struct tcpctrlblk* tcb){
	if(tcb == NULL){
		ERROR("all_streams_unused tcb NULL");
	}
	for(int sid = 0; sid <= MAX_SID; sid++){
		if(tcb->stream_state[sid] != STREAM_STATE_UNUSED){
			return false;
		}
	}
	return true;
}

void stream_close_handler(int s, int sid){
	if(s < MIN_FD || s > MAX_FD){
		ERROR("stream_close_handler invalid fd %d", s);
	}
	struct tcpctrlblk* tcb = fdinfo[s].tcb;
	if(tcb == NULL){
		ERROR("stream_close_handler tcb NULL");
	}
	if(sid < 0 || sid > MAX_SID){
		ERROR("stream_close_handler invalid sid");
	}
	if(tcb->write_side_close_state[sid] == WR_CLOSE_ST_LSS_ACKED && tcb->lss_received[sid]){
		prepare_sid_for_reuse(tcb, sid);
		if(tcb->is_active_side && all_streams_unused(tcb)){
			DEBUG("all streams closed");
			fsm(s, FSM_EVENT_DO_CHANNEL_CLOSE, NULL, NULL);
		}
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
	//DEBUG("tcb->timeout %lli -> (%lli) %lli", tcb->timeout, tcb->rtt_e + KRTO*tcb->Drtt_e, MIN(MAX(tcb->rtt_e + KRTO*tcb->Drtt_e,MIN_TIMEOUT), MAX_TIMEOUT));
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
	int total_counter = 0;
	int handled_counter = 0;
	int out_ack_counter = 0;
	int req_ack_counter = 0;
	int dmp_counter = 0;
	int payload_counter = 0;
	int out_dmp_counter = 0;
	long scheduler_tot_time_ns = 0;

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

	check_rx_buffer_drops("myio_start");

	struct sockaddr_ll from;
	socklen_t from_len = sizeof(from);

	int received_packet_size; // mytcp: size
	while((received_packet_size = recvfrom(unique_raw_socket_fd,l2_rx_buf,L2_RX_BUF_SIZE,0, (struct sockaddr *)&from, &from_len))>=0){
		if (from.sll_pkttype == PACKET_OUTGOING) {
			continue;
		}
		if(received_packet_size < sizeof(struct ethernet_frame)){
			DEBUG("low received_packet_size %d < %lu", received_packet_size, sizeof(struct ethernet_frame));
			continue;
		}
		total_counter++;
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
			if(memcmp(&ip->dstaddr, myip, 4) != 0){ // Ignore packets not addressed to us
				continue;
			}
			if(ip->proto != TCP_PROTO){
				continue;
			}

			// TCP
			struct tcp_segment * tcp = (struct tcp_segment *) ((char*)ip + (ip->ver_ihl&0x0F)*4);

			int i;
			for(i=MIN_FD;i<MAX_FD;i++){
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
				for(i=MIN_FD;i<MAX_FD;i++){
					if( (fdinfo[i].st == FDINFO_ST_TCB_CREATED) &&(fdinfo[i].tcb->st == TCB_ST_LISTEN) && (tcp->d_port == fdinfo[i].l_port) ){
						break;
					}
				}
			}
			if(i == MAX_FD){
				// The packet is not for me
				continue; // go to the processing of the next received packet, if any
			}
			handled_counter++;

			LOG_TCP_SEGMENT("IN", (uint8_t*) tcp, htons(ip->totlen) - (ip->ver_ihl&0xF)*4);

			assert_handler_lock_acquired("myio FSM_EVENT_PKT_RCV");
			fsm(i, FSM_EVENT_PKT_RCV, ip, NULL);

			struct tcpctrlblk * tcb = fdinfo[i].tcb;
			int backlog_index = -1;

			if(tcb->st == TCB_ST_LISTEN){
				for(int backlog_i = 0; backlog_i < fdinfo[i].backlog_length; backlog_i ++){
					if(ip->srcaddr == fdinfo[i].channel_backlog[backlog_i].r_addr && tcp->s_port == fdinfo[i].channel_backlog[backlog_i].r_port){
						tcb = &(fdinfo[i].channel_backlog[backlog_i]);
						backlog_index = backlog_i;
						break;
					}
				}
			}

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
			bool fin = tcp->flags & FIN;

			int acked_size = 0; // Number of (non-DMP) bytes acknowledged by the incoming segment, used by congestion_control_fsm for ABC cgwin increase

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

				if((htonl(tcp->ack) >= shifter) && (htonl(tcp->ack)-shifter <= tcb->txlast->seq + ((uint32_t)tcb->txlast->payloadlen) + ((tcb->st > TCB_ST_ESTABLISHED && tcb->st != TCB_ST_CLOSE_WAIT)?1U:0U) - shifter)){
					bool send_window_advanced = false;
					while((tcb->txfirst!=NULL) && ((htonl(tcp->ack)-shifter) >= (tcb->txfirst->seq - shifter + tcb->txfirst->payloadlen + (tcb->txfirst->fin ? 1 : 0)))){ //Ack>=Seq+payloadlen
						struct txcontrolbuf * temp = tcb->txfirst;
						tcb->txfirst = tcb->txfirst->next;

						// RTT calculation removed

						if(!temp->dummy_payload && temp->payloadlen > 0){
							if(temp->segment != NULL){
								fdinfo[i].tcb->flightsize-=temp->payloadlen;

								/* 
								It is not clear (to me) if cgwin should be increased only for non-SACKed segments or for all segments cumulatively acked... 
								Since with a SACK we are most likely in some congestion event it seems more prudent to ignore SACKed segments for acked_size, but I'm not really sure about this
								*/
								acked_size += temp->payloadlen;
							}
						}

						if(temp->segment != NULL){
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
									stream_close_handler(i, sid);
								}
							}

							myfree(temp->segment);
							temp->segment = NULL;
						}
						myfree(temp);
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

							struct txcontrolbuf *cursor = tcb->txfirst;
							while(cursor != NULL){
								if(cursor->segment != NULL){
									uint32_t cursor_shifted_seq = cursor->seq - shifter;
									uint32_t cursor_shifted_end = cursor_shifted_seq + cursor->payloadlen;

									if(left_shifted_seq <= cursor_shifted_seq && cursor_shifted_end <= right_shifted_seq){
										//DEBUG("Something removed");
										// Remove the node from the tx queue

										if(!cursor->dummy_payload && cursor->payloadlen > 0){
											fdinfo[i].tcb->flightsize-=cursor->payloadlen;
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
												stream_close_handler(i, sid);
											}
										}

										myfree(cursor->segment);
										cursor->segment = NULL;
									}
								}
								
								cursor = cursor->next;
							}
						}
					}
				}

				congctrl_fsm(tcb,FSM_EVENT_PKT_RCV,tcp,payload_length, acked_size);
			}


			

			if(payload_length > 0 || fin){
				int sid = 0;
				int ssn = 0;
				bool dummy_payload = false;
				bool ms_option_included = false;
				if(tcb->ms_option_enabled && !fin){
					int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
					if(ms_index >= 0){
						sid = (tcp->payload[ms_index+2]>>2) & 0x1F;
						ssn = ((tcp->payload[ms_index+2]&0x3) << 8) | tcp->payload[ms_index+3];
						ms_option_included = true;
						dummy_payload = tcp->d_offs_res & (DMP >> 8);
					}
				}

				if(dummy_payload){
					dmp_counter++;
				}else{
					payload_counter++;
				}

				bool in_order_for_channel = true; // Updated later in the code

				uint32_t channel_offset = ntohl(tcp->seq)-tcb->ack_offs; // Position of this segment in the channel stream, without the initial random offset
				if(channel_offset >= tcb->cumulativeack){
					// This segment is not a duplicate of something already cumulative-acked


					if(ntohs(tcp->window) != 0){
						/* 
						We don't use segments that are with an ACK which is not the most advanced one, because if we use those segments naively
						we could make mistakes in the calculation of "calculated_scheduler_tokens".
						The problem could be that a segment arrives with an ACK number that include in the flow control calculation some segments
						that are not in the TX queue anymore (because cumulativeACK already went past them with some other segments received before
						this one), and we can no longer know their size.
						We could do some tricks and upper-bound this, so instead of just ignoring the incoming out-of-order segment we could use a
						received advertised window reduced by the difference between the incoming ack and the most recent ack. However, this situation
						can arise only in case segments are reordered over the network, so for now this is just ignored.
						*/
						uint32_t highest_received_ack_shifted_network_order = htonl(tcb->seq_offs+tcb->sequence);
						if(tcb->txfirst != NULL){
							if(tcb->txfirst->segment == NULL){
								ERROR("There is something wrong with SACK, the first segment in the tx queue can never be a sacked segment");
							}
							highest_received_ack_shifted_network_order = tcb->txfirst->segment->seq;
						}
						if(tcp->ack == highest_received_ack_shifted_network_order){
							uint32_t new_radwin = inflate_window_scale(ntohs(tcp->window), tcb->in_window_scale_factor);
							int64_t calculated_scheduler_tokens = new_radwin; // signed to handle negative values in weird edge cases
							// We traverse the TX queue to look for all segments of that stream. 
							// If we found some segments (that will be after this cumulative ack) for the same stream without DMP, we decrease the number
							// of tokens to allocate. If we don't find any, we use new_radwin as the new token count directly
							struct txcontrolbuf* tx_queue_cursor = tcb->txfirst;
							while(tx_queue_cursor != NULL){
								if(tx_queue_cursor->sid == sid && !tx_queue_cursor->dummy_payload){
									calculated_scheduler_tokens -= tx_queue_cursor->payloadlen;
								}
								tx_queue_cursor = tx_queue_cursor->next;
							}
							if(calculated_scheduler_tokens > tcb->scheduler_tokens[sid]){
								/*
								We update the token count only if it increases, ensuring that it does not decrease.
								This is because, otherwise, this condition could happen, leading to a final value 
								of scheduler_tokens lower than it should be.
								- A sends a DMP segment with ACK X, SEQ Y, and Window 100
								- A consumes something more
								- A sends a DMP segment with ACK X, SEQ Y+1, Window 200
								- Over the wire, the packet with SEQ Y gets delayed, and arrives after Y+1
								- When Y+1 arrives, scheduler_tokens gets set to 200
								- If we don't do this check, when Y arrives scheduler_tokens is set to 100
								*/
								tcb->scheduler_tokens[sid] = calculated_scheduler_tokens;
							}
						}
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

						in_order_for_channel = false;

						if(tcb->ms_option_enabled && !newrx->fin){
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
										stream_close_handler(i, sid);
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
										// https://claude.ai/share/ab71f5f1-3c3c-4158-97f0-508a2705790e
										myfree(newrx_stream->segment);
										myfree(newrx_stream);
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
									if(tcb->unack->fin){
										// The FIN segment is not enqueued for any stream
										myfree(tcb->unack->segment);
										tcb->unack->segment = NULL;
									}else{
										DEBUG("Last received packet before error:");
										print_l2_packet(l2_rx_buf);
										DEBUG("unack:");
										print_tcp_segment(tcb->unack->segment);
										DEBUG("unack channel_offset: %u", tcb->unack->channel_offset);
										DEBUG("unack payload length %d", tcb->unack->payload_length);
										DEBUG("next_rx_ssn %d received %d", tcb->next_rx_ssn[sid], ssn);
										ERROR("in-order segment not consumed from channel queue");
									}
								}
							}else{
								// For non-MS connections, we can do here the insertion in the stream RX queue
								if(tcb->unack->segment == NULL){
									// This error is wrong after the SACK modification, this can happen if something is SACKed
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

							tcb->cumulativeack += tcb->unack->payload_length + (tcb->unack->fin ? 1 : 0);
							if(!tcb->unack->dummy_payload && !tcb->unack->fin){
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
							myfree(tcb->unack);
							tcb->unack = next;
						}
					}
				}

				if(!tcb->ms_option_enabled){
					if(!in_order_for_channel){
						fast_send_tcp(i, backlog_index, ACK, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
						out_ack_counter++;
						tcb->requested_acks = 0;
					}else{
						tcb->requested_acks++;
					}
				}else{
					if(ms_option_included){
						//prepare_tcp(i, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
						if(!dummy_payload && in_order_for_channel){
							tcb->requested_acks++;
						}
						else{
							if(!in_order_for_channel){
								fast_send_tcp(i, backlog_index, ACK, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
								out_ack_counter++;
								tcb->requested_acks = 0;
							}else{
								tcb->requested_acks++;
							}
						}
					}else{
						if(fin){
							fast_send_tcp(i, backlog_index, ACK, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
							out_ack_counter++;
							tcb->requested_acks = 0;
						}else{
							DEBUG("Unexpected packet with payload but no MSTCP option or FIN flag:");
							print_l2_packet(l2_rx_buf);
							ERROR("Should we generate an ACK for this packet?");
						}
					}
				}
			}

			// ts_recent update ( https://datatracker.ietf.org/doc/html/rfc7323#section-4.3 )
			int ts_index = search_tcp_option(tcp, OPT_KIND_TIMESTAMPS);
			if(ts_index < 0){
				print_l2_packet(l2_rx_buf);
				ERROR("Timestamps not received (myio)");
			}
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

			struct timespec start_scheduler, end_scheduler;
			clock_gettime(CLOCK_REALTIME, &start_scheduler);
			scheduler(i);
			clock_gettime(CLOCK_REALTIME, &end_scheduler);
			long scheduler_duration_ns = (end_scheduler.tv_sec - start_scheduler.tv_sec) * 1000000000L + (end_scheduler.tv_nsec - start_scheduler.tv_nsec);
			scheduler_tot_time_ns += scheduler_duration_ns;
		}



		
	}//packet reception while end

	/*
	// Generation of enqueued fast ACKs
	while(requested_acks_queue.head != NULL){
		struct ack_generation_queue_node* request_node = requested_acks_queue.head;

		// Generate a single ACK regardless of the number of requests
		fast_send_tcp(request_node->fd, request_node->backlog_index, ACK, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
		out_ack_counter++;


		requested_acks_queue.head = requested_acks_queue.head->next;
		myfree(request_node);
	}
	*/

	assert_handler_lock_acquired("myio end");

	clock_gettime(CLOCK_REALTIME, &end);
	long duration_ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
	long duration_us = duration_ns / 1000;
	if(duration_us > TIMER_USECS){
		//DEBUG("myio %ld us\tt %d h %d in_p %d in_d %d r_ack %d out_ack %d out_dmp %d sched %.0f", duration_us, total_counter, handled_counter, payload_counter, dmp_counter, req_ack_counter, out_ack_counter, out_dmp_counter, scheduler_tot_time_ns/1000.0);
	}

	check_rx_buffer_drops("myio_end");

	enable_signal_reception(true);
}
void mytimer(int ignored){
	int out_packet_counter = 0;
	int out_bytes_counter = 0;
	int resolve_gateway_counter = 0;
	long send_ip_ns = 0;
    long update_tcp_header_ns = 0;
	long sendto_ns = 0;
	long eim_ns = 0;
	struct timespec t0, t1;

	disable_signal_reception(true);
	struct timespec start, end;
	clock_gettime(CLOCK_REALTIME, &start);

	tick++;


	if(resolve_gateway_mac_requested){
		resolve_gateway_mac_requested = false;
		uint8_t dummy_destmac[6];
		resolve_mac(*((unsigned int*)gateway), dummy_destmac);
		resolve_gateway_counter++;
	}

	for(int i=0;i<MAX_FD;i++){
		if(fdinfo[i].st != FDINFO_ST_TCB_CREATED){
			continue;
		}

		int fdinfo_backlog_length = fdinfo[i].backlog_length;
		for(int backlog_index = 0; backlog_index <= fdinfo_backlog_length; backlog_index++){
			int prepare_tcp_backlog_index = backlog_index;
		
			struct tcpctrlblk* tcb;
			int fd_sid;

			if(backlog_index == fdinfo[i].backlog_length){
				// The last iteration is for the "main" TCB
				tcb = fdinfo[i].tcb;
				fd_sid = fdinfo[i].sid;
				prepare_tcp_backlog_index = -1;
			}else{
				tcb = &(fdinfo[i].channel_backlog[backlog_index]);
				fd_sid = 0; // fd_sid is valid only if tcb->st != 0
			}

			if(tcb->st == 0 || tcb->st == TCB_ST_LISTEN || tcb->st == TCB_ST_CLOSED){
				continue;
			}

			if((tcb->fsm_timer!=0) && (tcb->fsm_timer < tick)){
				fsm(i, FSM_EVENT_TIMEOUT, NULL, NULL);
				continue;
			}
			if(fd_sid != SID_UNASSIGNED && (tcb->stream_fsm_timer[fd_sid] != 0) && (tcb->stream_fsm_timer[fd_sid] <= tick)){
				/* Note: If for any reason the stream timeout is used for something different from the opening of streams without anything to transmit, you need to modify
				in prepare_tcp where the stream_fsm_timer is set to 0 if any segment is transmitted on the stream
				*/
				fsm(i, FSM_EVENT_STREAM_TIMEOUT, NULL, NULL);
				continue;
			}
			struct txcontrolbuf* txcb = tcb->txfirst;
			struct txcontrolbuf* prev = NULL;
			int acc = 0; // payload bytes accumulator
			bool something_sent_now = false;
			while(txcb != NULL && (acc < tcb->cgwin+tcb->lta || txcb->payloadlen == 0 || txcb->dummy_payload)){
				// Karn invalidation not handled
				if(txcb->retry == 0){
					// This is the first TX attempt for a segment, and at this point I know that there is enough space in the cwnd to send it, so it will be sent
					if(!txcb->dummy_payload){
						tcb->flightsize += txcb->payloadlen;
					}
				} else if(txcb->txtime > 0 && txcb->txtime+tcb->timeout > tick && txcb->segment != NULL){
					// txcb->segment != NULL ensures that we consider only non-SACKed segments for congestion control
					
					acc += txcb->payloadlen;
					prev = txcb;
					txcb = txcb->next;
					continue;
				}
				if(txcb->retry > 0 && txcb->payloadlen == 0 && txcb->segment != NULL && txcb->segment->flags == ACK){
					// If this is only an ACK without payload it does not need to be RETXed
					// we remove txcb from the TX queue
					myfree(txcb->segment);
					if(prev != NULL){
						prev->next = txcb->next;
					}else{
						tcb->txfirst = txcb->next;
					}
					if(tcb->txlast == txcb){
						tcb->txlast = prev;
					}
					myfree(txcb);
					txcb = prev != NULL? prev->next : tcb->txfirst;
					continue;
				}
				if(txcb->segment == NULL){
					// we don't update acc for SACKed segments
					prev = txcb;
					txcb = txcb->next;
					continue;
				}
				bool is_fast_transmit = (txcb->txtime == 0); // Fast retransmit (when dupACKs are received) is done by setting txtime=0
				if(txcb->retry > 0){
					if(!is_fast_transmit){
						congctrl_fsm(tcb,FSM_EVENT_TIMEOUT,NULL,0,0);
						LOG_RTO(tcb->timeout);
					}

					// Reset the TX time of all other segments in the tx queue, otherwise they could trigger a timeout soon after this
					struct txcontrolbuf* cursor = txcb->next;
					while(cursor != NULL){
						if(cursor->retry > 0 && cursor->txtime > 0){
							cursor->txtime = tick;
						}
						cursor = cursor->next;
					}
				}
				txcb->retry++;
				txcb->txtime = tick;
				something_sent_now = true;

				clock_gettime(CLOCK_REALTIME, &t0);
				update_tcp_header(i, backlog_index == fdinfo_backlog_length ? -1 : backlog_index, txcb);
				clock_gettime(CLOCK_REALTIME, &t1);
                update_tcp_header_ns += (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);
				if(txcb->seq >= tcb->highest_sent_sequence_number){
					tcb->highest_sent_sequence_number = txcb->seq + txcb->payloadlen + (txcb->fin?1:0);
				}
				clock_gettime(CLOCK_REALTIME, &t0);
				send_ip((unsigned char*) txcb->segment, (unsigned char*) &(tcb->r_addr), txcb->totlen, TCP_PROTO);
				clock_gettime(CLOCK_REALTIME, &t1);
                send_ip_ns += (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);
				sendto_ns += sendto_call_time;
				eim_ns += eim_time;
				out_packet_counter++;
				out_bytes_counter += txcb->totlen;

				acc += txcb->payloadlen;
				prev = txcb;
				txcb = txcb->next;
			}
			if(!something_sent_now && tcb->requested_acks){
				// Note: this is not accounted for in the mytimer statistics (update_tcp_header_ns and send_ip_ns)
				fast_send_tcp(i, prepare_tcp_backlog_index, ACK, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
			}
			tcb->requested_acks = 0;
		}
	}

	clock_gettime(CLOCK_REALTIME, &end);
	long duration_ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
	long duration_us = duration_ns / 1000;
	if(duration_us > TIMER_USECS){
		//DEBUG("mytimer %ld us\tgw %d out_pkt %d bytes %d |\tuth %ld sip %ld st %ld eim %ld", duration_us, resolve_gateway_counter, out_packet_counter, out_bytes_counter, update_tcp_header_ns / 1000, send_ip_ns / 1000, sendto_ns / 1000, eim_ns / 1000);
	}
	enable_signal_reception(true);
}


/*
if USE_CUSTOM_MALLOC is defined, the following functions (to be used only in user-space) become thin wrappers around glibc's implementation, because
there will be no conflicts between the user malloc (based on glibc) and the TCP one (custom)
*/
// To be used in user code
void* safe_mymalloc(size_t sz){
	#ifndef USE_CUSTOM_MALLOC
	disable_signal_reception(false);
	void* ret = mymalloc(sz);
	if(ret == NULL && sz != 0){
		myperror("mymalloc");
		ERROR("safe_mymalloc %u failed", sz);
	}
	enable_signal_reception(false);
	return ret;
	#else
	return malloc(sz);
	#endif
}
// To be used in user code
void safe_myfree(void* ptr){
	#ifndef USE_CUSTOM_MALLOC
	disable_signal_reception(false);
	myfree(ptr);
	enable_signal_reception(false);
	#else
	return free(ptr);
	#endif
}
// To be used in user code
void* safe_myrealloc(void* ptr, size_t size){
	#ifndef USE_CUSTOM_MALLOC
	disable_signal_reception(false);
	void* to_return = myrealloc(ptr, size);
	enable_signal_reception(false);
	return to_return;
	#else
	return realloc(ptr, size);
	#endif
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
void free_img_list() {
	if (img_list == NULL) {
		return;
	}
	for (int i = 0; i < num_images; i++) {
		safe_myfree(img_list[i]);
		img_list[i] = NULL;
	}
	safe_myfree(img_list);
	img_list = NULL;
	num_images = 0;
}
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

	img_list = safe_mymalloc(num_images * sizeof(char*));

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

		img_list[cur_img] = safe_mymalloc(img_name_len + 1);
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
	char* data = safe_mymalloc(RESP_BUF_SIZE); // both req and resp
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
	safe_myfree(data);




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
	client_buffer[0] = safe_mymalloc(RESP_BUF_SIZE);
	
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
				client_buffer[i] = safe_mymalloc(RESP_BUF_SIZE);
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
			client_buffer[i] = safe_mymalloc(RESP_BUF_SIZE);
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
						continue;
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
					safe_myfree(client_buffer[i]);
					DEBUG("close %d", i);
				}
			}
		}
	}

	free_img_list();

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
	char* data = safe_mymalloc(RESP_BUF_SIZE); // both req and resp
	sprintf(data, "GET /%d HTTP/1.1\r\nX-Client-ID: %d\r\nX-Req-Num: %d\r\n\r\n", MIN(RESP_PAYLOAD_BYTES,1000), 0, -1);
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
		if(MAIN_LOOP_NANOSLEEP){
			nanosleep(&short_sleep, NULL);
		}
	}
	safe_myfree(data);


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
	client_buffer[0] = safe_mymalloc(RESP_BUF_SIZE);
	
	for(int i=1; i<num_clients_test; i++){
		s = mysocket(AF_INET,SOCK_STREAM,0);
		if(s == -1){
			myperror("mysocket");
			exit(EXIT_FAILURE);
		}
		client_sockets[i] = s;
	}
	DEBUG("all sockets created");

	while(true){

		// End main if all the clients are stopped
		bool all_stopped = true;
		for(int i=0; i<num_clients_test && all_stopped; i++){
			if(!client_connected[i] || client_active[i]){
				all_stopped = false;
			}
		}
		if(all_stopped){
			DEBUG("all clients stopped");
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
				client_buffer[i] = safe_mymalloc(RESP_BUF_SIZE);
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
			client_buffer[i] = safe_mymalloc(RESP_BUF_SIZE);
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
						continue;
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
					safe_myfree(client_buffer[i]);
				}
			}
		}
		if(MAIN_LOOP_NANOSLEEP){
			nanosleep(&short_sleep, NULL);
		}
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
	DEBUG("Total:  %.2f KB/s (%.2f Mbps) DL  |  %.2f KB/s UL  (%"PRId64" ms, %.2f s)", ((double)dl_sum) / meas_dur, ((double)dl_sum) / meas_dur * 8 / 1000, ((double)ul_sum) / meas_dur, meas_dur, ((double)(meas_dur)/1000));
	DEBUG("#################################################################");
	DEBUG("wait...");
	// persistent_nanosleep(0, 200000000); // wait 200 ms
	persistent_nanosleep(5, 0);
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
			DEBUG("tot\t\t%"PRId64" ms", get_timestamp_ms() - meas_start);
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
			struct single_srv_data* new_arr = safe_mymalloc(sizeof(struct single_srv_data)*(num_clients+1));
			if((num_clients == 0) != (clients == NULL)){
				ERROR("full_duplex_server_app invalid state num_clients client_sockets");
			}
			if(clients != NULL){
				memcpy(new_arr, clients, sizeof(struct single_srv_data)*num_clients);
				safe_myfree(clients);
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
					DEBUG("received close from client %d", i);
					myclose(clients[i].s);
					clients[i].srv_st = SERVER_ST_STOPPED;
					goto single_app_return;
				}
				if(n < 0){
					myperror("myread");
					ERROR("full_duplex_server_app myread failed for unexpected reasons");
				}
				strend += n;
				*strend= '\0';
				char* end_of_headers_substr = strstr(clients[i].req_arr, "\r\n\r\n"); 
				if(end_of_headers_substr != NULL){
					//DEBUG(clients[i].req_arr);

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
				num_clients--;
				DEBUG("num_clients=%d", num_clients);
				if(num_clients == 0){
					safe_myfree(clients);
					clients = NULL;
				}else{
					clients = safe_myrealloc(clients, sizeof(struct single_srv_data)*num_clients);
				}
			}else{
				cur++;
			}
		}
		if(MAIN_LOOP_NANOSLEEP){
			nanosleep(&short_sleep, NULL);
		}
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

	DEBUG("load_ifconfig OK");
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

	resolve_gateway_mac();

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
		if ( mylisten(listening_socket,128) == -1 ) { 
			myperror("mylisten"); 
			exit(EXIT_FAILURE);
		}
		DEBUG("mylisten OK");
		
		full_duplex_server_app(listening_socket);
	}else{
		ERROR("Invalid MAIN_MODE %d", MAIN_MODE);
	}
}