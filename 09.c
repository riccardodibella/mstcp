#define _DEFAULT_SOURCE

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

/* DEFINE MACROS */

#define MIN(x,y) ( ((x) > (y)) ? (y) : (x) )
#define MAX(x,y) ( ((x) < (y)) ? (y) : (x) )

#define NUM_CLIENTS 2
#define NUM_CLIENT_MESSAGES 100
#define MS_ENABLED true
#define CLIENT 0
#define SERVER 1
#ifndef MAIN_MODE // Compile with -DMAIN_MODE=CLIENT or -DMAIN_MODE=SERVER
#define MAIN_MODE CLIENT
#endif
#define MYREAD_MODE_BLOCKING 1
#define MYREAD_MODE_NON_BLOCKING 2
#define MYWRITE_MODE_BLOCKING 1
#define MYWRITE_MODE_NON_BLOCKING 2

#ifdef LOCAL_SERVER
#define SERVER_IP_STR "127.0.0.1"
#else
#define SERVER_IP_STR "172.104.237.69"
#endif

#define INTERFACE_NAME "eth0" // load_ifconfig
#define TIMER_USECS 500
#define MAX_ARP 200 // number of lines in the ARP cache
#define MAX_FD 16 // File descriptors go from 3 (included) up to this value (excluded)
#define L2_RX_BUF_SIZE 30000
#define MAXTIMEOUT 2000
// #define TODO_BUFFER_SIZE 64000
#define RX_VIRTUAL_BUFFER_SIZE 0x1000
#define TX_BUFFER_SIZE 64000
#define STREAM_OPEN_TIMEOUT 2 // in ticks

#define MIN_PORT 19000
#define MAX_PORT 19999

#define TCP_PROTO 6 // protocol field inside IP header

#define TCP_MSS 1460 // MTU = 1500, MSS = MTU - 20 (IP Header) - 20 (TCP Header)
#define FIXED_OPTIONS_LENGTH 40
#define MAX_SEGMENT_PAYLOAD (TCP_MSS - FIXED_OPTIONS_LENGTH) // 1420, may be used for congestion control

#define DEFAULT_WINDOW_SCALE 0 // Default parameter sent during the handshake

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
#define STREAM_STATE_LSS_SENT 3
#define STREAM_STATE_LSS_RCV 4
#define STREAM_STATE_CLOSED 5

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
	int totlen; // Includes IP header, TCP header, options and padding
	struct tcp_segment* segment;

	int64_t txtime;
	int retry;
};

struct channel_rx_queue_node{
	struct channel_rx_queue_node* next;
	uint32_t channel_offset; // sequence number - tcb->ack_offs
	int total_segment_length;
	int payload_length;
	int sid;
	struct tcp_segment* segment;
};
struct stream_rx_queue_node{
	struct stream_rx_queue_node* next;
	int sid;
	uint16_t ssn;
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
	unsigned short adwin[TOT_SID];
	unsigned short radwin[TOT_SID];
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
	unsigned int cumulativeack; // Channel property
	unsigned int ack_offs; // Channel property
    unsigned int seq_offs; // Channel property
	long long timeout; // Channel property
	unsigned int sequence; // Channel property 
	unsigned int mss; // Channel property
	unsigned int stream_end; // Channel property (bad name)
	unsigned int fsm_timer; // Channel property
	unsigned short init_radwin; // Used in MS-TCP as a default value for radwin of new streams

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

	/* CONG CTRL (channel properties) */
	//#ifdef CONGCTRL
	unsigned int ssthreshold;
	unsigned int rtt_e;
	unsigned int Drtt_e;
	unsigned int cong_st;
	unsigned int last_ack;
	unsigned int repeated_acks;
	unsigned int flightsize;
	unsigned int cgwin;
	unsigned int lta;
	//#endif
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

unsigned char myip[4];
unsigned char mymac[6];
unsigned char mask[4];
unsigned char gateway[4];

/* TXBUFSIZE and INIT_TIMEOUT may be modified at program startup */
//int TXBUFSIZE = 100000; // #define TXBUFSIZE    ((g_argc<3) ?100000:(atoi(g_argv[2])))  
// int INIT_TIMEOUT = 300*1000; // #define INIT_TIMEOUT (((g_argc<4) ?(300*1000):(atoi(g_argv[3])*1000))/TIMER_USECS)
int INIT_TIMEOUT = MAXTIMEOUT;

int unique_raw_socket_fd = -1; // mytcp: unique_s

int last_port=MIN_PORT; // Last assigned port during bind()

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

uint8_t print_buffer[1024];

/* FUNCTION DEFINITIONS */

// In case you need to know the name of the caller function: https://stackoverflow.com/a/16100246
void ERROR(char* c, ...){
	printf("ERROR %.6u: ", (uint32_t) tick);
	va_list args;
	va_start(args, c);
	vprintf(c, args);
	va_end(args);
	printf("\n");
	exit(EXIT_FAILURE);
}

void DEBUG(char* c, ...){
	printf("DEBUG %.6u: ", (uint32_t) tick);
	va_list args;
	va_start(args, c);
	vprintf(c, args);
	va_end(args);
	printf("\n");
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

void print_tcp_segment(struct tcp_segment* tcp){
	printf("----TCP SEGMENT----\n");
	printf("PORTS: SRC %u DST %u\n", htons(tcp->s_port), htons(tcp->d_port));
	printf("SEQ %u ACK %u\n", htonl(tcp->seq), htonl(tcp->ack));
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
	for(int i=0; i<6; i++){
		printf("%.2X%s", mac[i],i!=5?":":"\n");
	}
}
void print_ip(uint8_t* ip){
	for(int i=0; i<4; i++){
		printf("%d%s", ip[i],i!=3?".":"\n");
	}
}
void print_ip_datagram(struct ip_datagram* ip){
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
	printf("MYPERROR %s: %s\n", message, strerror(myerrno));
}

void acquire_handler_lock(){
	if(global_handler_lock != 1){
		ERROR("acquire_handler_lock global_handler_lock %d != 1", global_handler_lock);
	}
	global_handler_lock--;
	//DEBUG("a");
}

void release_handler_lock(){
	if(global_handler_lock != 0){
		ERROR("release_handler_lock global_handler_lock %d != 0", global_handler_lock);
	}
	global_handler_lock++;
	//DEBUG("r");
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
	ip->ver_ihl=0x45;
	ip->tos=0;
	ip->totlen=htons(20+payloadsize);
	ip->id = rand()&0xFFFF;
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

void send_ip(unsigned char * payload, unsigned char * targetip, int payloadlen, unsigned char proto){
	int i,t,len ;
	struct sockaddr_ll sll;
	unsigned char destmac[6];
	unsigned char packet[2000];
	struct ethernet_frame * eth = (struct ethernet_frame *) packet;
	struct ip_datagram * ip = (struct ip_datagram *) eth->payload; 

	// if(!(rand()%INV_LOSS_RATE) && g_argv[4][0]=='S') {printf("==========TX LOST ===============\n");return 1;}
	// if((losscounter++ == 25)  &&(g_argv[4][0]=='S')){printf("==========TX LOST ===============\n");return 1;}

	/**** HOST ROUTING */
	if( ((*(unsigned int*)targetip) & (*(unsigned int*) mask)) == ((*(unsigned int*)myip) & (*(unsigned int*) mask)))
		t = resolve_mac(*(unsigned int *)targetip, destmac); // if yes
	else
		t = resolve_mac(*(unsigned int *)gateway, destmac); // if not
	if(t==-1){
		ERROR("send_ip resolve_mac failed");
	}

	forge_ethernet(eth,destmac,0x0800);
	forge_ip(ip,payloadlen,proto,*(unsigned int *)targetip); 
	memcpy(ip->payload,payload,payloadlen);

	len=sizeof(sll);
	bzero(&sll,len);
	sll.sll_family=AF_PACKET;
	sll.sll_ifindex = if_nametoindex(INTERFACE_NAME);

	DEBUG("Outgoing send_ip packet:");
	print_l2_packet(packet);

	t=sendto(unique_raw_socket_fd, packet,14+20+payloadlen, 0, (struct sockaddr *)&sll,len);
	if (t == -1) {
		perror("send_ip sendto failed"); 
		exit(EXIT_FAILURE);
	}
}
#pragma endregion RAW_SOCKET_ACCESS







int prepare_tcp(int s, uint16_t flags /*Host order*/, uint8_t* payload, int payloadlen, uint8_t* options, int optlen){
	struct tcpctrlblk*tcb = fdinfo[s].tcb;
	struct txcontrolbuf * txcb = (struct txcontrolbuf*) malloc(sizeof( struct txcontrolbuf));
	if(fdinfo[s].l_port == 0 || tcb->r_port == 0){
		ERROR("prepare_tcp invalid port l %u r %u\n", htons(fdinfo[s].l_port), htons(tcb->r_port));
	}

	txcb->txtime = -MAXTIMEOUT ; 
	txcb->payloadlen = payloadlen;
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
		DEBUG("txcb sid %d ssn %d", txcb->sid, txcb->ssn);
		
		// Deactivate the FSM timer for this stream (we are sending a segment, so we don't need to wait for the timeout to open the new stream)
		tcb->stream_fsm_timer[txcb->sid] = 0;
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
unsigned short int tcp_checksum(uint8_t* b1, int len1, uint8_t* b2, int len2){
	uint16_t prev, total;
	prev = compl1(b1,len1); 
	total = (prev + compl1(b2,len2));
	if (total < prev ) total++;
	return (0xFFFF - total);
}

void update_tcp_header(int s, struct txcontrolbuf *txctrl){
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
			*(uint32_t*) (tcp->payload+i+2) = htonl(tick);

			// bytes i+6, i+7, i+8 and i+9 are for the most recent TS value to echo
			*(uint32_t*) (tcp->payload+i+6) = htonl(tcb->ts_recent); // ts_recent is 0 if this is a SYN (not SYN+ACK) packet
		}
		if(tcp->payload[i] == OPT_KIND_SACK){
			// DEBUG("TODO SACK update");
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
	tcp->window = htons(tcb->adwin[fdinfo[s].sid]);
	tcp->checksum = htons(tcp_checksum((uint8_t*) &pseudo, sizeof(pseudo), (uint8_t*) tcp, txctrl->totlen));
}


struct channel_rx_queue_node* create_channel_rx_queue_node(uint32_t channel_offset, struct ip_datagram* ip, struct tcp_segment* tcp, struct channel_rx_queue_node* next){
	// IP datagram is needed for segment and payload lengths
	// Instead of channel_offset we could pass the tcb as a parameter and calculate the channel_offset again here
	/*
	struct channel_rx_queue_node{
		struct channel_rx_queue_node* next;
		uint32_t channel_offset; // sequence number - tcb->ack_offs
		int total_segment_length;
		int payload_length;
		struct tcp_segment* segment;
	};
	*/
	if(ip == NULL || tcp == NULL){
		ERROR("create_channel_rx_queue_node unexpected NULL parameter");
	}
	int sid = 0;
	int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
	if(ms_index >= 0){
		sid = (tcp->payload[ms_index+2]>>2) & 0x1F;
	}

	struct channel_rx_queue_node* to_return = malloc(sizeof(struct channel_rx_queue_node));
	to_return->next = next;
	to_return->channel_offset = channel_offset;
	to_return->total_segment_length = htons(ip->totlen) - (ip->ver_ihl&0xF)*4;
	to_return->sid = sid;
	to_return->payload_length = to_return->total_segment_length - (tcp->d_offs_res>>4)*4;
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
	DEBUG("RX -> Channel offset %d", channel_offset);
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
	int ms_index = search_tcp_option(ch_node->segment, OPT_KIND_MS_TCP);
	if(ms_index < 0){
		ERROR("create_stream_rx_queue_node no ms option");
	}
	int sid = (ch_node->segment->payload[ms_index+2]>>2) & 0x1F;
	int ssn = ((ch_node->segment->payload[ms_index+2]&0x3) << 8) | ch_node->segment->payload[ms_index+3];
	// Last stream segment bit currently ignored

	struct stream_rx_queue_node* to_return = (struct stream_rx_queue_node*) malloc(sizeof(struct stream_rx_queue_node));

	to_return->next = NULL; // Always inserted at the end of the stream queue
	to_return->sid = sid;
	to_return->ssn = ssn;
	to_return->total_segment_length = ch_node->total_segment_length;
	to_return->payload_length = ch_node->payload_length;
	to_return->dummy_payload = (ch_node->segment->d_offs_res & 0x01);
	to_return->consumed_bytes = 0;
	to_return->segment = ch_node->segment;

	ch_node->segment = NULL;

	DEBUG("Channel -> Stream SID %d SSN %d (offset %d)", sid, ssn, ch_node->channel_offset);

	return to_return;
}




void direct_segmentation_scheduler(int s){
	if(s < 3 || s >= MAX_FD){
		ERROR("direct_segmentation_scheduler invalid fd %d", s);
	}
	struct tcpctrlblk* tcb = fdinfo[s].tcb;
	if(tcb == NULL){
		ERROR("direct_segmentation_scheduler tcb NULL");
	}
	DEBUG("direct_segmentation_scheduler start");
	const int max_payload_length = TCP_MSS - FIXED_OPTIONS_LENGTH;
	uint8_t* temp_payload_buf = malloc(max_payload_length);
	for(int sid = 0; sid < TOT_SID; sid++){
		if(tcb->stream_state[sid] == STREAM_STATE_OPENED || tcb->stream_state[sid] == STREAM_STATE_LSS_RCV){
			// We can transmit some more data on the stream
			int available_bytes = TX_BUFFER_SIZE-tcb->txfree[sid];
			DEBUG("Stream %d: available_bytes = %d", sid, available_bytes);
			while(available_bytes > 0){
				int payload_length = MIN(available_bytes, max_payload_length);
				for(int i=0; i<payload_length; i++){
					temp_payload_buf[i] = tcb->stream_tx_buffer[sid][tcb->tx_buffer_occupied_region_start[sid]];
					tcb->tx_buffer_occupied_region_start[sid] = (tcb->tx_buffer_occupied_region_start[sid]+1)%TX_BUFFER_SIZE;
					tcb->txfree[sid]++;
					available_bytes--;
				}
				if(!tcb->ms_option_enabled){
					prepare_tcp(s, ACK, temp_payload_buf, payload_length, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
				}else{
					int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
					uint8_t* opt = malloc(optlen);
					memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
					
					// Stream update
					opt[2] = sid<<2 | (((tcb->next_ssn[sid])>>8) & 0x03);
					opt[3] = (tcb->next_ssn[sid]) & 0xFF;
					DEBUG("Packet inserted in TX queue (sid %d ssn %d) - payload length %d", sid, tcb->next_ssn[sid], payload_length);
		
					tcb->next_ssn[sid]++;
					DEBUG("new next_ssn for stream %d: %d", sid, tcb->next_ssn[sid]);
					prepare_tcp(s, ACK, temp_payload_buf, payload_length, opt, optlen);
					free(opt);
				}
			}
		}
	}
	free(temp_payload_buf);
	DEBUG("direct_segmentation_scheduler end");
}

// Abstract scheduler stub to call one of the different scheduler implementations
void scheduler(int s){
	/*
	if(-1 == sigprocmask(SIG_BLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
	acquire_handler_lock();
	*/

	direct_segmentation_scheduler(s);

	/*
	release_handler_lock();
	if(-1 == sigprocmask(SIG_UNBLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
	*/
}





bool port_in_use(unsigned short port){
	int s;
	for (s=3; s<MAX_FD; s++){
		if(fdinfo[s].st != FDINFO_ST_FREE && fdinfo[s].st != FDINFO_ST_UNBOUND){
			if(fdinfo[s].l_port == port){
				return true;
			}
		}
	}
	return false;
}

unsigned short get_free_port(){
	unsigned short p;
	for(p = last_port; p<MAX_PORT && port_in_use(p); p++);
	if(p<MAX_PORT){
		return last_port=p;
	}
	for( p = MIN_PORT; p<last_port && port_in_use(p); p++);
	if (p<last_port){
		return last_port=p;
	}
	return 0;
}

int mybind(int s, struct sockaddr * addr, int addrlen){
	if((addr->sa_family != AF_INET)){
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
	DEBUG("mybind assigned port %d", ntohs(fdinfo[s].l_port));
	fdinfo[s].l_addr = (a->sin_addr.s_addr) ? a->sin_addr.s_addr : *(unsigned int*)myip;
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



int fsm(int s, int event, struct ip_datagram * ip, struct sockaddr_in* active_open_remote_addr){
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
				struct sockaddr_in local;
				local.sin_port=htons(0);
				local.sin_addr.s_addr = htonl(0);
				local.sin_family = AF_INET;
				if(-1 == mybind(s,(struct sockaddr *) &local, sizeof(struct sockaddr_in)))	{
					myperror("implicit binding failed\n"); 
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

			tcb->seq_offs=rand();
			tcb->ack_offs=0;
			tcb->stream_end=0xFFFFFFFF; //Max file
			tcb->mss = TCP_MSS;
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

			tcb->ssthreshold = INIT_THRESH * TCP_MSS;
			tcb->cgwin = INIT_CGWIN* TCP_MSS;
			tcb->rtt_e = 0;
			tcb->Drtt_e = 0;
			tcb->cong_st = CONGCTRL_ST_SLOW_START;

			tcb->r_port = active_open_remote_addr->sin_port;
			tcb->r_addr = active_open_remote_addr->sin_addr.s_addr;

			tcb->unack = NULL;

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
				if(tcb->out_window_scale_factor != 0){
					ERROR("TODO tcb->adwin management with out_window_scale_factor != 0");
				}
				tcb->radwin[i] = 0; // This will be initialized with the reception of the SYN+ACK
				tcb->stream_tx_buffer[i] = NULL;
				tcb->txfree[i] = 0;
				tcb->tx_buffer_occupied_region_start[i] = tcb->tx_buffer_occupied_region_end[i] = 0;
				tcb->next_ssn[i] = 0;
				tcb->next_rx_ssn[i] = 0;
				tcb->stream_fsm_timer[i] = 0;
				tcb->stream_rx_queue[i] = NULL;
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
							fdinfo[s].tcb->stream_rx_queue[stream] = NULL;
							fdinfo[s].tcb->adwin[stream] = RX_VIRTUAL_BUFFER_SIZE;
							fdinfo[s].tcb->stream_fsm_timer[stream] = tick + STREAM_OPEN_TIMEOUT;
							return 0;
						}
					}
				}

				// No such connection exists: bind to a new port and open a new connection
				struct sockaddr_in local;
				local.sin_port=htons(0);
				local.sin_addr.s_addr = htonl(0);
				local.sin_family = AF_INET;
				if(-1 == mybind(s,(struct sockaddr *) &local, sizeof(struct sockaddr_in)))	{
					myperror("implicit binding failed\n"); 
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

			tcb->seq_offs=rand();
			tcb->ack_offs=0;
			tcb->stream_end=0xFFFFFFFF;
			tcb->mss = TCP_MSS;
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

			tcb->ssthreshold = INIT_THRESH * TCP_MSS;
			tcb->cgwin = INIT_CGWIN* TCP_MSS;
			tcb->rtt_e = 0;
			tcb->Drtt_e = 0;
			tcb->cong_st = CONGCTRL_ST_SLOW_START;

			tcb->r_port = active_open_remote_addr->sin_port;
			tcb->r_addr = active_open_remote_addr->sin_addr.s_addr;

			tcb->unack = NULL;

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
				tcb->stream_rx_queue[i] = NULL;
				tcb->adwin[i] = RX_VIRTUAL_BUFFER_SIZE; // RX Buffer Size
				if(tcb->out_window_scale_factor != 0){
					ERROR("TODO tcb->adwin management with out_window_scale_factor != 0");
				}
				tcb->radwin[i] = 0; // This will be initialized with the reception of the SYN+ACK
				tcb->txfree[i] = 0;
				tcb->tx_buffer_occupied_region_start[i] = tcb->tx_buffer_occupied_region_end[i] = 0;
				tcb->next_ssn[i] = 0;
				tcb->next_rx_ssn[i] = 0;
				tcb->stream_fsm_timer[i] = 0;
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

					tcb->init_radwin = tcb->radwin[0] = htons(tcp->window);
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

					/*
					We include all the usual payload options in this ACK
					(we could avoid inserting the SACK, but it is simpler to do like this)
					*/
					prepare_tcp(s, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));

					tcb->st = TCB_ST_ESTABLISHED;
				}
			}
			break;
		case TCB_ST_LISTEN:
			if(event == FSM_EVENT_PKT_RCV){
				if(!(tcp->flags & SYN)){
					break;
				}
				DEBUG("Received SYN!");

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
				tcb->mss = MIN(mss_received, TCP_MSS);
				tcb->ts_offset = tcb->ts_recent = received_remote_timestamp;

				tcb->ms_option_enabled = ms_received && MS_ENABLED;

				tcb->ssthreshold = INIT_THRESH * TCP_MSS;
				tcb->cgwin = INIT_CGWIN* TCP_MSS;
				tcb->rtt_e = 0;
				tcb->Drtt_e = 0;
				tcb->cong_st = CONGCTRL_ST_SLOW_START;

				tcb->r_port = tcp->s_port;
				tcb->r_addr = memcmp((uint8_t*) &ip->srcaddr, myip, 4) ? ip->srcaddr : inet_addr("127.0.0.1");
				

				tcb->seq_offs=rand();
				tcb->ack_offs=htonl(tcp->seq)+1;
				tcb->cumulativeack=0;

				tcb->timeout = INIT_TIMEOUT;
				tcb->txfirst = tcb->txlast = NULL;

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
					backlog_tcb->stream_rx_queue[0] = NULL;
					backlog_tcb->adwin[0] = RX_VIRTUAL_BUFFER_SIZE;
					backlog_tcb->radwin[0] = htons(tcp->window); // TODO Window scale not handled 
					backlog_tcb->txfree[0] = TX_BUFFER_SIZE;
					backlog_tcb->tx_buffer_occupied_region_start[0] = backlog_tcb->tx_buffer_occupied_region_end[0] = 0;
					backlog_tcb->next_ssn[0] = 1; // SSN 0 already sent (SYN)
					backlog_tcb->next_rx_ssn[0] = 1; // SSN 0 already received (SYN+ACK)
					backlog_tcb->stream_fsm_timer[0] = 0;
					for(int i = 1; i<TOT_SID; i++){ // Initialize as unused all the streams after SID 0
						backlog_tcb->stream_state[i] = STREAM_STATE_UNUSED;
						backlog_tcb->stream_tx_buffer[i] = NULL;
						backlog_tcb->stream_rx_queue[i] = NULL;
						backlog_tcb->adwin[i] = RX_VIRTUAL_BUFFER_SIZE; // RX buffer size
						if(tcb->out_window_scale_factor != 0){
							ERROR("TODO tcb->adwin management with out_window_scale_factor != 0");
						}
						backlog_tcb->radwin[i] = 0; // Initialized when the stream is created, based on the remote window for that stream
						backlog_tcb->txfree[i] = 0;
						backlog_tcb->tx_buffer_occupied_region_start[i] = backlog_tcb->tx_buffer_occupied_region_end[i] = 0;
						backlog_tcb->next_ssn[i] = 0;
						backlog_tcb->next_rx_ssn[0] = 1;
						backlog_tcb->stream_fsm_timer[i] = 0;
					}
					backlog_tcb->listening_fd = s;


					// Listening TCB re-initialization (same as mylisten)
					bzero(tcb,sizeof(struct tcpctrlblk));
					tcb->st = TCB_ST_LISTEN;
					fdinfo[s].tcb->is_active_side = false;
					fdinfo[s].tcb->listening_fd = s;
				}
			}
			break;
		case TCB_ST_ESTABLISHED:
			if(event ==FSM_EVENT_PKT_RCV && (tcp->flags & SYN)){
				// The SYN+ACK has been retransmitted (ignored)
				break;
			}
			if(event == FSM_EVENT_STREAM_TIMEOUT){
				int sid = fdinfo[s].sid;
				if(fdinfo[s].tcb->next_ssn[sid] != 0){
					ERROR("FSM_EVENT_STREAM_TIMEOUT stream %d already opened", sid);
				}
				int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
				uint8_t* opt = malloc(optlen);
				memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
				
				// Stream update
				opt[2] = sid<<2;
				opt[3] = 0; // SSN=0 for the opening segment

				fdinfo[s].tcb->next_ssn[sid]++;

				uint8_t* dummy_payload = malloc(1); // value doesn't matter

				prepare_tcp(s, ACK | DMP, dummy_payload, 1, opt, optlen);

				free(dummy_payload);
				free(opt);
				break;
			}
			if(event == FSM_EVENT_PKT_RCV){
				int sid = 0;
				int ssn = 0;
				if(tcb->ms_option_enabled){
					int ms_index = search_tcp_option(tcp, OPT_KIND_MS_TCP);
					if(ms_index >= 0){
						sid = (tcp->payload[ms_index+2]>>2) & 0x1F;
						ssn = ((tcp->payload[ms_index+2]&0x3) << 8) | tcp->payload[ms_index+3];
						if(ssn == 0 && tcb->stream_state[sid] == STREAM_STATE_UNUSED){
							tcb->stream_state[sid] = STREAM_STATE_READY;

							tcb->radwin[sid] = htons(tcp->window);
							tcb->txfree[sid] = TX_BUFFER_SIZE;
							tcb->tx_buffer_occupied_region_start[sid] = tcb->tx_buffer_occupied_region_end[sid] = 0;
							if(tcb->stream_tx_buffer[sid] != NULL){
								ERROR("stream_tx_buffer != NULL before malloc");
							}
							tcb->stream_tx_buffer[sid] = malloc(TX_BUFFER_SIZE);
							tcb->stream_rx_queue[sid] = NULL;
							tcb->adwin[sid] = RX_VIRTUAL_BUFFER_SIZE;
							// tcb->next_rx_ssn[sid] not incremented because it will be incremented in myio when the packet is inserted in stream RX queue

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

							DEBUG("Ready stream %d", sid);
							DEBUG("Number of ready streams for fd %d: %d",tcb->listening_fd, fdinfo[tcb->listening_fd].ready_streams);
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

	struct sockaddr_in * remote_addr = (struct sockaddr_in*) addr; //mytcp: a

	int res = fsm(s, FSM_EVENT_APP_ACTIVE_OPEN, NULL, remote_addr); 
	if(res < 0){
		// Bind may fail, or other errors
		return res;
	}
	struct tcpctrlblk* tcb = fdinfo[s].tcb;
	if(fdinfo[s].sid == 0){
		DEBUG("waiting for ack in myconnect...");
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
	DEBUG("Before myaccept loop");
	do{
		if(fdinfo[s].ready_streams == 0){
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
			//DEBUG("%u %u", htons(fdinfo[s].tcb->r_port), htons(fdinfo[s].channel_backlog[cursor_index].r_port));
			struct tcpctrlblk* tcb = (struct tcpctrlblk*) malloc(sizeof(struct tcpctrlblk));
			memcpy(tcb, fdinfo[s].channel_backlog + cursor_index, sizeof(struct tcpctrlblk));
			bzero(fdinfo[s].channel_backlog + cursor_index, sizeof(struct tcpctrlblk));

			//DEBUG("%d",tcb->stream_state[0]);
			tcb->stream_state[0] = STREAM_STATE_OPENED;
			//DEBUG("%d",tcb->stream_state[0]);
			DEBUG("myaccept fd %d sid %d stream state %d ", s, 0, tcb->stream_state[0]);

			fdinfo[free_fd].st = FDINFO_ST_TCB_CREATED;
			fdinfo[free_fd].tcb = tcb;
			fdinfo[free_fd].sid = 0;
			fdinfo[free_fd].l_port = fdinfo[s].l_port;
			fdinfo[free_fd].l_addr = fdinfo[s].l_addr;

			// There is no entry for stream 0 in the backlog
			fdinfo[s].ready_streams--;
			fdinfo[s].ready_channels--;

			prepare_tcp(free_fd, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
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
		return free_fd;
	}while(pause());
	ERROR("myaccept something went very wrong, you should never reach after the do while"); // pause always returns -1
}

int mywrite_direct_segmentation(int s, uint8_t * buffer, int maxlen){
	DEBUG("mywrite_direct_segmentation s %d data |%s| maxlen %d", s, buffer, maxlen);
	// Direct segmentation mywrite
	if(fdinfo[s].st != FDINFO_ST_TCB_CREATED || fdinfo[s].tcb == NULL || fdinfo[s].tcb->st != TCB_ST_ESTABLISHED){
		ERROR("mywrite invalid socket %d %d", fdinfo[s].st, FDINFO_ST_TCB_CREATED);
	}
	if(fdinfo[s].st != FDINFO_ST_TCB_CREATED || fdinfo[s].tcb->st != TCB_ST_ESTABLISHED){
		myerrno = EINVAL;
		return -1;
	}
	if(maxlen < 0){
		ERROR("mywrite invalid maxlen %d");
	}
	if(maxlen == 0){
		return 0;
	}

	// do-while skipped for direct segmentation
	int start_byte_number = 0;
	while(start_byte_number < maxlen){
		// DEBUG("start_byte_number %d", start_byte_number);
		int remaining_length = maxlen - start_byte_number;
		int payload_length = MIN(remaining_length, TCP_MSS - FIXED_OPTIONS_LENGTH);
		
		if(-1 == sigprocmask(SIG_BLOCK, &global_signal_mask, NULL)){
			perror("sigprocmask"); 
			exit(EXIT_FAILURE);
		}
		acquire_handler_lock();

		if(!fdinfo[s].tcb->ms_option_enabled){
			prepare_tcp(s, ACK, buffer + start_byte_number, payload_length, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
		}else{
			int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
			uint8_t* opt = malloc(optlen);
			memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
			
			// Stream update
			opt[2] = fdinfo[s].sid<<2 | (((fdinfo[s].tcb->next_ssn[fdinfo[s].sid])>>8) & 0x03);
			opt[3] = (fdinfo[s].tcb->next_ssn[fdinfo[s].sid]) & 0xFF;
			DEBUG("Packet inserted in TX queue (sid %d ssn %d)", fdinfo[s].sid, fdinfo[s].tcb->next_ssn[fdinfo[s].sid]);

			fdinfo[s].tcb->next_ssn[fdinfo[s].sid]++;
			DEBUG("new next_ssn for stream %d: %d", fdinfo[s].sid, fdinfo[s].tcb->next_ssn[fdinfo[s].sid]);
			prepare_tcp(s, ACK, buffer + start_byte_number, payload_length, opt, optlen);
			free(opt);
		}

		release_handler_lock();
		if(-1 == sigprocmask(SIG_UNBLOCK, &global_signal_mask, NULL)){
			perror("sigprocmask"); 
			exit(EXIT_FAILURE);
		}
		start_byte_number += payload_length;
	}
	if(start_byte_number != maxlen){
		ERROR("invalid start_byte_number at end of mywrite with direct segmentation");
	}
	return start_byte_number;
}

int mywrite(int s, uint8_t * buffer, int maxlen){
	DEBUG("mywrite s %d data |%s| maxlen %d", s, buffer, maxlen);
	if(fdinfo[s].st != FDINFO_ST_TCB_CREATED || fdinfo[s].tcb == NULL || fdinfo[s].tcb->st != TCB_ST_ESTABLISHED){
		ERROR("mywrite invalid socket %d %d", fdinfo[s].st, FDINFO_ST_TCB_CREATED);
	}
	if(fdinfo[s].st != FDINFO_ST_TCB_CREATED || fdinfo[s].tcb->st != TCB_ST_ESTABLISHED){
		myerrno = EINVAL;
		return -1;
	}
	// TODO bisognerebbe aggiungere un controllo sullo stato dello stream (?)
	if(maxlen < 0){
		ERROR("mywrite invalid maxlen %d");
	}
	if(maxlen == 0){
		return 0;
	}
	int sid = fdinfo[s].sid;
	int actual_len;
	if(mywrite_mode == MYWRITE_MODE_NON_BLOCKING){
		if(fdinfo[s].tcb->txfree[sid] == 0){
			errno = EAGAIN;
			return -1;
		}
		actual_len = MIN(maxlen,fdinfo[s].tcb->txfree[sid]);
	}else{
		do{
			actual_len = MIN(maxlen,fdinfo[s].tcb->txfree[sid]);
			if ((actual_len !=0) || (fdinfo[s].tcb->st == TCB_ST_CLOSED)) break;
		}while(pause());
	}
	
	DEBUG("mywrite actual_len %d", actual_len);
	if(-1 == sigprocmask(SIG_BLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
	acquire_handler_lock();
	for(int byte_num = 0; byte_num < actual_len; byte_num++){
		fdinfo[s].tcb->stream_tx_buffer[sid][fdinfo[s].tcb->tx_buffer_occupied_region_end[sid]] = buffer[byte_num];
		fdinfo[s].tcb->tx_buffer_occupied_region_end[sid] = (fdinfo[s].tcb->tx_buffer_occupied_region_end[sid] + 1) % TX_BUFFER_SIZE;
		fdinfo[s].tcb->txfree[sid]--;
	}
	scheduler(s);
	release_handler_lock();
	if(-1 == sigprocmask(SIG_UNBLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
	return actual_len;
}

int myread(int s, unsigned char *buffer, int maxlen){
	if((fdinfo[s].st != FDINFO_ST_TCB_CREATED) || (fdinfo[s].tcb->st < TCB_ST_ESTABLISHED )){ 
		ERROR("Invalid socket myread");
		myerrno = EINVAL; 
		return -1; 
	}
	if (maxlen==0){
		return 0;
	}
	if(!fdinfo[s].tcb->ms_option_enabled){
		ERROR("ms option not enabled myread");
	}
	int sid = fdinfo[s].sid;
	if(sid == SID_UNASSIGNED){
		ERROR("sid unassigned myread");
	}
	struct tcpctrlblk* tcb = fdinfo[s].tcb;
	if(tcb->stream_state[sid] < STREAM_STATE_OPENED){
		ERROR("myread fd %d sid %d invalid stream state %d ", s, sid, tcb->stream_state[sid]);
	}
	// DEBUG("myread waiting stream %d", sid);
	while(tcb->stream_rx_queue[sid] == NULL || tcb->stream_rx_queue[sid]->dummy_payload){
		/* 
		NOTA: Questo non gestisce bene il caso in cui è presente solo un segmento nella coda, e è un segmento con LSS attivo
		e DMP=1, che può essere inviato alla fine di uno stream, e in questo caso bisognerebbe uscire da questo ciclo invece
		di andare avanti. Va corretto quando si guarda la chiusura delle connessioni
		*/
		if(tcb->stream_rx_queue[sid] != NULL){
			// condition "tcb->stream_rx_queue[sid]->dummy_payload" is true

			struct stream_rx_queue_node* dmp_node = tcb->stream_rx_queue[sid];
			tcb->stream_rx_queue[sid] = tcb->stream_rx_queue[sid]->next;
			tcb->adwin[sid] += dmp_node->payload_length;
			DEBUG("Removed DMP node from stream %d rx queue", sid);
			free(dmp_node->segment);
			free(dmp_node);
			continue;
		}
		switch(myread_mode){
			case MYREAD_MODE_BLOCKING:
				pause();
				break;
			case MYREAD_MODE_NON_BLOCKING:
				errno = EAGAIN;
				return -1;
				break;
			default:
				ERROR("myread invalid myread_mode %d", myread_mode);
		}
	}
	// At this point there is something to consume
	int read_consumed_bytes = 0;
	while(tcb->stream_rx_queue[sid] != NULL && read_consumed_bytes < maxlen){
		bool lss = false; // TODO
		if(lss && read_consumed_bytes != 0  && (tcb->stream_rx_queue[sid]->dummy_payload || (tcb->stream_rx_queue[sid]->consumed_bytes == tcb->stream_rx_queue[sid]->payload_length))){
			// Do not consume this segment at this time: it will be consumed at the next call of myread, that will return 0
			break;
		}
		if(tcb->stream_rx_queue[sid]->dummy_payload){
			struct stream_rx_queue_node* dmp_node = tcb->stream_rx_queue[sid];
			tcb->stream_rx_queue[sid] = tcb->stream_rx_queue[sid]->next;
			tcb->adwin[sid] += dmp_node->payload_length;
			DEBUG("Removed DMP node from stream %d rx queue", sid);
			// free dmp_node and its segment
			free(dmp_node->segment);
			free(dmp_node);

			continue;
		}
		int missing_read_bytes = maxlen - read_consumed_bytes;
		int remaining_segment_bytes = tcb->stream_rx_queue[sid]->payload_length - tcb->stream_rx_queue[sid]->consumed_bytes;

		int current_segment_read_bytes = MIN(missing_read_bytes, remaining_segment_bytes);
		memcpy(buffer + read_consumed_bytes, tcb->stream_rx_queue[sid]->segment->payload + ((tcb->stream_rx_queue[sid]->segment->d_offs_res>>4)*4-20), current_segment_read_bytes);

		read_consumed_bytes += current_segment_read_bytes;
		tcb->adwin[sid] += current_segment_read_bytes;
		tcb->stream_rx_queue[sid]->consumed_bytes += current_segment_read_bytes;
		if(!lss && tcb->stream_rx_queue[sid]->consumed_bytes == tcb->stream_rx_queue[sid]->payload_length){
			// Segment fully consumed: remove it from the stream rx queue
			struct stream_rx_queue_node* dmp_node = tcb->stream_rx_queue[sid];
			tcb->stream_rx_queue[sid] = tcb->stream_rx_queue[sid]->next;

			// free dmp_node and its segment
			free(dmp_node->segment);
			free(dmp_node);
		}
	}
	return read_consumed_bytes;
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
	uint32_t rtt = tick - ntohl(*(uint32_t*) (tcp->payload+ts_index+6));
	//DEBUG("before rtt_estimate\trtt_e=%d Drtt_e=%d timeout=%d", tcb->rtt_e, tcb->Drtt_e, tcb->timeout);
	if(tcb->rtt_e == 0) {
		tcb->rtt_e = rtt; 
		tcb->Drtt_e = rtt/2; 
	}
	else{
		tcb->Drtt_e = ((8-BETA)*tcb->Drtt_e + BETA*abs(rtt-tcb->rtt_e))>>3;
		tcb->rtt_e = ((8-ALPHA)*tcb->rtt_e + ALPHA*rtt)>>3;
	}
	tcb->timeout = MIN(MAX(tcb->rtt_e + KRTO*tcb->Drtt_e,300*1000/TIMER_USECS), MAXTIMEOUT);
	//DEBUG("after rtt_estimate\trtt_e=%d Drtt_e=%d timeout=%d", tcb->rtt_e, tcb->Drtt_e, tcb->timeout);
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
	if(-1 == sigprocmask(SIG_BLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
	acquire_handler_lock();
	//DEBUG("io");

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
		//DEBUG("ntr");
		release_handler_lock();
		if(-1 == sigprocmask(SIG_UNBLOCK, &global_signal_mask, NULL)){
			perror("sigprocmask"); 
			exit(EXIT_FAILURE);
		}
		// DEBUG("nntr");
		return;
	}

	int received_packet_size; // mytcp: size
	while((received_packet_size = recvfrom(unique_raw_socket_fd,l2_rx_buf,L2_RX_BUF_SIZE,0,NULL,NULL))>=0){
		if(received_packet_size < sizeof(struct ethernet_frame)){
			continue;
		}
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
				if((fdinfo[i].st == FDINFO_ST_TCB_CREATED) && (fdinfo[i].l_port == tcp->d_port) && (tcp->s_port == fdinfo[i].tcb->r_port) && (ip->srcaddr == fdinfo[i].tcb->r_addr)){
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
					if( (fdinfo[i].st == FDINFO_ST_TCB_CREATED) &&(fdinfo[i].tcb->st == TCB_ST_LISTEN) && (tcp->d_port == fdinfo[i].l_port) ){
						break;
					}
				}
			}
			if(i == MAX_FD){
				// The packet is not for me
				continue; // go to the processing of the next received packet, if any
			}
			DEBUG("Incoming myio tcp packet:");
			print_l2_packet(l2_rx_buf);

			//DEBUG("Incoming TCP segment:");
			//print_tcp_segment(tcp);

			struct tcpctrlblk * tcb = fdinfo[i].tcb;

			fsm(i, FSM_EVENT_PKT_RCV, ip, NULL);

			if(tcb->st < TCB_ST_ESTABLISHED){
				continue;
			}

			if(tcp->flags & ACK){
				/* 
				At this point I know that the connection is established, Timestamps is always supported, and I can modify my RTT estimate using the received segment.
				For the Active Open side, this estimate includes also the RTT for the first SYN / SYN+ACK exchange
				*/
				// TODO spostare la chiamata, o farla solo in determinate condizioni https://www.rfc-editor.org/rfc/rfc7323#section-4
				rtt_estimate(tcb, tcp);
			}

			if(tcp->flags & SYN){
				// SYN or SYN+ACK packets don't need to remove anything from the queue and don't generate any ack after the FSM (everything is done in there)
				continue;
			}

			if(tcb->txfirst !=NULL){
				// Removal from TX queue for the cumulative ACK

				int shifter = htonl(tcb->txfirst->segment->seq);

				if((htonl(tcp->ack)-shifter >= 0) && (htonl(tcp->ack)-shifter-(tcb->stream_end)?1:0 <= htonl(tcb->txlast->segment->seq) + tcb->txlast->payloadlen - shifter)){ // -1 is to compensate the FIN	
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

						fdinfo[i].tcb->flightsize-=temp->payloadlen;

						free(temp->segment);
						free(temp);
						if(tcb->txfirst	== NULL) tcb->txlast = NULL;
					}//While
				}
			}

			if(tcb->txfirst != NULL){
				// Removal from TX queue for SACK option

				int shifter = tcb->txfirst->seq;

				int sack_opt_index = search_tcp_option(tcp, OPT_KIND_SACK);
				if(sack_opt_index > 0){
					int sack_entries_count = (tcp->payload[sack_opt_index+1] - 2) / 8;
					for(int entry = 0; entry < sack_entries_count; entry++){
						int block_left_edge_seq = ntohl(*(uint32_t*) tcp->payload + sack_opt_index + 2 + entry*8);
						int block_right_edge_seq = ntohl(*(uint32_t*) tcp->payload + sack_opt_index + 2 + entry*8 + 4);

						struct txcontrolbuf *cursor = tcb->txfirst, *prev = NULL;
						while(cursor != NULL){
							int cursor_shifted_seq = cursor->seq - shifter;
							int left_shifted_seq = block_left_edge_seq - shifter;
							int right_shifted_seq = block_right_edge_seq - shifter;

							if(left_shifted_seq < cursor_shifted_seq && cursor_shifted_seq < right_shifted_seq){
								// Remove the node from the tx queue
								if(prev == NULL){
									free(cursor->segment);
									free(cursor);
									tcb->txfirst = tcb->txlast = NULL;
									break;
								}else{
									prev->next = cursor->next;
									free(cursor->segment);
									free(cursor);
									cursor = prev;
								}
							}
							prev = cursor;
							cursor = cursor->next;
						}
					}
				}
			}

			int payload_length = htons(ip->totlen) - (ip->ver_ihl&0xF)*4 - (tcp->d_offs_res>>4)*4;
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

				uint32_t channel_offset = ntohl(tcp->seq)-tcb->ack_offs; // Position of this segment in the channel stream, without the initial random offset
				DEBUG("channel_offset = %u (ntohl(seq) = %u ; ack_offs = %u)", channel_offset,  ntohl(tcp->seq), tcb->ack_offs);
				if(channel_offset >= tcb->cumulativeack){
					// This segment is not a duplicate of something already cumulative-acked

					//DEBUG("TODO currently not checking if the segment is within the max RX window size");

					struct channel_rx_queue_node* newrx = NULL;
					if(tcb->unack == NULL){
						// The RX queue is empty and this packet is not a duplicate of an already ACKed one: this packet becomes the only one in the RX queue
						DEBUG("Insertion in at the beginning of empty unack queue");
						tcb->unack = newrx = create_channel_rx_queue_node(channel_offset, ip, tcp, NULL);
					}else{
						// There is already at least one packet in the RX queue: traverse the queue until you get to the end or you find a node with higher channel offset
						struct channel_rx_queue_node *prev = NULL, *cursor = tcb->unack;
						while(cursor != NULL && cursor->channel_offset < channel_offset){
							prev = cursor;
							cursor = cursor->next;
						}
						if(cursor == NULL){
							// We traversed the whole queue without finding any segment with a higher channel offset: insert the new one at the end of the queue
							DEBUG("Insertion at the end of the queue");
							newrx = create_channel_rx_queue_node(channel_offset, ip, tcp, NULL);
							prev->next = newrx;

							// If we insert a segment at the end of its stream RX queue, we use it to update radwin
							tcb->radwin[sid] = htons(tcp->window);
						}else{
							// Now cursor is either NULL or has a channel_offset <= to that of the RXed segment
							if(cursor->channel_offset != channel_offset){
								// using "cursor" as next handles correctly both the cases for end of the queue and for middle of the queue
								newrx = create_channel_rx_queue_node(channel_offset, ip, tcp, cursor);
								if(prev == NULL){
									// Insertion at the beginning of the queue
									DEBUG("Insertion at the beginning of the queue");
									tcb->unack = newrx;
								}else{
									// Insertion in the middle (or at the end) of the queue
									DEBUG("Insertion in the middle (or at the end) of the queue");
									prev->next = newrx;
								}
							}else{
								// Duplicate of an out-of-order packet (ignored)
							}
						}
					}
					DEBUG("newrx added to rx queue");
					print_rx_queue(tcb);
					// if newrx == NULL the packet was a duplicate of an out-of-order packet
					if(newrx != NULL){
						// new node has been inserted in the channel queue
						if(!tcb->ms_option_enabled){
							ERROR("TODO insert in RX stream buffer non-MS");
						}
						if((tcb->ms_option_requested || tcb->ms_option_enabled) && sid == 0 && ssn == 0){
							// I don't really know how this might happen, but this for sure shouldn't happen so a check shouldn't hurt
							// Note that the situation sid==0&&ssn==0 might happen if ms is not enabled or if the packet is only an ACK without payload
							print_l2_packet(l2_rx_buf);
							ERROR("Unexpected sid 0 ssn 0 when inserting in the stream RX queue");
						}
						struct channel_rx_queue_node* cursor = newrx;
						DEBUG("tcb->next_rx_ssn[sid %d] %d == ssn %d", sid, tcb->next_rx_ssn[sid], ssn);
						int current_candidate_ssn = ssn; // Do avoid "polluting" the variable "ssn" used for newrx
						while(cursor != NULL && tcb->next_rx_ssn[sid] == current_candidate_ssn){
							// cursor contains an in-order segment for the stream
							
							// This unlinks the segments in cursor and links it to the new stream queue node
							struct stream_rx_queue_node* newrx_stream = create_stream_rx_queue_node(cursor);
							DEBUG("Moving segment SID %d SSN %d from channel queue to stream queue", newrx_stream->sid, newrx_stream->ssn);

							if(tcb->stream_rx_queue[sid] == NULL){
								tcb->stream_rx_queue[sid] = newrx_stream;
							}else{
								// Traverse the stream RX queue until you get to the end
								// This could be done much faster by keeping a pointer to the last element, but doing it in this way I am more confident in not doing errors, this can be improved later
								struct stream_rx_queue_node* last = tcb->stream_rx_queue[sid];
								while(last->next != NULL){
									last = last->next;
								}
								last->next = newrx_stream;
							}

							tcb->next_rx_ssn[sid]++;
							// advance to the next segment of this stream in the channel RX queue
							cursor = cursor->next;
							while(cursor != NULL){
								if(cursor->segment != NULL){
									int cursor_ms_index = search_tcp_option(cursor->segment, OPT_KIND_MS_TCP);
									if(cursor_ms_index>=0){
										int cursor_sid = (cursor->segment->payload[cursor_ms_index+2]>>2) & 0x1F;
										int cursor_ssn = ((cursor->segment->payload[cursor_ms_index+2]&0x3) << 8) | cursor->segment->payload[cursor_ms_index+3];
										if(cursor_sid == sid){
											DEBUG("Next found for channel -> stream transfer");
											current_candidate_ssn = cursor_ssn;
											break;
										}else{
											DEBUG("Skipped SID %d SSN %d for channel -> stream transfer", cursor_sid, cursor_ssn);
										}
									}
								}else{
									DEBUG("Skipped empty node for channel -> stream transfer");
								}
								cursor = cursor->next;
							}
							// Now cursor is the next node in the channel RX queue referring to this stream, or NULL if there are no more segments for this stream
						}

						// Removal of in-order segments at the beginning of the channel RX queue
						DEBUG("Initial channel RX queue:");
						print_rx_queue(tcb);
						while((tcb->unack != NULL) && (tcb->unack->channel_offset == tcb->cumulativeack)){
							if(tcb->unack->segment != NULL){
								DEBUG("Last received packet before error:");
								print_l2_packet(l2_rx_buf);
								DEBUG("unack channel_offset: %u", tcb->unack->channel_offset);
								DEBUG("unack payload length %d", tcb->unack->payload_length);
								DEBUG("newrx channel_offset: %u", newrx->channel_offset);
								DEBUG("newrx payload length %d", newrx->payload_length);
								ERROR("in-order segment not consumed from channel queue");
							}
							tcb->cumulativeack += tcb->unack->payload_length;
							if(tcb->unack->channel_offset != channel_offset){
								// We don't advance radwin if we go past the segment that we just received
								tcb->radwin[tcb->unack->sid] -= tcb->unack->payload_length;
							}
							struct channel_rx_queue_node* next = tcb->unack->next;
							free(tcb->unack);
							tcb->unack = next;

							DEBUG("something removed from rx queue");
							DEBUG("Queue after removal:");
							print_rx_queue(tcb);
						}
					}
				}

				if(!tcb->ms_option_enabled){
					if(tcb->txfirst==NULL){
						// Generate an ACK without MS Option
						prepare_tcp(i, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
					}
				}else{
					if(ms_option_included){
						if(!dummy_payload){
							// Allocate a new SSN and send an ACK on the stream with the DMP flag
							//DEBUG("TODO fix the way ACKs are generated for MS segments");

							int optlen = sizeof(PAYLOAD_OPTIONS_TEMPLATE_MS);
							uint8_t* opt = malloc(optlen);
							memcpy(opt, PAYLOAD_OPTIONS_TEMPLATE_MS, optlen);
							
							// Stream update
							opt[2] = sid<<2 | (tcb->next_ssn[sid] >> 8)&0x3;
							opt[3] = (tcb->next_ssn[sid])&0xFF;
							DEBUG("Generating ACK sid %d ssn %d", sid, tcb->next_ssn[sid]);
							tcb->next_ssn[sid]++;
							DEBUG("new SSN for sid %d: %d", sid, tcb->next_ssn[sid]);

							uint8_t* dummy_payload = malloc(1); // value doesn't matter

							prepare_tcp(i, ACK | DMP, dummy_payload, 1, opt, optlen);
							free(dummy_payload);
							free(opt);
						}else{
							DEBUG("Generating non-MS ACK for incoming DMP segment");
							// Generic ACK
							prepare_tcp(i, ACK, NULL, 0, PAYLOAD_OPTIONS_TEMPLATE, sizeof(PAYLOAD_OPTIONS_TEMPLATE));
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
			if((segment_ts_val - tcb->ts_offset) >= (tcb->ts_recent - tcb->ts_offset) && (segment_seq - tcb->ack_offs) <= tcb->cumulativeack){
				tcb->ts_recent = segment_ts_val;
			}
		}
	}//packet reception while end
	//DEBUG("eio");
	release_handler_lock();
	if(-1 == sigprocmask(SIG_UNBLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
	//DEBUG("eeio");
}
void mytimer(int ignored){
	if(-1 == sigprocmask(SIG_BLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
	acquire_handler_lock();
	//DEBUG("t");

	tick++;
	//DEBUG("mytimer tick %"PRIu64, tick);


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
		while(txcb != NULL && acc < tcb->cgwin+tcb->lta){
			// Karn invalidation not handled
			if(txcb->retry == 0){
				// This is the first TX attempt for a segment, and at this point I know that there is enough space in the cwnd to send it, so it will be sent
				tcb->flightsize += txcb->payloadlen;
			}
			if(txcb->txtime+tcb->timeout > tick){
				acc += txcb->totlen;
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
			txcb->retry++;

			update_tcp_header(i, txcb);
			DEBUG("Segment RETX");
			send_ip((unsigned char*) txcb->segment, (unsigned char*) &(tcb->r_addr), txcb->totlen, TCP_PROTO);

			acc += txcb->totlen;
			prev = txcb;
			txcb = txcb->next;
		}
	}

	// DEBUG("et");
	release_handler_lock();
	if(-1 == sigprocmask(SIG_UNBLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
	//DEBUG("eet");
}

int main(){
	load_ifconfig();

	raw_socket_setup();

	// Signal handlers association
	// https://claude.ai/share/cead81ba-d6f2-4f36-89e2-3a2dca9515fe
	struct sigaction action_io, action_timer;
	memset(&action_io, 0, sizeof(action_io));
	memset(&action_timer, 0, sizeof(action_timer));
	action_io.sa_flags = SA_RESTART;
	action_timer.sa_flags = SA_RESTART;
	action_io.sa_handler = myio;
	action_timer.sa_handler = mytimer;
	sigaction(SIGIO, &action_io, NULL);
	sigaction(SIGALRM, &action_timer, NULL);

	// Enable the reception of signals
	if( -1 == sigemptyset(&global_signal_mask)) {perror("sigemtpyset"); return EXIT_FAILURE;}
	if( -1 == sigaddset(&global_signal_mask, SIGIO)){perror("sigaddset SIGIO"); return EXIT_FAILURE;} 
	if( -1 == sigaddset(&global_signal_mask, SIGALRM)){perror("sigaddset SIGALRM"); return EXIT_FAILURE;} 
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
	
	DEBUG("Startup OK");

	if(MAIN_MODE == CLIENT){
		int client_sockets[NUM_CLIENTS];
		// Client code to connect to a server
		int s = mysocket(AF_INET,SOCK_STREAM,0);
		if(s == -1){
			myperror("mysocket");
			exit(EXIT_FAILURE);
		}
		DEBUG("mysocket OK");
		client_sockets[0] = s;
		/*
		struct sockaddr_in loc_addr;
		loc_addr.sin_family = AF_INET;
		loc_addr.sin_port = 0; // Automatic port 
		loc_addr.sin_addr.s_addr = 0; // Automatic addr (myip)
		if( -1 == mybind(s,(struct sockaddr *) &loc_addr, sizeof(struct sockaddr_in))){
			myperror("mybind"); 
			exit(EXIT_FAILURE);
		}
		DEBUG("mybind OK");
		*/
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(19500);
		//addr.sin_addr.s_addr = *(uint32_t*)myip;
		//addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		//addr.sin_addr.s_addr = inet_addr("93.184.215.14");
		//addr.sin_addr.s_addr = inet_addr("199.231.164.68"); //faq
		addr.sin_addr.s_addr = inet_addr(SERVER_IP_STR);
		if (-1 == myconnect(s,(struct sockaddr * )&addr,sizeof(struct sockaddr_in))){
			myperror("myconnect");
			exit(EXIT_FAILURE);
		}
		DEBUG("myconnect OK");
		persistent_nanosleep(2,0);
		for(int i=1; i<NUM_CLIENTS; i++){
			int s_loop = mysocket(AF_INET,SOCK_STREAM,0);
			if(s_loop == -1){
				myperror("mysocket");
				exit(EXIT_FAILURE);
			}
			DEBUG("loop myconnect %d (fd %d)", i, s_loop);
			if (-1 == myconnect(s_loop,(struct sockaddr * )&addr,sizeof(struct sockaddr_in))){
				myperror("myconnect");
				exit(EXIT_FAILURE);
			}
			client_sockets[i] = s_loop;
		}
		for(int num_message = 0; num_message < NUM_CLIENT_MESSAGES; num_message++){
			// Write some data in all of the client sockets
			for(int i=0; i<NUM_CLIENTS; i++){
				uint8_t data[100];
				sprintf(data, "Client %d message %d;", i, num_message);
				int data_length = strlen(data);
				int res = mywrite(client_sockets[i], data, data_length);
				if(res != data_length){
					ERROR("mywrite invalid return value (for direct segmentation) %d != %d", res, data_length);
				}
			}
		}
		while(true){}
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
		int client_sockets[NUM_CLIENTS];
		for(int i=0; i<NUM_CLIENTS; i++){
			struct sockaddr_in remote_addr;
			remote_addr.sin_family=AF_INET;
			int len = sizeof(struct sockaddr_in);
			int s = myaccept(listening_socket, (struct sockaddr*) &remote_addr, &len);
			if(s<0){
				myperror("myaccept");
				exit(EXIT_FAILURE);
			}
			client_sockets[i] = s;
		}
		// persistent_nanosleep(60, 0);
		while(true){
			for(int i=0; i<NUM_CLIENTS; i++){
				int s = client_sockets[i];
				char myread_buf[100000];
				memset(myread_buf, 0, sizeof(myread_buf));
				// DEBUG("wait myread fd %d stream %d", s, fdinfo[s].sid);
				int n = myread(s, myread_buf, sizeof(myread_buf));
				if(n == -1 && errno == EAGAIN){
					continue;
				}
				DEBUG("myread return %d fd %d stream %d", n, s, fdinfo[s].sid);
				DEBUG("\n\n\nmyread result |%s|\n\n", myread_buf);
			}
		}
	}else{
		ERROR("Invalid MAIN_MODE %d", MAIN_MODE);
	}
	
}