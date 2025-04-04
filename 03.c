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

#define MS_ENABLED true

#define INTERFACE_NAME "eth0" // load_ifconfig
#define TIMER_USECS 500
#define MAX_ARP 200 // number of lines in the ARP cache
#define MAX_FD 8 // File descriptors go from 3 (included) up to this value (excluded)
#define L2_RX_BUF_SIZE 30000
#define RXBUFSIZE 64000
#define MAXTIMEOUT 2000

#define MIN_PORT 19000
#define MAX_PORT 19999

#define TCP_PROTO 6 // protocol field inside IP header

#define TCP_MSS 1460 // MTU = 1500, MSS = MTU - 20 (IP Header) - 20 (TCP Header)
#define FIXED_OPTIONS_LENGTH 40
#define MAX_SEGMENT_PAYLOAD (TCP_MSS - FIXED_OPTIONS_LENGTH) // 1420, may be used for congestion control

#define DEFAULT_WINDOW_SCALE 0 // Default parameter sent during the handshake

#define FDINFO_ST_FREE 0 // mytcp: FREE
#define FDINFO_ST_UNBOUND 1 // mytcp: TCP_UNBOUND
#define FDINFO_ST_BOUND 2 // mytcp: TCP_BOUND 
#define FDINFO_ST_GCB_CREATED 3 // mytcp: TCB_CREATED

#define CTRLBLK_TYPE_NONE 0 // used for socket_info.cb_type
#define CTRLBLK_TYPE_TCP 1
#define CTRLBLK_TYPE_STREAM 2
#define CTRLBLK_TYPE_CHANNEL 3

#define FSM_EVENT_APP_ACTIVE_OPEN 1
#define FSM_EVENT_APP_PASSIVE_OPEN 2
#define FSM_EVENT_PKT_RCV 3
#define FSM_EVENT_APP_CLOSE 4
#define FSM_EVENT_TIMEOUT 5

#define TCP_ST_CLOSED 10 // initial state
#define TCP_ST_LISTEN 11  // represents waiting for a connection request from any remote TCP and port.
#define TCP_ST_SYN_SENT 12 // represents waiting for a matching connection request after having sent a connection request.
#define TCP_ST_SYN_RECEIVED 13 // represents waiting for a confirming connection request acknowledgment after having both received and sent a connection request.
#define TCP_ST_ESTABLISHED 14 // represents an open connection, data received can be delivered to the user.  The normal state for the data transfer phase of the connection.
#define TCP_ST_FIN_WAIT_1 15 // waiting for a connection termination request from the remote TCP, or an acknowledgment of the conne
#define TCP_ST_FIN_WAIT_2 16 // waiting for a connection termination request from the remote TCP.
#define TCP_ST_CLOSE_WAIT 17 // waiting for a connection termination request from the local user.
#define TCP_ST_CLOSING 18  // waiting for a connection termination request acknowledgment from the remote TCP.
#define TCP_ST_LAST_ACK 19 // waiting for an acknowledgment of the connection termination request previously sent to the remote TCP
#define TCP_ST_TIME_WAIT 20 // waiting for enough time to pass to be sure the remote TCP received the acknowledgment of its connecti

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

struct txcontrolbuf{
	struct tcp_segment * segment;
	int totlen;
	int payloadlen;
	long long int txtime;
	struct txcontrolbuf * next;
	int retry;
};

struct arpcacheline {
	unsigned int key; //IP address
	unsigned char mac[6]; //Mac address
};

// Generic control block (TCP / Stream / Channel control block)
struct genctrlblk{
	int cb_type;
};

struct tcpctrlblk{
	int cb_type; // CTRBLK_TYPE_TCP

	struct txcontrolbuf *txfirst, * txlast;
	int st;
	bool is_active_side;
	unsigned short l_port; // replicated from fdinfo
	unsigned short r_port;
	unsigned int r_addr;
	unsigned short adwin;
	unsigned short radwin;
	unsigned char * rxbuffer;
	unsigned int rx_win_start; 
	struct rxcontrol* unack;
	unsigned int cumulativeack;
	unsigned int ack_offs, seq_offs;
	long long timeout; 
	unsigned int sequence; 
	unsigned int txfree; 
	unsigned int mss;
	unsigned int stream_end; 
	unsigned int fsm_timer; 

	bool ms_option_requested; // true if the MS option is inserted in the SYN. This information is used in the fsm for the SYN+ACK reception to know if the MS option has to be considered or not
	uint8_t out_window_scale_factor;
	uint8_t in_window_scale_factor;
	uint32_t ts_recent; // https://www.ietf.org/rfc/rfc1323.txt pp. 15-16

	/* CONG CTRL*/
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

struct gcb_list_node {
	int cb_type; // CTRLBLK_TYPE_NONE, CTRLBLK_TYPE_TCP or CTRLBLK_TYPE_CHANNEL
	struct genctrlblk* gcb;
	struct gcb_list_node* next;
};

struct socket_info {
	int st; 
	int cb_type; // CTRLBLK_TYPE_NONE, CTRLBLK_TYPE_TCP or CTRLBLK_TYPE_STREAM
	struct genctrlblk * gcb;
	unsigned short l_port;
	unsigned int l_addr;

	struct gcb_list_node backlog_head; // Backlog listen queue (TCP or Channel Control Blocks)
	int ready_streams; // Number of ready streams that can be consumed by accept(). If ready_streams == backlog_length new connections or streams have to be refused
	int backlog_length; // Maximum number of streams that can be ready before starting to reset new connections/streams (mytcp: bl)
};






/* GLOBAL VARIABLES */


unsigned char myip[4];
unsigned char mymac[6];
unsigned char mask[4];
unsigned char gateway[4];

/* TXBUFSIZE and INIT_TIMEOUT may be modified at program startup */
int TXBUFSIZE = 100000; // #define TXBUFSIZE    ((g_argc<3) ?100000:(atoi(g_argv[2])))  
int INIT_TIMEOUT = 300*1000; // #define INIT_TIMEOUT (((g_argc<4) ?(300*1000):(atoi(g_argv[3])*1000))/TIMER_USECS)

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

struct gcb_list_node chinfo_head;

/* FUNCTION DEFINITIONS */

void ERROR(char* c, ...){
	printf("ERROR: ");
	va_list args;
	va_start(args, c);
	vprintf(c, args);
	va_end(args);
	printf("\n");
	exit(EXIT_FAILURE);
}

void myperror(char* message) {
	printf("MYPERROR %s: %s\n", message, strerror(myerrno));
}

void acquire_handler_lock(){
	if(global_handler_lock != 0){
		ERROR("acquire_handler_lock global_handler_lock %d != 0", global_handler_lock);
	}
	global_handler_lock--;
}

void release_handler_lock(){
	if(global_handler_lock != 0){
		ERROR("acquire_handler_lock global_handler_lock %d != 0", global_handler_lock);
	}
	global_handler_lock++;
}

struct gcb_list_node* create_gcb_list_node(struct genctrlblk* gcb){
	struct gcb_list_node* to_return = malloc(sizeof(struct gcb_list_node));
	memset(to_return, 0, sizeof(struct gcb_list_node));
	to_return->gcb = gcb;
}

int gcb_list_length(struct gcb_list_node* head_ptr){
	if(head_ptr == NULL){
		ERROR("gcb_list_node_length head_ptr NULL");
	}
	int to_return = 0;
	struct gcb_list_node* cursor = head_ptr;
	while(cursor != NULL){
		cursor = cursor->next;
		to_return++;
	}
	return to_return;
}

void gcb_list_insert_at(struct gcb_list_node* head_ptr, struct gcb_list_node* new_node, int index){
	if(head_ptr == NULL || new_node == NULL){
		ERROR("gcb_list_node_length ptr NULL");
	}
	if(new_node->next != NULL){
		// This may be intended, but it is more likely that there is a bug
		ERROR("gcb_list_insert_at new_node next != NULL");
	}
	int list_length = gcb_list_length(head_ptr);
	if(index < 0 || index >= list_length){
		ERROR("gcb_list_insert_at invalid index %d", index);
	}

	struct gcb_list_node* cursor = head_ptr;
	for(int i=0; i<index; i++){
		cursor = cursor->next;
	}
	new_node->next = cursor->next;
	cursor->next = new_node;
}

void gcb_list_append(struct gcb_list_node* head_ptr, struct gcb_list_node* new_node){
	// This could be done much more efficiently, but it is easier to find bugs, it can be optimized later
	gcb_list_insert_at(head_ptr, new_node, gcb_list_length(head_ptr));
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
	if(-1 == unique_raw_socket_fd){
		ERROR("load_ifconfig fd -1");
	}

	// https://www.ibm.com/docs/en/aix/7.2?topic=i-ioctl-socket-control-operations#ioctl_socket_control_operations__commtrf2-gen400__title__1
	struct ifreq ifr;
	struct sockaddr_in* addr_ptr;
	strcpy(ifr.ifr_name, INTERFACE_NAME);

	// ifr.ifr_addr is of type "struct sockaddr"
	addr_ptr = (struct sockaddr_in*) &ifr.ifr_addr;

	if(ioctl(unique_raw_socket_fd, SIOCGIFADDR, &ifr) == -1){
		perror("ioctl SIOCGIFADDR");
		exit(EXIT_FAILURE);
	}
	memcpy(myip, &(addr_ptr->sin_addr.s_addr), sizeof(myip));

	if(ioctl(unique_raw_socket_fd, SIOCGIFNETMASK, &ifr) == -1){
		perror("ioctl SIOCGIFNETMASK");
		exit(EXIT_FAILURE);
	}
	memcpy(mask, &(addr_ptr->sin_addr.s_addr), sizeof(mask));

	if(ioctl(unique_raw_socket_fd, SIOCGIFHWADDR, &ifr) == -1){
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
}
#pragma endregion STARTUP_FUNCTIONS







#pragma region RAW_SOCKET_ACCESS
int resolve_mac(unsigned int destip, unsigned char * destmac) {
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
		if ((clock()-start) > CLOCKS_PER_SEC/100){
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

void forge_ethernet(struct ethernet_frame * eth, unsigned char * dest, unsigned short type){
	memcpy(eth->dstmac,dest,6);
	memcpy(eth->srcmac,mymac,6);
	eth->type=htons(type);
};

void send_ip(unsigned char * payload, unsigned char * targetip, int payloadlen, unsigned char proto){
	static int losscounter;
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
	t=sendto(unique_raw_socket_fd, packet,14+20+payloadlen, 0, (struct sockaddr *)&sll,len);
	if (t == -1) {
		perror("send_ip sendto failed"); 
		exit(EXIT_FAILURE);
	}
}
#pragma endregion RAW_SOCKET_ACCESS






void prepare_tcp(struct genctrlblk* gcb, uint16_t flags /* Host order */, unsigned char * payload, int payloadlen,unsigned char * options, int optlen){
	if(gcb == NULL){
		ERROR("prepare_tcp gcb NULL");
	}

	/* 
	To create the outgoing packet we need some fields of the Control Block:
	- l_port
	- r_port
	- seq_offs
	- sequence
	*/
	uint16_t local_port, remote_port;
	uint16_t sequence, seq_offs;
	switch(gcb->cb_type){
		case CTRLBLK_TYPE_TCP:
			struct tcpctrlblk* tcb = (struct tcpctrlblk*)gcb;
			local_port = tcb->l_port;
			remote_port = tcb->r_port;
			seq_offs = tcb->seq_offs;
			sequence = tcb->sequence;
			break;
		case CTRLBLK_TYPE_CHANNEL:
			ERROR("TODO prepare_tcp CTRLBLK_TYPE_CHANNEL");
			break;
		case CTRLBLK_TYPE_STREAM:
			ERROR("TODO prepare_tcp CTRLBLK_TYPE_STREAM");
			break;
		default:
			ERROR("prepare_tcp invalid gcb->cb_type");
	}
	if(local_port == 0 || remote_port == 0){
		ERROR("prepare_tcp invalid port l %u s %u\n", htons(local_port), htons(remote_port));
	}
	struct txcontrolbuf * new_txcb = (struct txcontrolbuf*) malloc(sizeof(struct txcontrolbuf));
	new_txcb->txtime = -MAXTIMEOUT; 
	new_txcb->payloadlen = payloadlen;
	new_txcb->totlen = payloadlen + 20 + FIXED_OPTIONS_LENGTH;
	new_txcb->retry = 0;

	struct tcp_segment * tcp = new_txcb->segment = (struct tcp_segment *) malloc(sizeof(struct tcp_segment));

	tcp->s_port = local_port;
	tcp->d_port = remote_port;

	tcp->seq = htonl(seq_offs+sequence);
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


	// Insertion of the new node in the TX queue
	new_txcb->next=NULL;
	switch(gcb->cb_type){
		case CTRLBLK_TYPE_TCP:
			struct tcpctrlblk* tcb = (struct tcpctrlblk*)gcb;
			if(tcb->txfirst == NULL) { 
				tcb->txlast = tcb->txfirst = new_txcb;
			}
			else {
				tcb->txlast->next = new_txcb; 
				tcb->txlast = tcb->txlast->next; // tcb->txlast = new_txcb;
			}
			tcb->sequence += payloadlen;
			break;
		case CTRLBLK_TYPE_CHANNEL:
			// Should be the same of normal TCP
			ERROR("TODO prepare_tcp CTRLBLK_TYPE_CHANNEL");
			break;
		case CTRLBLK_TYPE_STREAM:
			// Should insert into the corresponding channel TX queue
			ERROR("TODO prepare_tcp CTRLBLK_TYPE_STREAM");
			break;
		default:
			ERROR("prepare_tcp invalid gcb->cb_type");
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

void update_tcp_header(struct genctrlblk* gcb, struct txcontrolbuf *txctrl){
	if(gcb == NULL || txctrl == NULL){
		ERROR("update_tcp_header NULL param");
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
	uint32_t r_addr, ack_offs, cumulativeack, adwin, ts_recent;
	switch(gcb->cb_type){
		case CTRLBLK_TYPE_TCP:
			struct tcpctrlblk* tcb = (struct tcpctrlblk*) gcb;
			r_addr = tcb->r_addr;
			ack_offs = tcb->ack_offs;
			cumulativeack = tcb->cumulativeack;
			adwin = tcb->adwin;
			ts_recent = tcb->ts_recent;
			break;
		case CTRLBLK_TYPE_CHANNEL:
			ERROR("TODO update_tcp_header CTRLBLK_TYPE_CHANNEL");
			break;
		default:
			ERROR("update_tcp_header invalid gcb type");
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
			if(tcp->flags & SYN){
				// https://www.ietf.org/rfc/rfc1323.txt pp. 15-16

				// bytes i+2, i+3, i+4 and i+5 are for the current tick value (current Timestamp)
				*(uint32_t*) (tcp->payload+2) = htonl(tick);

				// bytes i+6, i+7, i+8 and i+9 are for the most recent TS value to echo
				*(uint32_t*) (tcp->payload+6) = htonl(ts_recent);
			}
		}
		if(tcp->payload[i] == OPT_KIND_SACK){
			ERROR("TODO SACK update");
		}
		int length = tcp->payload[i+1];
		i += length - 1; // with the i++ we go to the start of the next option
	}
	

	struct pseudoheader pseudo;
	pseudo.s_addr = *(uint32_t*)myip;
	pseudo.d_addr = r_addr;
	pseudo.zero = 0;
	pseudo.prot = TCP_PROTO;
	pseudo.len = htons(txctrl->totlen);

	tcp->checksum = htons(0);
	tcp->ack = htonl(ack_offs + cumulativeack);
	tcp->window = htons(adwin);
	tcp->checksum = htons(tcp_checksum((uint8_t*) &pseudo, sizeof(pseudo), (uint8_t*) tcp, txctrl->totlen));
}




/* 
The returned TCB is already linked inside fdinfo[fd].gcb. 
It is returned just to avoid having to cast the pointer from the TCB after 
this function returns, but it can be ignored safely without creating leaks.
*/
struct tcpctrlblk* create_closed_tcb(int fd){
	if(fdinfo[fd].gcb != NULL){
		ERROR("create_closed_tcb gcb != NULL");
	}
	fdinfo[fd].gcb = (struct genctrlblk *) malloc(sizeof(struct tcpctrlblk));
	bzero(fdinfo[fd].gcb, sizeof(struct tcpctrlblk));
	struct tcpctrlblk* tcb = (struct tcpctrlblk*) fdinfo[fd].gcb;
	fdinfo[fd].st = CTRLBLK_TYPE_TCP;
	tcb->cb_type = CTRLBLK_TYPE_TCP;
	tcb->st = TCP_ST_CLOSED;
}

void init_closed_tcb_default_values(struct tcpctrlblk* tcb){
	/* This function could be changed to initialize any type of
	control block, with fields that depend on the specific type */

	tcb->rxbuffer = (unsigned char*) malloc(RXBUFSIZE);
	tcb->txfree = TXBUFSIZE;
	tcb->seq_offs=rand();
	tcb->ack_offs=0;
	tcb->stream_end=0xFFFFFFFF; //Max file
	tcb->mss = TCP_MSS;
	tcb->sequence=0;
	tcb->rx_win_start=0;
	tcb->cumulativeack =0;
	tcb->timeout = INIT_TIMEOUT;
	tcb->adwin =RXBUFSIZE;
	tcb->radwin =RXBUFSIZE;
	tcb->fsm_timer = 0;
	tcb->ms_option_requested = false;
	tcb->is_active_side = false;
	tcb->out_window_scale_factor = DEFAULT_WINDOW_SCALE;
	tcb->in_window_scale_factor = 0;
	tcb->ts_recent = 0;

	//#ifdef CONGCTRL
	tcb->ssthreshold = INIT_THRESH * TCP_MSS;
	tcb->cgwin = INIT_CGWIN* TCP_MSS;
	tcb->timeout = INIT_TIMEOUT;
	tcb->rtt_e = 0;
	tcb->Drtt_e = 0;
	tcb->cong_st = CONGCTRL_ST_SLOW_START;
	//#endif
}


int fsm(struct genctrlblk* gcb, int event, struct ip_datagram * ip){
	switch(event){
		case FSM_EVENT_APP_ACTIVE_OPEN:
			if(gcb->cb_type != CTRLBLK_TYPE_TCP){
				// TODO cosa bisogna fare nella FSM per l'active open di uno stream?
				ERROR("Invalid GCB for FSM active open");
			}
			// At this point we know that we have a TCB
			struct tcpctrlblk * tcb = (struct tcpctrlblk*) gcb;
			
			if(tcb->st != TCP_ST_SYN_SENT){
				ERROR("Invalid state %d FSM active open", tcb->st);
			}
			
			init_closed_tcb_default_values(tcb);
			tcb->is_active_side = true;

			uint8_t* opt_ptr = NULL;
			int opt_len;

			if(MS_ENABLED){
				opt_len = 23;
				opt_ptr = malloc(opt_len);

				opt_ptr[0] = OPT_KIND_MSS; // MSS Kind
				opt_ptr[1] = 4; // MSS Length
				opt_ptr[2] = TCP_MSS >> 8;
				opt_ptr[3] = TCP_MSS & 0xFF;
				opt_ptr[4] = OPT_KIND_MS_TCP; // MS Kind
				opt_ptr[5] = 4; // MS Length
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

				tcb->ms_option_requested = true;
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

				tcb->ms_option_requested = false;
			}

			prepare_tcp((struct genctrlblk*) tcb, SYN, NULL,0,opt_ptr,opt_len);
			tcb->st = TCP_ST_SYN_SENT;
			if(opt_ptr != NULL){
				free(opt_ptr);
			}

			// New TCB is added to the channel linked list
			gcb_list_append(&chinfo_head, create_gcb_list_node((struct genctrlblk*) tcb));
			/*
			struct gcb_list_node* chinfo_last = &chinfo_head;
			while(chinfo_last->next == NULL){
				chinfo_last = chinfo_last->next;
			}
			chinfo_last->next = create_gcb_list_node(tcb);
			*/
			
			break;
		default:
			ERROR("fsm invalid event %d", event);
	}
}



void myio(int ignored){
	if(-1 == sigprocmask(SIG_BLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
	acquire_handler_lock();

	struct pollfd fds[1];
	fds[0].fd = unique_raw_socket_fd;
	fds[0].events = POLLIN;
	fds[0].revents=0;
	if( poll(fds,1,0) == -1) { 
		perror("Poll myio failed"); 
		exit(EXIT_FAILURE);
	}

	if(!(fds[0].revents & POLLIN)){
		// There is nothing to read
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
			ERROR("TODO myio tcp");

			// Note: When copying from mytcp, be careful of the bug that deletes the last ACK of the three-way handshake after the connection state changes
			// WP msg: "La soluzione più facile sarebbe fare il ciclo sulla tx queue solo se il pacchetto ricevuto non è un SYN"
		}
	}//packet reception while end

	release_handler_lock();
	if(-1 == sigprocmask(SIG_UNBLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
}

void mytimer(int ignored){
	if(-1 == sigprocmask(SIG_BLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
	acquire_handler_lock();

	tick++;

	struct gcb_list_node* cursor = chinfo_head.next;
	while(cursor != NULL){
		switch(cursor->cb_type){
			case CTRLBLK_TYPE_TCP:
				struct tcpctrlblk* tcb = (struct tcpctrlblk*) cursor->gcb;
				if((tcb->fsm_timer!=0 ) && (tcb->fsm_timer < tick)){
					fsm((struct genctrlblk*) tcb, FSM_EVENT_TIMEOUT, NULL);
					// TODO: da qualche parte devo togliere il nodo di questo tcb dalla linked list, ma questo va gestito bene nelle iterazioni di questo ciclo con cursor
					ERROR("TODO read the comment");
					continue;
				}

				/* For TCP, we traverse the TX queue until the congestion window is full, (re)transmitting the packets according to their transmission time */
				struct txcontrolbuf* txcb = tcb->txfirst;
				int acc = 0; // payload bytes accumulator
				while(txcb != NULL && acc < tcb->cgwin+tcb->lta){
					// Karn invalidation not handled

					if(txcb->retry == 0){
						// This is the first TX attempt for a segment, and at this point I know that there is enough space in the cwnd to send it, so it will be sent
						tcb->flightsize += txcb->payloadlen;
					}
					if(txcb->txtime+tcb->timeout > tick ){
						acc += txcb->totlen;
						txcb = txcb->next;
						continue;
					}
					bool is_fast_transmit = (txcb->txtime == 0); // Fast retransmit (when dupACKs are received) is done by setting txtime=0
					txcb->txtime = tick;
					txcb->retry++;

					update_tcp_header((struct genctrlblk*) tcb, txcb);
					send_ip((unsigned char*) txcb->segment, (unsigned char*) &(tcb->r_addr), txcb->totlen, TCP_PROTO);

					acc += txcb->totlen;
					txcb = txcb->next;
				}
				
				break;
			case CTRLBLK_TYPE_CHANNEL:
				/* In principle, for a MS channel we wouldn't need to keep track of the value of the congestion window as we traverse the TX queue, because packets
				are inserted by the scheduler only when there is enough space available for that packet. This is not true though: the congestion window may decrease
				in case of a congestion event, and in this case we need to transmit only the first unacked packets. */
				ERROR("TODO mytimer CTRLBLK_TYPE_CHANNEL");
				break;
			default:
				ERROR("mytimer unsupported cursor->cb_type %d", cursor->cb_type);
		}
	}

	release_handler_lock();
	if(-1 == sigprocmask(SIG_UNBLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
}





bool port_in_use( unsigned short port ){
	int s;
	for ( s=3; s<MAX_FD; s++)
	if (fdinfo[s].st != FDINFO_ST_FREE && fdinfo[s].st!=FDINFO_ST_UNBOUND){
		if(fdinfo[s].l_port == port){
			return true;
		}
	}
	return false;
}

unsigned short int get_free_port(){
	unsigned short p;
	for ( p = last_port; p<MAX_PORT && port_in_use(p); p++);
	if (p<MAX_PORT){
		return last_port=p;
	}
	for ( p = MIN_PORT; p<last_port && port_in_use(p); p++);
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
	if(a->sin_port != 0 && port_in_use(a->sin_port)) {
		myerrno = EADDRINUSE; 
		return -1;
	} 
	fdinfo[s].l_port = (a->sin_port != 0) ? a->sin_port : get_free_port();   
	if(fdinfo[s].l_port == 0 ) {
		myerrno = EADDRINUSE; // mytcp: ENOMEM 
		return -1;
	}
	fdinfo[s].l_addr = (a->sin_addr.s_addr)?a->sin_addr.s_addr:*(unsigned int*)myip;
	fdinfo[s].st = FDINFO_ST_UNBOUND;
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
		myerrno = 0;
		return i;
	}
}


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

		// TODO spostare da qui nella FSM
		struct tcpctrlblk* tcb = create_closed_tcb(s);
		tcb->l_port = fdinfo[s].l_port;
		tcb->r_port = remote_addr->sin_port;
		tcb->r_addr = remote_addr->sin_addr.s_addr;

		fsm((struct genctrlblk*) tcb, FSM_EVENT_APP_ACTIVE_OPEN, NULL); 
		while(sleep(10)){
			if(tcb->st == TCP_ST_ESTABLISHED ){
				return 0;
			}
			if(tcb->st == TCP_ST_CLOSED){ 
				myerrno = ECONNREFUSED; 
				return -1;
			}
		}
	}else{
		ERROR("TODO myconnect Multi-Stream");
	}
	
	// If the connection is not established within the timeout
	myerrno=ETIMEDOUT; 
	return -1;
}

int main(){
	raw_socket_setup();
	load_ifconfig();

	// Signal handlers association
	struct sigaction action_io, action_timer;
	action_io.sa_handler = myio;
	action_timer.sa_handler = mytimer;
	sigaction(SIGIO, &action_io, NULL);
	sigaction(SIGALRM, &action_timer, NULL);

	// Enable the reception of signals
	if( -1 == sigemptyset(&global_signal_mask)) {perror("sigemtpyset"); return EXIT_FAILURE;}
	if( -1 == sigaddset(&global_signal_mask, SIGIO)){perror("sigaddset SIGIO");return EXIT_FAILURE;} 
	if( -1 == sigaddset(&global_signal_mask, SIGALRM)){perror("sigaddset SIGALRM");return EXIT_FAILURE;} 
	if( -1 == sigprocmask(SIG_UNBLOCK, &global_signal_mask, NULL)){perror("sigprocmask"); return EXIT_FAILURE;}

	// Create and start the periodic timer
	struct itimerval myt;
	myt.it_interval.tv_sec=0;				/* Interval for periodic timer */
	myt.it_interval.tv_usec=TIMER_USECS;	/* Interval for periodic timer */
	myt.it_value.tv_sec=0;    				/* Time until next expiration */
	myt.it_value.tv_usec=TIMER_USECS;		/* Time until next expiration */
	if( -1 == setitimer(ITIMER_REAL, &myt, NULL)){
		perror("setitimer"); 
		return EXIT_FAILURE;
	}
	
	printf("Startup OK\n");
}