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
#define FDINFO_ST_TCB_CREATED 3 // mytcp: TCB_CREATED

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


struct tcpctrlblk{
	struct txcontrolbuf *txfirst, * txlast;
	int st;
	// unsigned short l_port; // replicated from fdinfo
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

	bool is_active_side;
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

struct tcb_list_node {
	struct tcpctrlblk* tcb;
	struct tcb_list_node* next;
};

struct socket_info {
	int st; 
	int cb_type; // CTRLBLK_TYPE_NONE, CTRLBLK_TYPE_TCP or CTRLBLK_TYPE_STREAM
	struct tcpctrlblk * tcb;
	unsigned short l_port;
	unsigned int l_addr;

	struct tcb_list_node backlog_head; // Backlog listen queue (TCP or Channel Control Blocks)
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

struct tcb_list_node* create_tcb_list_node(struct tcpctrlblk* tcb){
	struct tcb_list_node* to_return = malloc(sizeof(struct tcb_list_node));
	memset(to_return, 0, sizeof(struct tcb_list_node));
	to_return->tcb = tcb;
}

int tcb_list_length(struct tcb_list_node* head_ptr){
	if(head_ptr == NULL){
		ERROR("tcb_list_node_length head_ptr NULL");
	}
	int to_return = 0;
	struct tcb_list_node* cursor = head_ptr;
	while(cursor != NULL){
		cursor = cursor->next;
		to_return++;
	}
	return to_return;
}

void tcb_list_insert_at(struct tcb_list_node* head_ptr, struct tcb_list_node* new_node, int index){
	if(head_ptr == NULL || new_node == NULL){
		ERROR("tcb_list_insert_at ptr NULL");
	}
	if(new_node->next != NULL){
		// This may be intended, but it is more likely that there is a bug
		ERROR("tcb_list_insert_at new_node next != NULL");
	}
	int list_length = tcb_list_length(head_ptr);
	if(index < 0 || index >= list_length){
		ERROR("tcb_list_insert_at invalid index %d", index);
	}

	struct tcb_list_node* cursor = head_ptr;
	for(int i=0; i<index; i++){
		cursor = cursor->next;
	}
	new_node->next = cursor->next;
	cursor->next = new_node;
}

void tcb_list_append(struct tcb_list_node* head_ptr, struct tcb_list_node* new_node){
	// This could be done much more efficiently, but it is easier to find bugs, it can be optimized later
	tcb_list_insert_at(head_ptr, new_node, tcb_list_length(head_ptr));
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

void forge_ethernet(struct ethernet_frame* eth, unsigned char * dest, unsigned short type){
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







int prepare_tcp(int s, uint16_t flags /*Host order*/, uint8_t* payload, int payloadlen, uint8_t* options, int optlen){
	struct tcpctrlblk*tcb = fdinfo[s].tcb;
	struct txcontrolbuf * txcb = (struct txcontrolbuf*) malloc(sizeof( struct txcontrolbuf));
	if(fdinfo[s].l_port == 0 || tcb->r_port == 0){
		ERROR("prepare_tcp invalid port l %u s %u\n", htons(fdinfo[s].l_port), htons(tcb->r_port));
	}

	txcb->txtime = -MAXTIMEOUT ; 
	txcb->payloadlen = payloadlen;
	txcb->totlen = payloadlen + 20+FIXED_OPTIONS_LENGTH;
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
			if(tcp->flags & SYN){
				// https://www.ietf.org/rfc/rfc1323.txt pp. 15-16

				// bytes i+2, i+3, i+4 and i+5 are for the current tick value (current Timestamp)
				*(uint32_t*) (tcp->payload+2) = htonl(tick);

				// bytes i+6, i+7, i+8 and i+9 are for the most recent TS value to echo
				*(uint32_t*) (tcp->payload+6) = htonl(tcb->ts_recent);
			}
		}
		if(tcp->payload[i] == OPT_KIND_SACK){
			ERROR("TODO SACK update");
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
	tcp->window = htons(tcb->adwin);
	tcp->checksum = htons(tcp_checksum((uint8_t*) &pseudo, sizeof(pseudo), (uint8_t*) tcp, txctrl->totlen));
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
	fdinfo[s].l_port = (a->sin_port != 0) ? a->sin_port : get_free_port();   
	if(fdinfo[s].l_port == 0) {
		myerrno = EADDRINUSE; // mytcp: ENOMEM 
		return -1;
	}
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
		myerrno = 0;
		return i;
	}
}

void fsm(int s, int event, struct ip_datagram * ip){
	ERROR("TODO fsm");
};




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



	for(int i=0;i<MAX_FD;i++){
		if(fdinfo[i].st != FDINFO_ST_TCB_CREATED){
			continue;
		}
		struct tcpctrlblk* tcb = fdinfo[i].tcb;
		if((tcb->fsm_timer!=0 ) && (tcb->fsm_timer < tick)){
			fsm(i,FSM_EVENT_TIMEOUT,NULL);
			continue;
		}
		struct txcontrolbuf* txcb = tcb->txfirst;
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
			bool is_fast_transmit = (txcb->txtime == 0); // Fast retransmit (when dupACKs are received) is done by setting txtime=0
			txcb->txtime = tick;
			txcb->retry++;

			update_tcp_header(i, txcb);
			send_ip((unsigned char*) txcb->segment, (unsigned char*) &(tcb->r_addr), txcb->totlen, TCP_PROTO);

			acc += txcb->totlen;
			txcb = txcb->next;
		}
	}



	release_handler_lock();
	if(-1 == sigprocmask(SIG_UNBLOCK, &global_signal_mask, NULL)){
		perror("sigprocmask"); 
		exit(EXIT_FAILURE);
	}
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