#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include<errno.h>
#include<stdio.h>
#include<signal.h>
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


#define MAXFRAME 30000
#define TIMER_USECS 500
#define RXBUFSIZE 64000
#define MAXTIMEOUT 2000
#define MAXRTO MAXTIMEOUT


#define MIN_PORT 19000
#define MAX_PORT 19999

#define MIN(x,y) (((x) > (y) ) ? (y) : (x) )
#define MAX(x,y) (((x) < (y) ) ? (y) : (x) )
char * * g_argv; // Global Argv
int g_argc; // Global Argc
#define TXBUFSIZE    ((g_argc<3) ?100000:(atoi(g_argv[2])))  
#define INIT_TIMEOUT (((g_argc<4) ?(300*1000):(atoi(g_argv[3])*1000))/TIMER_USECS)  
#define INV_LOSS_RATE    ((g_argc<6) ?10000:(atoi(g_argv[5])))  

char * usage_string = "%s <port> [<TXBUFSIZE (default 100K)>] [<TIMEOUT msec (default 300)>] [MODE: <SRV|CLN> (default SRV)] [1/LOSSRATE <1/N> (default 10000)\n";
unsigned char  mssopt[4] = { 0x02, 0x04, 0x05, 0x90};
unsigned char mss_ms_opt[] = {0x02, 0x04, 0x05, 0x90, 253, 4, 0, 0};
struct sigaction action_io, action_timer;
sigset_t mymask;
unsigned char l2buffer[MAXFRAME];
struct sockaddr_ll;
struct pollfd fds[1];
int fdfl;
long long int tick=0; 
int unique_s;
int fl;

struct sockaddr_ll sll;

int printbuf(void * b, int size){
	int i;
	unsigned char * c = (unsigned char *) b;
	for(i=0;i<size;i++)
		printf("%.2x(%.3d) ", c[i],c[i]);
	printf("\n");
}

unsigned char myip[4] = { 88,80,187,84 };
unsigned char mymac[6] = {0xf2,0x3c,0x91,0xdb,0xc2,0x98};
unsigned char mask[4] = { 255,255,255,0 };
unsigned char gateway[4] = { 88,80,187,1 };

#define INTERFACE_NAME "eth0"

void load_ifconfig(int fd){
	// https://www.ibm.com/docs/en/aix/7.2?topic=i-ioctl-socket-control-operations#ioctl_socket_control_operations__commtrf2-gen400__title__1
	struct ifreq ifr;
	struct sockaddr_in* addr_ptr;
	strcpy(ifr.ifr_name, INTERFACE_NAME);

	// ifr.ifr_addr is of type "struct sockaddr"
	addr_ptr = (struct sockaddr_in*) &ifr.ifr_addr;

	if(ioctl(fd, SIOCGIFADDR, &ifr) == -1){
		perror("ioctl SIOCGIFADDR");
		exit(EXIT_FAILURE);
	}
	memcpy(myip, &(addr_ptr->sin_addr.s_addr), sizeof(myip));

	if(ioctl(fd, SIOCGIFNETMASK, &ifr) == -1){
		perror("ioctl SIOCGIFNETMASK");
		exit(EXIT_FAILURE);
	}
	memcpy(mask, &(addr_ptr->sin_addr.s_addr), sizeof(mask));

	if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1){
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

unsigned long int rtclock(int cmd){
static struct timeval tv,zero;
gettimeofday(&tv,NULL);
if(cmd==1) zero = tv;
return (tv.tv_sec - zero.tv_sec)*1000000 + (tv.tv_usec - zero.tv_usec);
}

struct icmp_packet{
unsigned char type;
unsigned char code;
unsigned short checksum;
unsigned short id;
unsigned short seq;
unsigned char data[20];
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

int resolve_mac(unsigned int destip, unsigned char * destmac);

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

struct ethernet_frame {
unsigned char dstmac[6];
unsigned char srcmac[6];
unsigned short int type;
unsigned char payload[10];
};
int s;

int are_equal(void *a1, void *a2, int l)
{
char *b1 = (char *)a1;
char *b2 = (char *)a2;
for(int i=0; i<l; i++) if(b1[i]!=b2[i]) return 0;
return 1;
}

unsigned short int compl1( char * b, int len)
{
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
return (total);
}

unsigned short int checksum2 ( char * b1, int len1, char* b2, int len2)
{
unsigned short prev, total;
prev = compl1(b1,len1); 
total = (prev + compl1(b2,len2));
if (total < prev ) total++;
return (0xFFFF - total);
}

unsigned short int checksum ( char * b, int len)
{
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

void forge_icmp_echo(struct icmp_packet * icmp, int payloadsize)
{
int i;
icmp->type=8;
icmp->code=0;
icmp->checksum=htons(0);
icmp->id=htons(0x1234);
icmp->seq=htons(1);
for(i=0;i<payloadsize;i++)
	 icmp->data[i]=i&0xFF;
icmp->checksum=htons(checksum((unsigned char *)icmp , 8 + payloadsize));
}

void forge_ip(struct ip_datagram * ip, int payloadsize, char proto,unsigned int target )
{
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
ip->checksum = htons(checksum((unsigned char *)ip,20)); 
}

void forge_ethernet(struct ethernet_frame * eth, unsigned char * dest, unsigned short type)
{
memcpy(eth->dstmac,dest,6);
memcpy(eth->srcmac,mymac,6);
eth->type=htons(type);
 
};


int send_ip(unsigned char * payload, unsigned char * targetip, int payloadlen, unsigned char proto)
{
static int losscounter;
int i,t,len ;
unsigned char destmac[6];
unsigned char packet[2000];
struct ethernet_frame * eth = (struct ethernet_frame *) packet;
struct ip_datagram * ip = (struct ip_datagram *) eth->payload; 

if(!(rand()%INV_LOSS_RATE) && g_argv[4][0]=='S') {printf("==========TX LOST ===============\n");return 1;}
if((losscounter++ == 25)  &&(g_argv[4][0]=='S')){printf("==========TX LOST ===============\n");return 1;}
/**** HOST ROUTING */
if( ((*(unsigned int*)targetip) & (*(unsigned int*) mask)) == ((*(unsigned int*)myip) & (*(unsigned int*) mask)))  //The
	t = resolve_mac(*(unsigned int *)targetip, destmac); // if yes
else
	t = resolve_mac(*(unsigned int *)gateway, destmac); // if not

if(t==-1) return -1;

;//printf("destmac: ");printbuf(destmac,6);

forge_ethernet(eth,destmac,0x0800);
forge_ip(ip,payloadlen,proto,*(unsigned int *)targetip); 
memcpy(ip->payload,payload,payloadlen);
/*
;//printf("\nIP: ");printbuf(ip,20);
;//printf("\nTCP: ");printbuf(ip->payload,payloadlen);
;//printf("\n");
*/
//printbuf(packet+14,20+payloadlen);
len=sizeof(sll);
bzero(&sll,len);
sll.sll_family=AF_PACKET;
sll.sll_ifindex = if_nametoindex(INTERFACE_NAME);
t=sendto(unique_s,packet,14+20+payloadlen, 0,(struct sockaddr *)&sll,len);
if (t == -1) {perror("sendto failed"); return -1;}
}
		
#define MAX_ARP 200

struct arpcacheline {
unsigned int key; //IP address
unsigned char mac[6]; //Mac address
}arpcache[MAX_ARP];


#define TCP_PROTO 6
#define MAX_FD 8 
#define TCP_MSS 1400 
// Socket states (file descriptor)
#define FREE 0 
#define TCP_UNBOUND 1
#define TCP_BOUND 2
#define TCB_CREATED 3
// TCP Finite State Machine INPUTS
#define APP_ACTIVE_OPEN 1
#define APP_PASSIVE_OPEN 2
#define PKT_RCV 3
#define APP_CLOSE 4
#define TIMEOUT 5
// TCB states (TCP)
#define TCP_CLOSED 10 // initial state
#define LISTEN 11  // represents waiting for a connection request from any remote TCP and port.

#define SYN_SENT 12 // represents waiting for a matching connection request after having sent a connection request.

#define SYN_RECEIVED 13 //  represents waiting for a confirming connection request acknowledgment after having both received and sent a connection request.

#define ESTABLISHED 14 // - represents an open connection, data received can be delivered to the user.  The normal state for the data transfer phase of the connection.
#define FIN_WAIT_1 15 // waiting for a connection termination request from the remote TCP, or an acknowledgment of the conne
#define FIN_WAIT_2 16 // waiting for a connection termination request from the remote TCP.
#define CLOSE_WAIT 17 // waiting for a connection termination request from the local user.
#define CLOSING 18  // waiting for a connection termination request acknowledgment from the remote TCP.
#define LAST_ACK 19 // waiting for an acknowledgment of the connection termination request previously sent to the remote TCP
#define TIME_WAIT 20 //waiting for enough time to pass to be sure the remote TCP received the acknowledgment of its connecti

#define FIN 0x01
#define SYN 0x02
#define RST	0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20

#define MS_ENABLED 1

#define MS_STATE_UNSUPPORTED -1
#define MS_STATE_UNKNOWN 0
#define MS_STATE_SYN_SENT 1
#define MS_STATE_ESTABLISHED 2


int myerrno;

void myperror(char *message) {;//printf("%s: %s\n",message,strerror(myerrno));
}


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
                     +--------+--------+--------+--------+
                     |           Source Address          |
                     +--------+--------+--------+--------+
                     |         Destination Address       |
                     +--------+--------+--------+--------+
                     |  zero  |  PTCL  |    TCP Length   |
                     +--------+--------+--------+--------+

*/

struct pseudoheader {
unsigned int s_addr, d_addr;
unsigned char zero;
unsigned char prot;
unsigned short len;
};

struct rxcontrol{
unsigned int stream_offs;
unsigned int streamsegmentsize; 
struct rxcontrol * next;
};

struct txcontrolbuf{
struct tcp_segment * segment;
int totlen;
int payloadlen;
long long int txtime;
struct txcontrolbuf * next;
int retry;
};

struct tcpctrlblk{
struct txcontrolbuf *txfirst, * txlast;
int st;
unsigned short r_port;
unsigned int r_addr;
unsigned short adwin;
unsigned short radwin;
unsigned char * rxbuffer; 
unsigned int rx_win_start;
struct rxcontrol * unack;
unsigned int cumulativeack;
unsigned int ack_offs, seq_offs;
long long timeout;
unsigned int sequence;
unsigned int txfree;
unsigned int mss;
unsigned int stream_end;
unsigned int fsm_timer;
/* CONG CTRL*/

#ifdef CONGCTRL
unsigned int ssthreshold;
unsigned int rtt_e;
unsigned int Drtt_e;
unsigned int cong_st;
unsigned int last_ack;
unsigned int repeated_acks;
unsigned int flightsize;
unsigned int cgwin;
unsigned int lta;
#endif

/* MS-TCP */
int ms_state;
};

struct socket_info{
struct tcpctrlblk * tcb;
int st; 
unsigned short l_port;
unsigned int l_addr;
struct tcpctrlblk * tcblist; //Backlog listen queue
int bl; //backlog length;
}fdinfo[MAX_FD];


/* Congestion Control Parameters*/
#define ALPHA 1
#define BETA 4
#define KRTO 6
#define SLOW_START 0
#define CONG_AVOID 1
#define FAST_RECOV 2
#define INIT_CGWIN 1//in MSS
#define INIT_THRESH 8 //in MSS

#ifdef CONGCTRL
void congctrl_fsm(struct tcpctrlblk * tcb, int event, struct tcp_segment * tcp,int streamsegmentsize){

if(event == PKT_RCV){
						printf(" ACK: %d last ACK: %d\n",htonl(tcp->ack)-tcb->seq_offs, htonl(tcb->last_ack)-tcb->seq_offs);
	switch( tcb->cong_st ){

	case SLOW_START : 
	// when GRO is active tcb->cgwin += (htonl(tcp->ack)-htonl(tcb->last_ack));
		tcb->cgwin += tcb->mss;
		if(tcb->cgwin > tcb->ssthreshold) {
					tcb->cong_st = CONG_AVOID;
					printf(" SLOW START->CONG AVOID\n");	
					tcb->repeated_acks = 0;
	}
	break;

	case CONG_AVOID: 
 /* 
RFC 5681 page 9: 
1.   On the first and second duplicate ACKs received at a sender, a
     TCP SHOULD send a segment of previously unsent data per [RFC3042] provided that the receiver's advertised window allows, the total
     FlightSize would remain less than or equal to cwnd plus 2*SMSS, and that new data is available for transmission.  Further, the
     TCP sender MUST NOT change cwnd to reflect these two segments [RFC3042]. 
*/

		if((((tcp->flags)&(SYN|FIN))==0) &&  streamsegmentsize==0 && (htons(tcp->window) == tcb->radwin) && (tcp->ack == tcb->last_ack)) 
		if( tcp->ack == tcb->last_ack)
				tcb->repeated_acks++;

			printf(" REPEATED ACKS = %d (flags=0x%.2x streamsgmsize=%d, tcp->win=%d radwin=%d tcp->ack=%d tcb->lastack=%d)\n",tcb->repeated_acks,tcp->flags,streamsegmentsize,htons(tcp->window), tcb->radwin,htonl(tcp->ack),htonl(tcb->last_ack));

			if((tcb->repeated_acks == 1 ) || ( tcb->repeated_acks == 2)){
				 if (tcb->flightsize<=tcb->cgwin + 2* (tcb->mss))
						tcb->lta = tcb->repeated_acks+2*tcb->mss; //RFC 3042 Limited Transmit Extra-TX-win;	
			}
/*
 2.  When the third duplicate ACK is received, a TCP MUST set ssthresh to no more than the value given in equation (4).  When [RFC3042]
     is in use, additional data sent in limited transmit MUST NOT be included in this calculation.
									ssthresh = max (FlightSize / 2, 2*SMSS)            (4)
*/
 			else if (tcb->repeated_acks == 3){
				printf(" THIRD ACK...\n");
				if(tcb->txfirst!= NULL){
					struct txcontrolbuf * txcb;
					tcb->ssthreshold = MAX(tcb->flightsize/2,2*tcb->mss); 
					tcb->cgwin = tcb->ssthreshold + 2*tcb->mss; /* The third increment is in the FAST_RECOV state*/
/*
 3.  The lost segment starting at SND.UNA MUST be retransmitted and cwnd set to ssthresh plus 3*SMSS.  This artificially "inflates"
       the congestion window by the number of segments (three) that have left the network and which the receiver has buffered. */

					unsigned int shifter = MIN(htonl(tcb->txfirst->segment->seq),htonl(tcb->txfirst->segment->ack));
					if(htonl(tcb->txfirst->segment->seq)-shifter <= (htonl(tcp->ack)-shifter))
									tcb->txfirst->txtime = 0; //immediate retransmission 
					printf(" FAST RETRANSMIT....\n");
 					tcb->cong_st=FAST_RECOV;
					printf(" CONG AVOID-> FAST_RECOVERY\n");
									}
				}
				else {// normal CONG AVOID 
							// when GRO is active tcb->cgwin += (htonl(tcb->last_ack)-htonl(tcp->ack))*(htonl(tcb->last_ack)-htonl(tcp->ack))/tcb->cgw
							 tcb->cgwin += (tcb->mss)*(tcb->mss)/tcb->cgwin;
						   if (tcb->cgwin<tcb->mss) tcb->cgwin = tcb->mss;
				}
							break;

			case FAST_RECOV:
							/*
   4.  For each additional duplicate ACK received (after the third), cwnd MUST be incremented by SMSS.  This artificially inflates the
       congestion window in order to reflect the additional segment that has left the network.
*/
				if(tcb->last_ack==tcp->ack) {
						tcb->cgwin += tcb->mss;
						printf(" Increasing congestion window to : %d\n", tcb->cgwin);
				}
          else {
/*
   6.  When the next ACK arrives that acknowledges previously unacknowledged data, a TCP MUST set cwnd to ssthresh (the value
       set in step 2).  This is termed "deflating" the window.
*/
						tcb->cgwin = tcb->ssthreshold;
						tcb->cong_st=CONG_AVOID;
						printf("FAST_RECOVERY ---> CONG_AVOID\n");
					  tcb->repeated_acks=0;
					}
					break;
        }
						tcb->last_ack = tcp->ack; //in network order
		}
	else if (event == TIMEOUT) {
						if(tcb->cong_st == CONG_AVOID) tcb->ssthreshold= MAX(tcb->flightsize/2,2*tcb->mss);
						if(tcb->cong_st == FAST_RECOV) tcb->ssthreshold=MAX(tcb->mss,tcb->ssthreshold/=2);
						if(tcb->cong_st == SLOW_START) tcb->ssthreshold=MAX(tcb->mss,tcb->ssthreshold/=2);
						tcb->cgwin = INIT_CGWIN* tcb->mss;
						tcb->timeout = MIN( MAXRTO, tcb->timeout*2);
						tcb->rtt_e = 0; /* RFC 6298 Note 2 page 6 */
						printf(" TIMEOUT: --->SLOW_START\n");
						tcb->cong_st = SLOW_START;
					}
}


void rtt_estimate(struct tcpctrlblk * tcb, struct txcontrolbuf * node ){
	if(node->retry==1){ // If not retransmitted
		int rtt = tick - node->txtime;
		printf("%.7ld: RTT:%d RTTE:%d DRTTE:%d TIMEOUT:%lld",rtclock(0),rtt*1000/TIMER_USECS,tcb->rtt_e*1000/TIMER_USECS, tcb->Drtt_e*1000/TIMER_USECS,tcb->timeout*1000/TIMER_USECS);
		if (tcb->rtt_e == 0) {
				tcb->rtt_e = rtt; 
				tcb->Drtt_e = rtt/2; 
		}
		else{
			tcb->Drtt_e = ((8-BETA)*tcb->Drtt_e + BETA*abs(rtt-tcb->rtt_e))>>3;
			tcb->rtt_e = ((8-ALPHA)*tcb->rtt_e + ALPHA*rtt)>>3;
		}
		tcb->timeout = MIN(MAX(tcb->rtt_e + KRTO*tcb->Drtt_e,300*1000/TIMER_USECS),MAXRTO);
		printf("---> RTT:%d RTTE:%d DRTTE:%d TIMEOUT:%lld\n",rtt*1000/TIMER_USECS,tcb->rtt_e*1000/TIMER_USECS, tcb->Drtt_e*1000/TIMER_USECS,tcb->timeout*1000/TIMER_USECS);
    }
}    

#endif

int prepare_tcp(int s, unsigned char flags, unsigned char * payload, int payloadlen,unsigned char * options, int optlen){
struct tcpctrlblk *t = fdinfo[s].tcb;
struct tcp_segment * tcp;
struct txcontrolbuf * txcb = (struct txcontrolbuf*) malloc(sizeof( struct txcontrolbuf));

txcb->txtime = -MAXTIMEOUT ; 
txcb->payloadlen = payloadlen;
txcb->totlen = payloadlen + 20+optlen;
txcb->retry = 0;
tcp = txcb->segment = (struct tcp_segment *) malloc(sizeof(struct tcp_segment));

tcp->s_port = fdinfo[s].l_port ;
tcp->d_port = t->r_port;
if( t->r_port == 0 )
	;//printf("Illegal Packet...\n");
tcp->seq = htonl(t->seq_offs+t->sequence);
tcp->d_offs_res=(5+optlen/4) << 4; 
tcp->flags=flags&0x3F;
tcp->urgp=0;
if(options!=NULL)
	memcpy(tcp->payload,options,optlen);
if(payload != NULL)
	memcpy(tcp->payload+(optlen/4)*4,payload,payloadlen);
txcb->next=NULL;
if(t->txfirst == NULL) { t->txlast = t->txfirst = txcb;}
else {t->txlast->next = txcb; t->txlast = t->txlast->next; }
printf("%.7ld: Packet seq inserted %d:%d\n",rtclock(0),t->sequence, t->sequence+payloadlen);
t->sequence += payloadlen; 
//DEFERRED FIELDS
//tcp->ack;
//tcp->window;
//tcp->checksum=0;
}

int resolve_mac(unsigned int destip, unsigned char * destmac) 
{
int len,n,i;
clock_t start;
unsigned char pkt[1500];
struct ethernet_frame *eth;
struct arp_packet *arp;
for(i=0;i<MAX_ARP && (arpcache[i].key!=0);i++)
		if(!memcmp(&arpcache[i].key,&destip,4)) break;
if(arpcache[i].key){ //If found return 
	memcpy(destmac,arpcache[i].mac,6); 
	return 0; }
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
//printbuf(pkt,14+sizeof(struct arp_packet));
bzero(&sll,sizeof(struct sockaddr_ll));
sll.sll_family = AF_PACKET;
sll.sll_ifindex = if_nametoindex(INTERFACE_NAME);
len = sizeof(sll);
n=sendto(unique_s,pkt,14+sizeof(struct arp_packet), 0,(struct sockaddr *)&sll,len);
fl--;
sigset_t tmpmask=mymask;
if( -1 == sigdelset(&tmpmask, SIGALRM)){perror("Sigaddset");return 1;} 
sigprocmask(SIG_UNBLOCK,&tmpmask,NULL);
start=clock();
while(pause()){ //wake up only upon signals
for(i=0;(i<MAX_ARP) && (arpcache[i].key!=0);i++)
		if(!memcmp(&arpcache[i].key,&destip,4)) break;
if(arpcache[i].key){ 
		memcpy(destmac,arpcache[i].mac,6);
		sigprocmask(SIG_BLOCK,&tmpmask,NULL);
		fl++;
		return 0;
	}
if ((clock()-start) > CLOCKS_PER_SEC/100) break;  
	}
sigprocmask(SIG_BLOCK,&tmpmask,NULL);
fl++;
//sigaddset(&mymask,SIGALRM);   
return -1 ; //Not resolved
}

void update_tcp_header(int s, struct txcontrolbuf *txctrl){
struct tcpctrlblk * tcb  = fdinfo[s].tcb;
struct pseudoheader pseudo;
pseudo.s_addr = fdinfo[s].l_addr;
pseudo.d_addr = tcb->r_addr;
pseudo.zero = 0;
pseudo.prot = 6;
pseudo.len = htons(txctrl->totlen);
txctrl->segment->checksum = htons(0); 
txctrl->segment->ack = htonl(tcb->ack_offs + tcb->cumulativeack);
txctrl->segment->window = htons(tcb->adwin);
txctrl->segment->checksum = htons(checksum2((unsigned char*)&pseudo, 12, (unsigned char*) txctrl->segment, txctrl->totlen));  
}


int mysocket(int family, int type, int proto)
{
int i;
if (( family == AF_INET ) && (type == SOCK_STREAM) && (proto ==0)){
	for(i=3; i<MAX_FD && fdinfo[i].st!=FREE;i++);
	if(i==MAX_FD) {myerrno = ENFILE; return -1;}  
	else {
		bzero(fdinfo+i, sizeof(struct socket_info));
		fdinfo[i].st = TCP_UNBOUND;
		myerrno = 0;
		return i;
		}
}else {myerrno = EINVAL; return -1; }
}

int last_port=MIN_PORT;
int port_in_use( unsigned short port ){
int s;
for ( s=3; s<MAX_FD; s++)
	if (fdinfo[s].st != FREE && fdinfo[s].st!=TCP_UNBOUND)
		if(fdinfo[s].l_port == port)
			return 1;
return 0;
}

unsigned short int get_free_port()
{
unsigned short p;
for ( p = last_port; p<MAX_PORT && port_in_use(p); p++);
if (p<MAX_PORT) return last_port=p;
for ( p = MIN_PORT; p<last_port && port_in_use(p); p++);
if (p<last_port) return last_port=p;
return 0;
}

int mybind(int s, struct sockaddr * addr, int addrlen){
	if((addr->sa_family == AF_INET)){
		struct sockaddr_in * a = (struct sockaddr_in*) addr;
		if ( s >= 3 && s<MAX_FD){
			if(fdinfo[s].st != TCP_UNBOUND){myerrno = EINVAL; return -1;}
			if(a->sin_port && port_in_use(a->sin_port)) {myerrno = EADDRINUSE; return -1;} 
			fdinfo[s].l_port = (a->sin_port)?a->sin_port:get_free_port();   
			if(fdinfo[s].l_port == 0 ) {myerrno = ENOMEM; return -1;}
			fdinfo[s].l_addr = (a->sin_addr.s_addr)?a->sin_addr.s_addr:*(unsigned int*)myip;
			fdinfo[s].st = TCP_BOUND;
			myerrno = 0;
			return 0;
		}
		else { myerrno = EBADF ; return -1;}
	}
	else { myerrno = EINVAL; return -1; }
}

int fsm(int s, int event, struct ip_datagram * ip)
{
struct tcpctrlblk * tcb = fdinfo[s].tcb;
printf("%.7ld: FSM: Socket: %d Curr-State =%d, Input=%d \n",rtclock(0),s,tcb->st,event);	
struct tcp_segment * tcp;
int i;
if(ip != NULL)
 tcp = (struct tcp_segment * )((char*)ip+((ip->ver_ihl&0xF)*4));
switch(tcb->st){
	case TCP_CLOSED:
		if(event == APP_ACTIVE_OPEN) {
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

			#ifdef CONGCTRL
				tcb->ssthreshold = INIT_THRESH * TCP_MSS;
				tcb->cgwin = INIT_CGWIN* TCP_MSS;
				tcb->timeout = INIT_TIMEOUT;
				tcb->rtt_e = 0;
				tcb->Drtt_e = 0;
				tcb->cong_st = SLOW_START;
			#endif

			if(MS_ENABLED){
				prepare_tcp(s,SYN,NULL,0,mss_ms_opt,sizeof(mss_ms_opt));
				tcb->ms_state = MS_STATE_SYN_SENT;
			}else{
				prepare_tcp(s,SYN,NULL,0,mssopt,sizeof(mssopt));
				tcb->ms_state = MS_STATE_UNSUPPORTED;
			}
			tcb->st = SYN_SENT;	
		}
		break;
	
	case SYN_SENT:	
		if(event == PKT_RCV){
			if((tcp->flags&SYN) && (tcp->flags&ACK) && (htonl(tcp->ack)==tcb->seq_offs + 1)){
				tcb->seq_offs ++;
				tcb->ack_offs = htonl(tcp->seq) + 1;	
				free(tcb->txfirst->segment);
				free(tcb->txfirst);
				tcb->txfirst = tcb->txlast = NULL;	
				prepare_tcp(s,ACK,NULL,0,NULL,0);	
				tcb->st = ESTABLISHED;

				// MS-TCP option ACK check
				if(tcb->ms_state == SYN_SENT){
					bool option_found = false;

					int options_length = (tcp->d_offs_res >> 4) * 4 - 20;
					for(int options_cursor = 0; options_cursor < options_length; options_cursor++){
						uint8_t optkind = tcp->payload[options_cursor];
						if(optkind == 0){
							break;
						}
						if(optkind == 1){
							continue;
						}
						uint8_t optlen = tcp->payload[options_cursor + 1];
						options_cursor += (optlen - 1); // 1 is added at the beginning of the next iteration
						if(optkind == 253){
							option_found = true;
							break;
						}
					}
					printf("TODO continuare da qui\n");
					exit(0);

					tcb->ms_state = option_found ? MS_STATE_ESTABLISHED : MS_STATE_UNSUPPORTED;
				}
			}
		}
		break;

	 case ESTABLISHED: 
			if(event ==PKT_RCV && (tcp->flags&FIN))
				tcb->st = CLOSE_WAIT;
			else if(event == APP_CLOSE ){
    			prepare_tcp(s,FIN|ACK,NULL,0,NULL,0); //we announce no more data are sent...
    			tcb->st = FIN_WAIT_1;
    			}
  break;

	
	 case  CLOSE_WAIT:
			if(event == APP_CLOSE ){
					prepare_tcp(s,FIN|ACK,NULL,0,NULL,0);
					tcb->st = LAST_ACK;
			}		
	  break;

		case LAST_ACK:
			if((event == PKT_RCV) && (tcp->flags&ACK)	){
					if(htonl(tcp->ack) == (tcb->seq_offs + tcb->sequence + 1)){
						tcb->st = TCP_CLOSED;
					 	tcb->txfirst = tcb->txlast = NULL;	
				}
			}
		break;
case LISTEN:
  if((event == PKT_RCV) && ((tcp->flags)&SYN)){
    tcb->rxbuffer=(unsigned char*)malloc(RXBUFSIZE);
    tcb->seq_offs=rand();
    tcb->txfree = TXBUFSIZE; //Dynamic buffer
    tcb->ack_offs=htonl(tcp->seq)+1;
    tcb->r_port = tcp->s_port;
    tcb->r_addr = ip->srcaddr;
		tcb->rx_win_start=0;
    tcb->cumulativeack=0;
    tcb->adwin=RXBUFSIZE;
    tcb->radwin=RXBUFSIZE;
    tcb->mss=TCP_MSS;
    tcb->timeout = INIT_TIMEOUT;

#ifdef CONGCTRL
    tcb->ssthreshold = INIT_THRESH * TCP_MSS;
    tcb->cgwin = INIT_CGWIN * TCP_MSS;
    tcb->timeout = INIT_TIMEOUT;
    tcb->rtt_e = 0;
    tcb->Drtt_e = 0;
    tcb->cong_st = SLOW_START;
#endif  
    prepare_tcp(s,SYN|ACK,NULL,0,mssopt,sizeof(mssopt));
    tcb->st = SYN_RECEIVED;
    }
    break;
case SYN_RECEIVED:
  if(((event == PKT_RCV) && ((tcp->flags)&ACK)) &&!((tcp->flags)&SYN)){
    if(htonl(tcp->ack) == tcb->seq_offs + 1){
				free(tcb->txfirst->segment);
      free(tcb->txfirst);
      tcb->seq_offs++;
      tcb->txfirst = tcb->txlast = NULL; //Remove SYN+ACK from TXbuffer
      tcb->ack_offs=htonl(tcp->seq);
      for(i=0;i<fdinfo[s].bl && fdinfo[s].tcblist[i].st!=FREE;i++);
      if (fdinfo[s].tcblist[i].st!=FREE)
            prepare_tcp(s,RST,NULL,0,NULL,0);
        else {
              fdinfo[s].tcblist[i]=*tcb;
              fdinfo[s].tcblist[i].st = ESTABLISHED;
            }
      tcb->r_port = 0; // Detach the remote binding from the listening socket
      tcb->r_addr = 0;// Detach the remote binding from the listening socket
      tcb->st = LISTEN;
      }
    }
  break;

case FIN_WAIT_1:
  if((event == PKT_RCV) && ((tcp->flags)&FIN)){
    tcb->st = CLOSING;
    // Acknoweldgment will be sent as cumulative.
    }
  else if((event == PKT_RCV)&&((tcp->flags)&ACK))
        if(htonl(tcp->ack) == tcb->seq_offs + tcb->sequence + 1)
          tcb->st = FIN_WAIT_2;
  break;

case FIN_WAIT_2:
  if((event == PKT_RCV) && ((tcp->flags)&FIN)){
		tcb->fsm_timer = tick + tcb->timeout *4;
    tcb->st = TIME_WAIT;
   	while(tcb->txfirst!=NULL){
			struct txcontrolbuf * tmp = tcb->txfirst;
			tcb->txfirst = tcb->txfirst->next;
			free(tmp);
				}
}
  break;


case CLOSING:
  if((event == PKT_RCV)&&((tcp->flags)&ACK)) //Receiving FIN's ACK+1
        if(htonl(tcp->ack) == tcb->seq_offs + tcb->sequence + 1){
					tcb->fsm_timer = tick + tcb->timeout *4;
          tcb->st = TIME_WAIT;
					while(tcb->txfirst!=NULL){
						struct txcontrolbuf * tmp = tcb->txfirst;
						tcb->txfirst = tcb->txfirst->next;
						free(tmp);
					  }
				}
				
  break;


case TIME_WAIT: 
		if(event == TIMEOUT){
							while(tcb->unack!=NULL){
					struct rxcontrol * tmp = tcb->unack;
					tcb->unack = tcb->unack->next;
					free(tmp);
				}
				free(tcb->rxbuffer);
				free(fdinfo[s].tcb);
				bzero(fdinfo+s,sizeof(struct socket_info));

				fdinfo[s].st=FREE;
			}	
break;



	}
printf("%.7ld: FSM: Socket: %d Next:State =%d, Input=%d \n",rtclock(0),s,tcb->st,event);	
}

int myconnect(int s, struct sockaddr * addr, int addrlen){
if((addr->sa_family == AF_INET)){
	struct sockaddr_in * a = (struct sockaddr_in*) addr;
	struct sockaddr_in local;
	if ( s >= 3 && s<MAX_FD){
		if(fdinfo[s].st == TCP_UNBOUND){
				local.sin_port=htons(0);
				local.sin_addr.s_addr = htonl(0);
				local.sin_family = AF_INET;
				if(-1 == mybind(s,(struct sockaddr *) &local, sizeof(struct sockaddr_in)))	{myperror("implicit binding failed\n"); return -1; }
		}
		if(fdinfo[s].st == TCP_BOUND){
				fdinfo[s].tcb = (struct tcpctrlblk *) malloc(sizeof(struct tcpctrlblk));
				bzero(fdinfo[s].tcb, sizeof(struct tcpctrlblk));
				fdinfo[s].st = TCB_CREATED;
				fdinfo[s].tcb->st = TCP_CLOSED;
				fdinfo[s].tcb->r_port = a->sin_port;
				fdinfo[s].tcb->r_addr = a->sin_addr.s_addr;
				printf("%.7ld: Reset clock\n",rtclock(1));
				fsm(s,APP_ACTIVE_OPEN,NULL); 				
		} else {myerrno = EBADF; return -1; } 	
		while(sleep(10)){
				if(fdinfo[s].tcb->st == ESTABLISHED ) return 0;
				if(fdinfo[s].tcb->st == TCP_CLOSED ){ myerrno = ECONNREFUSED; return -1;} 
		}	
		myerrno=ETIMEDOUT; return -1;
	}
	else { myerrno = EBADF; return -1; }
}
else { myerrno = EINVAL; return -1; }
}

int mywrite(int s, unsigned char * buffer, int maxlen){
	int len,totlen=0,j,actual_len;
	if(fdinfo[s].st != TCB_CREATED || fdinfo[s].tcb->st != ESTABLISHED ){ myerrno = EINVAL; return -1; }
	if(maxlen == 0) return 0;

	do{
		actual_len = MIN(maxlen,fdinfo[s].tcb->txfree);
		if ((actual_len !=0) || (fdinfo[s].tcb->st == TCP_CLOSED)) break;
	}while(pause());

	for(j=0;j<actual_len; j+=fdinfo[s].tcb->mss){
		len = MIN(fdinfo[s].tcb->mss, actual_len-j);
		if(-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)){perror("sigprocmask"); return -1 ;}
		prepare_tcp(s,ACK,buffer+j,len,NULL,0);
		if(-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)){perror("sigprocmask"); return -1 ;}
		fdinfo[s].tcb->txfree -= len;
		totlen += len;
	}
	return totlen;	
} 


int myread(int s, unsigned char *buffer, int maxlen)
{
	int j,actual_len;
	if((fdinfo[s].st != TCB_CREATED) || (fdinfo[s].tcb->st < ESTABLISHED )){ myerrno = EINVAL; return -1; }
	if (maxlen==0) return 0;
	actual_len = MIN(maxlen,fdinfo[s].tcb->cumulativeack - fdinfo[s].tcb->rx_win_start);
	if(fdinfo[s].tcb->cumulativeack > fdinfo[s].tcb->stream_end) actual_len --;
	if(actual_len==0){
		while(pause()){
			actual_len = MIN(maxlen,fdinfo[s].tcb->cumulativeack - fdinfo[s].tcb->rx_win_start);
			if(actual_len>0 && (fdinfo[s].tcb->cumulativeack > fdinfo[s].tcb->stream_end)) actual_len --;
			if(actual_len!=0) break;		
			if(fdinfo[s].tcb->rx_win_start) 
				if(fdinfo[s].tcb->rx_win_start==fdinfo[s].tcb->stream_end) {return 0;}
			if ((fdinfo[s].tcb->st == CLOSE_WAIT) && (fdinfo[s].tcb->unack == NULL ) ) {return 0;} // FIN received and acknowledged
		}
	}
	for(j=0; j<actual_len; j++){
		buffer[j]=fdinfo[s].tcb->rxbuffer[(fdinfo[s].tcb->rx_win_start + j)%RXBUFSIZE];
	}
	fdinfo[s].tcb->rx_win_start+=j;
	return j;
}

int myclose(int s){
if((fdinfo[s].st == TCP_CLOSED) || (fdinfo[s].st == TCP_UNBOUND)) { myerrno = EBADF; return -1;}
fsm(s,APP_CLOSE,NULL);
return 0;
}

void mytimer(int number){
int i,tot,isfasttransmit, karn_invalidate=0;
struct txcontrolbuf * txcb;
if(-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)){perror("sigprocmask"); return ;}
fl++;
tick++;

//if(tick%(50000/TIMER_USECS)){ printf("%.7ld: tick=%lld\n",rtclock(0),tick);}
//if(tick%(1000000/TIMER_USECS)){ //;//printf("Mytimer Called\n"); }
if (fl > 1) printf("Overlap Timer\n");
for(i=0;i<MAX_FD;i++){
	if(fdinfo[i].st == TCB_CREATED){
		struct tcpctrlblk * tcb = fdinfo[i].tcb;
		if((tcb->fsm_timer!=0 ) && (tcb->fsm_timer < tick)){
			fsm(i,TIMEOUT,NULL);	
			continue;
			}
	
#ifdef CONGCTRL
		//for(tot=0,txcb=tcb->txfirst;  txcb!=NULL && (tot<MIN(tcb->cgwin+tcb->lta,tcb->radwin)); tot+=txcb->totlen, txcb = txcb->next){
		for(tot=0,txcb=tcb->txfirst;  txcb!=NULL && (tot<(tcb->cgwin+tcb->lta)); tot+=txcb->totlen, txcb = txcb->next){
			if(txcb->retry==0) //first transmission
				fdinfo[i].tcb->flightsize+=txcb->payloadlen;
			else 
#else
		for(tot=0,txcb=tcb->txfirst;  txcb!=NULL  /*&& (tot<tcb->radwin)*/;  txcb = txcb->next){
#endif
			if (karn_invalidate) txcb->retry++; //a previous segment has been retransmitted, so this one cannot be used for RTO
		  if(txcb->txtime+tcb->timeout > tick )  continue; //No timeout
			isfasttransmit = (txcb->txtime == 0); //FAST TRANSMIT for duplicate acks 
			txcb->txtime=tick;
			if(!karn_invalidate) txcb->retry ++; //increment only if not already incremented by invalidation 
			karn_invalidate = (txcb->retry > 1 ); // if it is a retransmission the next segments cannot be used for RTO
			update_tcp_header(i, txcb);
			send_ip((unsigned char*) txcb->segment, (unsigned char*) &fdinfo[i].tcb->r_addr, txcb->totlen, TCP_PROTO);
			printf("%.7ld: TX SOCK: %d SEQ:%d:%d ACK:%d Timeout = %lld FLAGS:0x%.2X (%d times)\n",rtclock(0),i,htonl(txcb->segment->seq) - fdinfo[i].tcb->seq_offs,htonl(txcb->segment->seq) - fdinfo[i].tcb->seq_offs+txcb->payloadlen,htonl(txcb->segment->ack) - fdinfo[i].tcb->ack_offs,tcb->timeout*TIMER_USECS/1000,txcb->segment->flags,txcb->retry);
#ifdef CONGCTRL
			if((txcb->retry > 1) &&(tcb->st >= ESTABLISHED) && !isfasttransmit)
				congctrl_fsm(tcb,TIMEOUT,NULL,0);
			printf(" Thresh: %d TxWin/MSS: %f, ST: %d RTT_E:%d\n",tcb->ssthreshold, tcb->cgwin/(float)tcb->mss,tcb->cong_st,tcb->rtt_e);
#endif
			}
	}
}
	fl--;
	if(-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)){perror("sigprocmask"); return ;}
}

void printrxq(struct rxcontrol* n){
printf(" RXQ: ");
for( ; n!=NULL; n = n->next)
	printf("(%d %d) ",n->stream_offs, n->streamsegmentsize);
printf("\n");
}


void myio(int number)
{
int i,len,size,shifter;
//;//printf("Myio Called\n");
struct ethernet_frame * eth=(struct ethernet_frame *)l2buffer;

if(-1 == sigprocmask(SIG_BLOCK, &mymask, NULL)){perror("sigprocmask"); return ;}
fl++;
if (fl > 1) ;//printf("Overlap (%d) in myio\n",fl);
if( poll(fds,1,0) == -1) { perror("Poll failed"); return; }
if (fds[0].revents & POLLIN){
	len = sizeof(struct sockaddr_ll);
	while ( 0 <= (size = recvfrom(unique_s,eth,MAXFRAME,0, (struct sockaddr *) &sll,&len))){
		if(size >1000) ;//printf("Packet %d-bytes received\n",size);  		
		if (eth->type == htons (0x0806)) {
			struct arp_packet * arp = (struct arp_packet *) eth->payload;
			if(htons(arp->op) == 2){ //It is ARP response
				for(i=0;(i<MAX_ARP) && (arpcache[i].key!=0);i++)
				if(!memcmp(&arpcache[i].key,arp->srcip,4)){
					memcpy(arpcache[i].mac,arp->srcmac,6); // Update
					break;
					}
					if(arpcache[i].key==0){
						;//printf("New ARP cache entry inserted\n");
						memcpy(arpcache[i].mac,arp->srcmac,6); //new insert
						memcpy(&arpcache[i].key,arp->srcip,4); // Update
					}
			}// It is ARP response
		} //it is ARP
		else if(eth->type == htons(0x0800)){
			struct ip_datagram * ip = (struct ip_datagram *) eth->payload;
			if (ip->proto == TCP_PROTO){
				struct tcp_segment * tcp = (struct tcp_segment *) ((char*)ip + (ip->ver_ihl&0x0F)*4);
				for(i=0;i<MAX_FD;i++)
					if((fdinfo[i].st == TCB_CREATED) && (fdinfo[i].l_port == tcp->d_port) 
							&& (tcp->s_port == fdinfo[i].tcb->r_port) && (ip->srcaddr == fdinfo[i].tcb->r_addr))
								break;
				if(i==MAX_FD)// if  not found connected TCB : second choice: listening socket
      			for(i=0;i<MAX_FD;i++) // Foreach TCB find listening sockets
        			if((fdinfo[i].st == TCB_CREATED) &&(fdinfo[i].tcb->st==LISTEN) && (tcp->d_port == fdinfo[i].l_port))
            		break;
			  if(i<MAX_FD)
						{
						struct tcpctrlblk * tcb = fdinfo[i].tcb;
						//printbuf((unsigned char*)ip,htons(ip->totlen));
						;//printf("(remote:%d) ---> (locahost:%d) socket=%d\n",htons(tcp->s_port),htons(tcp->d_port),i);

						;//printf("Received ack %d\n", htonl(tcp->ack)-tcb->seq_offs);
						printf("%.7ld: RX SOCK:%d ACK %d SEQ:%d SIZE:%d FLAGS:0x%.2X\n",rtclock(0),i,htonl(tcp->ack)-tcb->seq_offs,htonl(tcp->seq)-tcb->ack_offs,  htons(ip->totlen) - (ip->ver_ihl&0xF)*4 - (tcp->d_offs_res>>4)*4, tcp->flags);
						if(!(rand()%INV_LOSS_RATE) && g_argv[4][0]=='C') {printf("========== RX LOST ===============\n");break;}
						fsm(i,PKT_RCV,ip);
						;//printf("status = %d\n",fdinfo[i].tcb->st);
						if(tcb->st < ESTABLISHED)break; 

						unsigned int streamsegmentsize = htons(ip->totlen) - (ip->ver_ihl&0xF)*4 - (tcp->d_offs_res>>4)*4; 
						unsigned int stream_offs = ntohl(tcp->seq)-tcb->ack_offs;
						unsigned char * streamsegment = ((unsigned char*)tcp)+((tcp->d_offs_res>>4)*4);
						struct rxcontrol * curr, *newrx, *prev;

						if(tcb->txfirst !=NULL){
							shifter = htonl(tcb->txfirst->segment->seq);
							;//printf("Processing ack  %d\n", htonl(tcp->ack)-tcb->seq_offs);
							if((htonl(tcp->ack)-shifter >= 0) && (htonl(tcp->ack)-shifter-(tcb->stream_end)?1:0 <= htonl(tcb->txlast->segment->seq) + tcb->txlast->payloadlen - shifter)){ // -1 is to compensate the FIN	
								 while((tcb->txfirst!=NULL) && ((htonl(tcp->ack)-shifter) >= (htonl(tcb->txfirst->segment->seq)-shifter + tcb->txfirst->payloadlen))){ //Ack>=Seq+payloadlen
									struct txcontrolbuf * temp = tcb->txfirst;
										tcb->txfirst = tcb->txfirst->next;
										;//printf("Removing seq %d\n",htonl(temp->segment->seq)-tcb->seq_offs);
										fdinfo[i].tcb->txfree+=temp->payloadlen;
#ifdef CONGCTRL
									if(htonl(tcp->ack)-shifter ==(htonl(temp->segment->seq)-shifter + temp->payloadlen)) // Exact ACK matching: estimates
									if(temp->payloadlen!=0) // if not a piggybacked ACK of an ACK 
										 if(temp->retry<=1) // if never retransmitted or no other segment in the window has been retransmitted.  
										 	rtt_estimate(tcb,temp);
										fdinfo[i].tcb->flightsize-=temp->payloadlen;
#endif
										free(temp->segment);
										free(temp);
										if(tcb->txfirst	== NULL) tcb->txlast = NULL;
								}//While
#ifdef CONGCTRL
								 congctrl_fsm(tcb,PKT_RCV,tcp,streamsegmentsize);
#endif

	 							tcb->radwin =	htons(tcp->window);
							} 
						}
						
						if(((stream_offs + streamsegmentsize - tcb->rx_win_start)<RXBUFSIZE)){
							newrx = (struct rxcontrol *) malloc(sizeof(struct rxcontrol));
							newrx->stream_offs = stream_offs;
							newrx->streamsegmentsize = streamsegmentsize;
							if(tcp->flags&FIN) {
										printf("End of stream SEQ: %d\n",tcb->stream_end);
										tcb->stream_end=stream_offs + streamsegmentsize;
										printf("End of stream SEQ: %d\n",tcb->stream_end);
										newrx->streamsegmentsize++;
										}
							for(prev = curr = tcb->unack; curr!=NULL && curr->stream_offs<stream_offs; curr = (prev = curr)->next);		
							if((stream_offs<tcb->cumulativeack) || (curr!=NULL && curr->stream_offs==stream_offs)) 
									free(newrx);  //Duplicate or old packet: not to attach
							else {
								for(int k=0; k<streamsegmentsize;k++)
									tcb->rxbuffer[(stream_offs+k)%RXBUFSIZE] = streamsegment[k]; 

								if ( prev == curr) { //Add to the head : empty queue 
									tcb->unack = newrx;
									newrx->next = prev;
									;//printf("%d %d %d\n", (prev==NULL)?-1:prev->stream_offs, stream_offs, (curr==NULL)?-1:curr->stream_offs);
									}
								else { //Add after curr
									prev->next = newrx;
									newrx->next = curr; //No matter whether null or not.
									;//printf("%d %d %d\n", (prev==NULL)?-1:prev->stream_offs, stream_offs, (curr==NULL)?-1:curr->stream_offs);
										}
								printf(" Inserted: ");printrxq(tcb->unack);								
 
								while((tcb->unack != NULL) && (tcb->unack->stream_offs == tcb->cumulativeack)){
									struct rxcontrol * tmp;
									tmp = tcb->unack;
									tcb->cumulativeack += tcb->unack->streamsegmentsize;
									tcb->adwin = RXBUFSIZE- (tcb->cumulativeack - tcb->rx_win_start);
									tcb->unack = tcb->unack->next;	
									free(tmp);
									}
								printf(" Removed: ");printrxq(tcb->unack);								
								}	
							//printf("Preparing ACK\n");
							if(tcb->txfirst==NULL && tcb->st!=TIME_WAIT){ 
								prepare_tcp(i,ACK,NULL,0,NULL,0);
								}
						} 
				break;
				}// End of segment processing
		}//If TCP protocol
	}//IF ethernet
}//While packet
if (( errno != EAGAIN) && (errno!= EINTR )) { perror("Packet recvfrom Error\n"); }
}
fds[0].events= POLLIN|POLLOUT;
fds[0].revents=0;
if (fl > 1) ;//printf("Overlap (%d) in myio\n",fl);
	//printbuf(eth,size); 
fl--;
if(-1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)){perror("sigprocmask"); return ;}
}

int mylisten(int s, int bl){
if (fdinfo[s].st!=TCP_BOUND) {myerrno=EBADF; return -1;}
fdinfo[s].tcb = (struct tcpctrlblk *) malloc (sizeof(struct tcpctrlblk));
bzero(fdinfo[s].tcb,sizeof(struct tcpctrlblk));
fdinfo[s].st = TCB_CREATED;
fdinfo[s].tcb->st = LISTEN; /*Marking socket as passive opener*/
/*** Now we create the pending connection backlog ***********/
fdinfo[s].tcblist = (struct tcpctrlblk *) malloc (bl * sizeof(struct tcpctrlblk));
bzero(fdinfo[s].tcblist,bl* sizeof(struct tcpctrlblk));
fdinfo[s].bl = bl; //Backlog length size;
}

int myaccept(int s, struct sockaddr * addr, int * len)
{
	int i,j;
	if (addr->sa_family == AF_INET){
		struct sockaddr_in * a = (struct sockaddr_in *) addr;
		*len = sizeof(struct sockaddr_in);
		if (fdinfo[s].tcb->st!=LISTEN) {myerrno=EBADF; return -1;}
		if (fdinfo[s].tcblist == NULL) {myerrno=EBADF; return -1;}
		do{
			for(i=0;i<fdinfo[s].bl;i++){
				if(fdinfo[s].tcblist[i].st==ESTABLISHED){ //Not Fifo Queue
					for(j=3;j<MAX_FD && fdinfo[j].st!=FREE;j++); // Searching for free d
					if (j == MAX_FD) { myerrno=ENFILE; return -1;} //Not free descriptor
					else  { //Free File descriptor found
						fdinfo[j]=fdinfo[s];
						fdinfo[j].tcb=(struct tcpctrlblk *) malloc(sizeof(struct tcpctrlblk));
						memcpy(fdinfo[j].tcb,fdinfo[s].tcblist+i,sizeof(struct tcpctrlblk)); //Tcb of j is copied from this pending connection on backlog
						a->sin_port = fdinfo[j].tcb->r_port; //report on remote port
						a->sin_addr.s_addr = fdinfo[j].tcb->r_addr;//report on remote IP a
						fdinfo[j].bl=0; //twin socket has not backlog queue
						fdinfo[s].tcblist[i].st=FREE;
						printf("%.7ld: Reset clock\n",rtclock(1));
						prepare_tcp(j,ACK,NULL,0,NULL,0);
						return j; //New socket connect is returned
					}
				}//if pending connection
			}//for each fd
		} while(pause()); //Accept never ends
  	}else { myerrno=EINVAL; return -1;}
}


int main(int argc, char **argv)
{
clock_t start;
fl = 0;
struct itimerval myt;
action_io.sa_handler = myio;
action_timer.sa_handler = mytimer;
sigaction(SIGIO, &action_io, NULL);
sigaction(SIGALRM, &action_timer, NULL);
unique_s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
if (unique_s == -1 ) { perror("Socket Failed"); return 1;}
if (-1 == fcntl(unique_s, F_SETOWN, getpid())){ perror("fcntl setown"); return 1;} 
fdfl = fcntl(unique_s, F_GETFL, NULL); if(fdfl == -1) { perror("fcntl f_getfl"); return 1;}
fdfl = fcntl(unique_s, F_SETFL,fdfl|O_ASYNC|O_NONBLOCK); if(fdfl == -1) { perror("fcntl f_setfl"); return 1;}
load_ifconfig(unique_s);
fds[0].fd = unique_s;
fds[0].events= POLLIN|POLLOUT;
fds[0].revents=0;
sll.sll_family = AF_PACKET;
sll.sll_ifindex = if_nametoindex(INTERFACE_NAME);
myt.it_interval.tv_sec=0; /* Interval for periodic timer */
myt.it_interval.tv_usec=TIMER_USECS; /* Interval for periodic timer */
myt.it_value.tv_sec=0;    /* Time until next expiration */
myt.it_value.tv_usec=TIMER_USECS;    /* Time until next expiration */
if( -1 == sigemptyset(&mymask)) {perror("Sigemtpyset"); return 1;}
if( -1 == sigaddset(&mymask, SIGIO)){perror("Sigaddset");return 1;} 
if( -1 == sigaddset(&mymask, SIGALRM)){perror("Sigaddset");return 1;} 
if( -1 == sigprocmask(SIG_UNBLOCK, &mymask, NULL)){perror("sigprocmask"); return 1;}
if( -1 == setitimer(ITIMER_REAL, &myt, NULL)){perror("Setitimer"); return 1;}
if(argc == 1){ printf(usage_string,argv[0]); return 1;}
g_argv = argv;
g_argc = argc;
printf("Port: %d, TXBUFSIZE :%d , TIMEOUT: %d MODE:%s INV.LOSSRATE:%d\n", atoi(argv[1]), TXBUFSIZE, INIT_TIMEOUT*TIMER_USECS/1000,(argc>=5)?argv[4]:"SRV",INV_LOSS_RATE);
if(argc>=5 && !strcmp(argv[4],"CLN")){
/************* USER WEB CLIENT CODE *************/
int w,t;
unsigned char * httpreq = "GET /rfcs/rfc2246.html HTTP/1.1\r\nHost: www.faqs.org\r\nConnection:close\r\nUser-Agent: curl/7.47.0\r\nAccept: */*\r\n\r\n";


unsigned char httpresp[500000];
int s;
struct sockaddr_in addr, loc_addr;
s=mysocket(AF_INET,SOCK_STREAM,0);
addr.sin_family = AF_INET;
addr.sin_port =htons(80);
//addr.sin_addr.s_addr = inet_addr("23.215.60.27");
//addr.sin_addr.s_addr = inet_addr("172.217.169.4"); //google
addr.sin_addr.s_addr = inet_addr("199.231.164.68"); //faq
//addr.sin_addr.s_addr = inet_addr("88.80.187.84");
//addr.sin_addr.s_addr = inet_addr("142.250.179.227");

loc_addr.sin_family = AF_INET;
loc_addr.sin_port =((argc>=2)?htons(atoi(argv[1])):htons(0));
;//printf("Local port = %d\n",htons(loc_addr.sin_port));
loc_addr.sin_addr.s_addr = htonl(0);
if( -1 == mybind(s,(struct sockaddr *) &loc_addr, sizeof(struct sockaddr_in))){myperror("mybind"); return 1;}
if (-1 == myconnect(s,(struct sockaddr * )&addr,sizeof(struct sockaddr_in))){myperror("myconnect"); return 1;}
printf("Sending Req... %s\n", httpreq);
if ( mywrite(s,httpreq,strlen(httpreq))==1) { myperror("Mywrite Failed\n"); return -1;}
printf("a\n\n\n\n");
for (w=0; t=myread(s,httpresp+w,500000-w);w+=t)
	if(t== -1){myperror("myread"); return 1;}
printf("b\n\n\n\n");
printf("Response size = %d\n",w);
for(int u=0; u<w; u++){
		printf("%c",httpresp[u]);
		}
if (-1 == myclose(s)){myperror("myclose"); return 1;}

;//printf("I closed =================\n");
}
else

/********** USER'S WEB SERVER CODE****************/
{
struct sockaddr_in addr,remote_addr;
int i,j,k,s,t,s2,len;
int c;
FILE * fin;
char * method, *path, *ver;
char request[5000],response[10000];
if(argc>=5 && strcmp(argv[4],"SRV")){printf("Warning: unknown parameter \"%s\" -  assuming SRV...\n",argv[4]);}
s =  mysocket(AF_INET, SOCK_STREAM, 0);
if ( s == -1 ){ perror("Socket fallita"); return 1; }
addr.sin_family = AF_INET;
addr.sin_port =((argc>=2)?htons(atoi(argv[1])):htons(0));
addr.sin_addr.s_addr = 0;
if ( mybind(s,(struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {perror("bind fallita"); return 1;}
if ( mylisten(s,5) == -1 ) { myperror("Listen Fallita"); return 1; }
len = sizeof(struct sockaddr_in);
while(1){
remote_addr.sin_family=AF_INET;
s2 =  myaccept(s, (struct sockaddr *)&remote_addr,&len);
if ( s2 == -1 ) { myperror("Accept Fallita"); return 1;}
t = myread(s2,request,4999);
if ( t == -1 ) { myperror("Read fallita"); return 1;}
request[t]=0;
printf("\n=====================> %s\n",request);
method = request;
for(i=0;request[i]!=' ';i++){} request[i]=0; path = request+i+1;
for(i++;request[i]!=' ';i++); request[i]=0; ver = request+i+1;
for(i++;request[i]!='\r';i++); request[i]=0;
;//printf("method=%s path=%s ver=%s\n",method,path,ver);
if ((fin = fopen(path+1,"rt"))==NULL){
  sprintf(response,"HTTP/1.1 404 Not Found\r\n\r\n");
  mywrite(s2,response,strlen(response));
  }
else {
      sprintf(response,"HTTP/1.1 200 OK\r\n\r\n");
      mywrite(s2,response,strlen(response));
			
      while (t=fread(response,1,TCP_MSS,fin))
        for(i=0;i<t;i=i+k)
					k=mywrite(s2,response+i,t-i);
      fclose(fin);
    }
      myclose(s2);
}
 } //end while
/******************* END OF SERVER CODE**************/
           
start= tick;
while (sleep(2)){
if(((tick-start)*TIMER_USECS)>1000000) break;
	}
return 0;
}


