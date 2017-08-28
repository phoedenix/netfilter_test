#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>			// ip Header
#include <netinet/tcp.h>        // tcp Header
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

int search_site(const u_char* buf, int size){
    int i; 	
    printf("\n[+] Searcing....... ");
    char *ptr = strstr(buf, "test.gilgil.net");

    if(ptr == NULL)   
    	return 1;	// can't find result    
    else        
    	return 2;	// find result   
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, int *find_flag)
{
	int id = 0;
	int where = 0;
    int count = 0;
    int ret;

    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi; 
    unsigned char *data;

    printf("[+] ");
    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("No. %u, ", id);
    }

    mark = nfq_get_nfmark(tb);
    ifi = nfq_get_indev(tb);
    ifi = nfq_get_outdev(tb);
    ifi = nfq_get_physindev(tb);
    ifi = nfq_get_physoutdev(tb);
    ret = nfq_get_payload(tb, &data);

    if (ret >= 0) {
	    printf("Length: %d ", ret);

		int where = 0;
		struct ip *ipHdr = (struct ip *)(data + where);
	 	where = (ipHdr->ip_hl) * 4;
		struct tcphdr *tcpHdr = (struct tcphdr *)(data + where);
		where += (tcpHdr->th_off) * 4;		// tcp 헤더의 크기는 가변적(20-60B). Offset의 최소값은 5.

		*find_flag = search_site(data + where, ret); // Get searched result
		}
    fputc('\n', stdout);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
	int find_flag = 0;	// default value: 3
    u_int32_t id = print_pkt(nfa, &find_flag);

    printf("[+] Entering callback\n");

    if(find_flag == 2){
    	printf("*********************\n");
    	printf("*     WARNING!      *\n");
    	printf("*********************\n");
       	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
       }
    else 
    	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    /*get value*/
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("[+] Opening library handle.\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    //printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    //printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    //printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    //printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }
    fd = nfq_fd(h);
    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("[+] Packet received.\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }

        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
