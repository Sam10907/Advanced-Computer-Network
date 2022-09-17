#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <signal.h>
#define TIME_EXCEED -1
#define UNREACHABLE -2
#define TIMEOUT -3
typedef void (*sighandler_t)(int);
int awake;
int recv_icmp(int,struct sockaddr*,socklen_t*,uint16_t,uint16_t);
char* gethostip(struct sockaddr*);
void alarm_timer(int sig){
    awake = 1;
    return;
}
int main(int argc,char *argv[]){
    int send_fd = socket(AF_INET,SOCK_DGRAM,0);
    int recv_fd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    uint16_t sport = 12345;
    uint16_t desport = 33434;
    int seq = 0;
    if(send_fd < 0){
        perror("send socket error");
        exit(1);
    }
    if(recv_fd < 0){
        perror("recv socket error");
        exit(1);
    }
    struct sockaddr_in desti,source;
    socklen_t socklen = sizeof(source);
    socklen_t socklen1 = sizeof(desti);
    bzero(&desti,sizeof(desti));
    bzero(&source,sizeof(source));
    desti.sin_family = AF_INET;
    desti.sin_addr.s_addr = inet_addr(argv[2]);
    desti.sin_port = htons(desport);
    source.sin_family = AF_INET;
    source.sin_port = htons(sport);
    if(bind(send_fd,(struct sockaddr*) &source,socklen) != 0){
        perror("bind error");
        exit(1);
    }
    int hop = atoi(argv[1]), ttl = 1;
    int end = 0;
    char sendbuf[1500] = "";
    for(; ttl <= hop && !end; ttl++){
        int e = setsockopt(send_fd,IPPROTO_IP,IP_TTL,&ttl,sizeof(int));
        if(e < 0){ 
            perror("setsocket error");
            exit(1);
        }
        int n;
        if((n = sendto(send_fd,sendbuf,0,0,(struct sockaddr*) &desti,socklen1)) < 0){
            perror("sendto error");
            exit(1);
        }
        printf("TTL:%d\n",ttl);
        struct sockaddr addr;
        socklen_t addr_len = sizeof(addr);
        bzero(&addr,sizeof(addr));
        int code = recv_icmp(recv_fd,&addr,&addr_len,sport,desport);
        if(code == TIME_EXCEED){ //取得hostname and ip
            char hostname[1024] = "";
            if(getnameinfo(&addr,addr_len,hostname,sizeof(hostname),NULL,0,0) == 0){
                printf("%s (%s)\n",hostname,gethostip(&addr));
            }
            else printf("%s\n",gethostip(&addr));
        }else if(code == UNREACHABLE){ //取得hostname and ip
            end = 1;
            char hostname[1024] = "";
            if(getnameinfo(&addr,addr_len,hostname,sizeof(hostname),NULL,0,0) == 0){
                printf("%s (%s)\n",hostname,gethostip(&addr));
            }
            else printf("%s\n",gethostip(&addr));
        }else if(code == TIMEOUT){
            printf("**********\n");
        }
    }
}
char* gethostip(struct sockaddr* saddr){
    struct sockaddr_in *sin = (struct sockaddr_in*) saddr;
    static char hostip[30] = "";
    if(inet_ntop(AF_INET,&sin -> sin_addr,hostip,sizeof(hostip)) == NULL)
        return NULL;
    return hostip;
}
int recv_icmp(int fd,struct sockaddr* addr,socklen_t* socklen,uint16_t source,uint16_t desti){
    struct ip *ip1, *ip2;
    struct icmp *icmp;
    struct udphdr *udp;
    int nbytes;
    //3秒內若沒收到icmp reply packet的話，則往下個ttl送udp packet
   struct sigaction sig;
    sigemptyset(&sig.sa_mask);
    sig.sa_handler = alarm_timer;
    sig.sa_flags = 0;
    sigaction(SIGALRM, &sig, NULL);
    alarm(3);

    awake = 0;
    while(1){
        if(awake){
            alarm(0); 
            return TIMEOUT;
        }
        char recvbuf[1500] = "";
        if((nbytes = recvfrom(fd,recvbuf,sizeof(recvbuf),0,addr,socklen)) < 0){
            if (errno == EINTR)
                continue;
            perror("recvfrom error");
            exit(1);
        }
        ip1 = (struct ip*) recvbuf;
        int ip1_header_len = ip1 -> ip_hl * 4;
        icmp = (struct icmp*) (recvbuf + ip1_header_len);
        int icmp_len = nbytes - ip1_header_len;
        if(icmp_len < ICMP_MINLEN){
            continue;
        }
        if(icmp -> icmp_type == ICMP_TIMXCEED && icmp -> icmp_code == ICMP_TIMXCEED_INTRANS){
            ip2 = (struct ip*) (recvbuf + ip1_header_len + ICMP_MINLEN);
            int ip2_header_len = ip2 -> ip_hl * 4;
            udp = (struct udphdr*) (recvbuf + ip1_header_len + ICMP_MINLEN + ip2_header_len);
            if(ip2 -> ip_p == IPPROTO_UDP && udp -> uh_sport == htons(source) && udp -> uh_dport == htons(desti)){
                //檢查icmp所回應的是否是我們發送的udp packet
                alarm(0);
                return TIME_EXCEED;
            }
        }else if(icmp->icmp_type == ICMP_UNREACH){
            ip2 = (struct ip*) (recvbuf + ip1_header_len + ICMP_MINLEN);
            int ip2_header_len = ip2 -> ip_hl * 4;
            udp = (struct udphdr*) (recvbuf + ip1_header_len + ICMP_MINLEN + ip2_header_len);
            if(ip2 -> ip_p == IPPROTO_UDP && udp -> uh_sport == htons(source) && udp -> uh_dport == htons(desti)){
                //檢查icmp所回應的是否是我們發送的udp packet
                if(icmp -> icmp_code == ICMP_UNREACH_PORT){
                    alarm(0); 
                    return UNREACHABLE;
                }
                else{ 
                    alarm(0);
                    return icmp -> icmp_code;
                }
            }
        }
    }
}