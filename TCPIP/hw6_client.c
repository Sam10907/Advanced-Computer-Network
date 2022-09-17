
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <time.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	int send_fd = socket(AF_INET,SOCK_STREAM,0);
    int recv_fd = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in srv,srv1,cli;
    socklen_t len = sizeof(cli);
    //send
    srv.sin_family = AF_INET;
    srv.sin_port = htons(1234);
    srv.sin_addr.s_addr = inet_addr("10.0.0.1");
    //recv
    srv1.sin_family = AF_INET;
    srv1.sin_port = 0;
    srv1.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(recv_fd,(struct sockaddr*) &srv1,sizeof(srv1)) < 0){
        perror("bind error");
        exit(1);
    }
    socklen_t len1 = sizeof(srv1);
    getsockname(recv_fd,(struct sockaddr*) &srv1,&len1);
    if(connect(send_fd,(struct sockaddr*) &srv,sizeof(srv)) < 0){ //連線失敗
        perror("connect error\n");
        exit(1);
    }
    int port = srv1.sin_port;
    if(send(send_fd,&port,sizeof(port),0) < 0){
        perror("send error");
        exit(1);
    }
    
    if(listen(recv_fd,5) < 0){
        perror("listen error\n");
        exit(1);
    }
    int newfd;
    while((newfd = accept(recv_fd,(struct sockaddr*) &cli,&len))){
        int num;
        if(recv(newfd,&num,sizeof(num),0) < 0){
            perror("recv error");
            exit(1);
        }
        if(num != port) break; 
        else{
            char msg[50] = "This is priority socket";
            char msg1[50] = "This is normal socket";
            send(newfd,msg,strlen(msg),0);
            send(send_fd,msg1,strlen(msg1),0);
        } 
    }
}
