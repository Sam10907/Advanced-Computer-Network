
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h> 
#include <fcntl.h>

int main(int argc, char *argv[])
{
    int send_fd = socket(AF_INET,SOCK_STREAM,0);
    int recv_fd = socket(AF_INET,SOCK_STREAM,0);
    //將socket設為non-blocking
    int flags=fcntl(recv_fd,F_GETFL,0);
    fcntl(recv_fd,F_SETFL,flags | O_NONBLOCK);
    struct sockaddr_in srv,cli,srv1;
    socklen_t clilen=sizeof(cli);
    srv.sin_family=AF_INET;
    srv.sin_port=htons(1234);
    srv.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(recv_fd,(struct sockaddr*) &srv,sizeof(srv)) < 0){
        perror("bind error\n");
        exit(1);
    }
    //開始監聽
    if(listen(recv_fd,5) < 0){
        perror("listen error\n");
        exit(1);
    }

    fd_set rfds;
    fd_set afds;
    int maxfd = recv_fd;
    FD_ZERO(&rfds);
    FD_ZERO(&afds);
    FD_SET(recv_fd,&afds);
    int newfd, port,first = 1;
    while(1){
        memcpy(&rfds,&afds,sizeof(rfds));
        if(select(maxfd+1,&rfds,NULL,NULL,NULL) < 0){
            perror("no ready read file descriptor");
            exit(1);
        }
        if(FD_ISSET(recv_fd,&rfds)){ //如果有連線請求
            if((newfd = accept(recv_fd,(struct sockaddr*) &cli,&clilen)) < 0){
                perror("accept error");
                exit(1);
            }
            int flags=fcntl(newfd,F_GETFL,0);
            fcntl(newfd,F_SETFL,flags | O_NONBLOCK);
            maxfd = newfd;
            FD_SET(newfd,&afds);
        }
        int i;
        for(i = 0 ; i < (maxfd + 1) ; i++){
            if(i != recv_fd && FD_ISSET(i,&rfds)){
                if(first){
                    recv(i,&port,sizeof(port),0);
                    srv1.sin_family = AF_INET;
                    srv1.sin_port = port;
                    srv1.sin_addr.s_addr = cli.sin_addr.s_addr;
                    if(connect(send_fd,(struct sockaddr*) &srv1,sizeof(srv1)) < 0){
                        perror("connect error");
                        exit(1);
                    }
                    FD_SET(send_fd,&afds);
                    if(send(send_fd,&port,sizeof(port),0) < 0){
                        perror("send error");
                        exit(1);
                    }
                    first = 0;
                    break;
                }
                char buf[50] = "";
                recv(i,buf,sizeof(buf),0);
                printf("socket: %d %s\n",i,buf);
            }
        }
    }
    shutdown(recv_fd,SHUT_RDWR);
}