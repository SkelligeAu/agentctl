/* Linux proof: timeout includes a silent broker and an inherited lock holder. */
#include "ipc.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

static long now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1000+t.tv_nsec/1000000; }
static int threaded_result;
static void *connect_thread(void *unused) {
    (void)unused; threaded_result=ipc_connect_timeout("worker",2000); return NULL;
}
static int reply_fd(int socket, int fd) {
    char data[]="VERB issued\n\n", control[CMSG_SPACE(sizeof(int))]={0};
    struct iovec v={data,sizeof(data)-1}; struct msghdr m={0};
    m.msg_iov=&v; m.msg_iovlen=1; m.msg_control=control; m.msg_controllen=sizeof(control);
    struct cmsghdr *c=CMSG_FIRSTHDR(&m); c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS;
    c->cmsg_len=CMSG_LEN(sizeof(int)); memcpy(CMSG_DATA(c),&fd,sizeof(fd));
    return (int)sendmsg(socket,&m,MSG_NOSIGNAL);
}
int main(void) {
    int sockets[2]; assert(socketpair(AF_UNIX,SOCK_SEQPACKET,0,sockets)==0);
    int client=fcntl(sockets[0],F_DUPFD_CLOEXEC,10), server=fcntl(sockets[1],F_DUPFD_CLOEXEC,10);
    close(sockets[0]); close(sockets[1]); assert(dup2(client,3)==3); close(client);
    char path[]="/tmp/broker-lock-XXXXXX"; int lock=mkstemp(path); assert(lock>=0); unlink(path);
    assert(dup2(lock,5)==5); if(lock!=5) close(lock); setenv("AGENTCTL_BROKER_LOCK_FD","5",1);
    long start=now(); errno=0;
    assert(ipc_connect_timeout("worker",100)==IPC_ERR); assert(errno==ETIMEDOUT);
    assert(now()-start>=80 && now()-start<1000);
    /* Late responses cannot be reused after a timed-out exchange. */
    char b[512]; assert(recv(server,b,sizeof(b),0)>0); assert(recv(server,b,sizeof(b),0)==0);
    assert(reply_fd(server,5)<0 && errno==EPIPE);
    assert(ipc_connect_timeout("worker",100)==IPC_ERR);
    close(3); close(server);
    assert(ipc_connect_timeout("worker",100)==IPC_ERR && errno==ENOTCONN);
    assert(ipc_connect_timeout("worker",0)==IPC_ERR && errno==EINVAL);
    assert(socketpair(AF_UNIX,SOCK_SEQPACKET,0,sockets)==0);
    client=fcntl(sockets[0],F_DUPFD_CLOEXEC,10); server=fcntl(sockets[1],F_DUPFD_CLOEXEC,10);
    close(sockets[0]); close(sockets[1]); assert(dup2(client,3)==3); close(client);
    int ready[2]; assert(pipe(ready)==0); pid_t child=fork(); assert(child>=0);
    if(child==0) {
        close(ready[0]); struct flock l={0}; l.l_type=F_WRLCK; l.l_whence=SEEK_SET;
        assert(fcntl(5,F_SETLK,&l)==0); assert(write(ready[1],"1",1)==1); sleep(5); _exit(0);
    }
    close(ready[1]); assert(read(ready[0],b,1)==1); close(ready[0]); start=now();
    assert(ipc_connect_timeout("worker",100)==IPC_ERR && errno==ETIMEDOUT);
    assert(now()-start<1000); kill(child,SIGKILL); waitpid(child,NULL,0);
    /* The same deadline includes thread contention. First exchange can still
     * complete after a second caller times out waiting for the shared lock. */
    pthread_t thread; assert(pthread_create(&thread,NULL,connect_thread,NULL)==0);
    assert(recv(server,b,sizeof(b),0)>0); start=now();
    assert(ipc_connect_timeout("worker",100)==IPC_ERR && errno==ETIMEDOUT);
    assert(now()-start<1000);
    assert(reply_fd(server,5)>0); assert(pthread_join(thread,NULL)==0);
    assert(threaded_result>=0 && (fcntl(threaded_result,F_GETFD)&FD_CLOEXEC));
    close(threaded_result);
    close(3); close(5); close(server); return 0;
}
