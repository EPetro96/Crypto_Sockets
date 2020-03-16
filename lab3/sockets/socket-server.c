#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"
#include <crypto/cryptodev.h>

/* Insist until all of the data has been read */
ssize_t insist_read(int fd, void *buf, size_t cnt)
{
        ssize_t ret;
        size_t orig_cnt = cnt;

        while (cnt > 0) {
                ret = read(fd, buf, cnt);
                if (ret == 0) {
                	printf("Remote peer went away\n");
                	return 0;
                }
                if (ret < 0) {
                	perror("read from remote peer failed");
                        return ret;
                }
                buf += ret;
                cnt -= ret;
        }

        return orig_cnt;
}

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}


int main(void)
{
	char buf[BFR_SIZE];
	char addrstr[INET_ADDRSTRLEN];
	int sd, newsd;
	socklen_t len;
	struct sockaddr_in sa;


	struct session_op sess;
	struct crypt_op cryp;
	struct {
		unsigned char 	in[BFR_SIZE],
				encrypted[BFR_SIZE],
				decrypted[BFR_SIZE],
				iv[BLOCK_SIZE],
				key[KEY_SIZE];
	} data;

	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));

	fd_set read_set;
	int fd;

	fd = open("/dev/crypto", O_RDWR);
	if (fd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	
	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	printf("Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	printf("Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}

	//data.key = ['abcdefghijklmnop'];
	//data.iv = ['ponmlkjihgfedcba'];

	sprintf(data.key, "%s", "abcdefghijklmnop");
	sprintf(data.iv, "%s", "abcdefghijklmnop");

	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = data.key;

	//printf("Key is:%lu\n", (unsigned long) sess.key);

	//printf("Key after is:%lu\n", (unsigned long) sess.key);	

	cryp.ses = sess.ses;
	
	/* Loop forever, accept()ing connections */
	for (;;) {
		printf("Waiting for an incoming connection...\n");

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		printf("Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));


		/* We break out of the loop when the remote peer goes away */
		for (;;) {

			if (ioctl(fd, CIOCGSESSION, &sess)) {
		                perror("ioctl(CIOCGSESSION)");
                		return 1;
  			}



			FD_ZERO(&read_set);
			FD_SET(0, &read_set);
			FD_SET(newsd, &read_set);

			cryp.iv = data.iv;
			cryp.len = sizeof(buf);		

			if(select(newsd + 1, &read_set, NULL, NULL, NULL)){
				if(FD_ISSET(0, &read_set)){
					fgets(buf, sizeof(buf), stdin);
					
					if ( strcmp(buf,"/exit\n")==0 ) {
						if (close(newsd) < 0)
							perror("close");
						return 0;
					}

					cryp.src = buf;
					cryp.dst = data.encrypted;
					cryp.op = COP_ENCRYPT;

					if (ioctl(fd, CIOCCRYPT, &cryp)) {
						perror("ioctl(CIOCCRYPT)");
						return 1;
					}
						
					if (insist_write(newsd, data.encrypted, BFR_SIZE) != BFR_SIZE) {
						printf("write to remote peer failed\n");
						break;
					}
				}

				if(FD_ISSET(newsd, &read_set)){

					if (insist_read(newsd, buf, BFR_SIZE) != BFR_SIZE) break;

					cryp.src = buf;
					cryp.dst = data.decrypted;
					cryp.op = COP_DECRYPT;
					if (ioctl(fd, CIOCCRYPT, &cryp)) {
						perror("ioctl(CIOCCRYPT)");
						return 1;
					}
			
					printf("%s",data.decrypted);
				}

			}
		}
		if (ioctl(fd, CIOCFSESSION, &sess)) {
                        perror("ioctl(CIOCFSESSION)");
                	return 1;
                }

		/* Make sure we don't leak open files */
		if (close(newsd) < 0)
			perror("close");
	}

	/* This will never happen */
	return 1;
}
