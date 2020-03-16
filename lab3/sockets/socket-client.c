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
                	printf("Server went away. Exiting...\n");
                	return 0;
                }
                if (ret < 0) {
                	perror("read from server failed");
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

int main(int argc, char *argv[])
{
	int sd, port;
	char buf[BFR_SIZE];
	char *hostname;

	int fd;
	fd_set read_set;

	struct hostent *hp;
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

	//data.key = "abcdefghijklmnop";
	//data.iv = "ponmlkjihgfedcba";
	
	sprintf(data.key, "%s", "abcdefghijklmnop");
	sprintf(data.iv, "%s", "abcdefghijklmnop");
	
	if (argc != 3) {
		printf("Usage: %s [hostname] [port]\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	printf("Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if (!(hp = gethostbyname(hostname))) {
		perror("DNS lookup failed");
		exit(1);
	}

	fd = open("/dev/crypto", O_RDWR);
	if (fd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = data.key;

	if (ioctl(fd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	printf("Connecting to remote host... ");
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	printf("Connected.\n");
	
	/* Read answer and write it to standard output */
	for (;;) {

		FD_ZERO(&read_set);
		FD_SET(0, &read_set);
		FD_SET(sd, &read_set);

		cryp.ses = sess.ses;
		cryp.len = sizeof(buf);
		cryp.iv = data.iv;

		if(select(sd + 1, &read_set, NULL, NULL, NULL)){

			if(FD_ISSET(0, &read_set)){

			    	fgets(buf, sizeof(buf), stdin);

		        	if (strcmp(buf,"/exit\n") == 0) break;

				cryp.src = buf;
				cryp.dst = data.encrypted;
				cryp.op = COP_ENCRYPT;

				if (ioctl(fd, CIOCCRYPT, &cryp)) {
					perror("ioctl(CIOCCRYPT)");
					return 1;
				}
		        
		    		if (insist_write(sd, data.encrypted, BFR_SIZE) != BFR_SIZE) {
					perror("write to server failed");
					break;
	    			}
	    		}

	    		if(FD_ISSET(sd, &read_set)){

		    		if (insist_read(sd, buf, BFR_SIZE) != BFR_SIZE) break;
			
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

	if (close(sd) < 0)
		perror("close");
	
	return 0;
}
