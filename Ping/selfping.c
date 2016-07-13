#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/poll.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

/* Defaults */
static bdaddr_t bdaddr;
static int size    = 669;
static int ident   = 200;
static int delay   = 1;
static int count   = -1;
static int timeout = 10;
static int reverse = 0;
static int verify = 0;

/* Stats */
static int sent_pkt = 0;
static int recv_pkt = 0;

int set_l2cap_mtu( int sock, uint16_t mtu ) {
	struct l2cap_options opts;
    int optlen = sizeof(opts), err;
    err = getsockopt( sock, SOL_L2CAP, L2CAP_OPTIONS, &opts, &optlen );
    if( ! err ) {
        opts.omtu = opts.imtu = mtu;
        opts.omtu = opts.imtu = mtu;
        err = setsockopt( sock, SOL_L2CAP, L2CAP_OPTIONS, &opts, optlen );
    }
    return err;
};

static float tv2fl(struct timeval tv)
{
	return (float)(tv.tv_sec*1000.0) + (float)(tv.tv_usec/1000.0);
}

int main() {
    int btsock;
	struct sockaddr_l2 addr;
	unsigned char *send_buf;
	unsigned char *recv_buf;
	socklen_t optlen;
	uint8_t id;
    int i;
    int lost;
    char * svr = "58:3F:54:7A:F8:5E";
	char str[18];

	/* Default options */
	bacpy(&bdaddr, BDADDR_ANY);

	send_buf = malloc(L2CAP_CMD_HDR_SIZE + size);
	recv_buf = malloc(L2CAP_CMD_HDR_SIZE + size);
	if (!send_buf || !recv_buf) {
		perror("Can't allocate buffer");
		exit(1);
	}

	/* Create socket */

    btsock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
	if (btsock < 0) {
		perror("Can't create socket");
		return -1;
	}

    set_l2cap_mtu(btsock, 1000);

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, &bdaddr);

	if (bind(btsock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't bind socket");
		return -1;
	}

	/* Connect to remote device */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(svr, &addr.l2_bdaddr);

	if (connect(btsock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't connect");
		return -1;
	}/* Get local address */
	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);

	if (getsockname(btsock, (struct sockaddr *) &addr, &optlen) < 0) {
		perror("Can't get local address");
		return -1;
	}

	ba2str(&addr.l2_bdaddr, str);
	printf("Ping: %s from %s (data size %d) ...\n", svr, str, size);

	/* Initialize send buffer */
	for (i = 0; i < size; i++)
		send_buf[L2CAP_CMD_HDR_SIZE + i] = (i % 40) + 'A';

	id = ident;

	while (count == -1 || count-- > 0) {
		struct timeval tv_send, tv_recv, tv_diff;
		l2cap_cmd_hdr *send_cmd = (l2cap_cmd_hdr *) send_buf;
		l2cap_cmd_hdr *recv_cmd = (l2cap_cmd_hdr *) recv_buf;

		/* Build command header */
		send_cmd->ident = id;
		send_cmd->len   = htobs(size);

		if (reverse)
			send_cmd->code = L2CAP_ECHO_RSP;
		else
			send_cmd->code = L2CAP_ECHO_REQ;

		gettimeofday(&tv_send, NULL);

		/* Send Echo Command */
		if (send(btsock, send_buf, L2CAP_CMD_HDR_SIZE + size, 0) <= 0) {
			perror("Send failed");
			return -1;
		}

		/* Wait for Echo Response */
		lost = 0;
		while (1) {
			struct pollfd pf[1];
			int err;

			pf[0].fd = btsock;
			pf[0].events = POLLIN;

			if ((err = poll(pf, 1, timeout * 1000)) < 0) {
				perror("Poll failed");
				return -1;
			}

			if (!err) {
				lost = 1;
				break;
			}

			if ((err = recv(btsock, recv_buf, L2CAP_CMD_HDR_SIZE + size, 0)) < 0) {
				perror("Recv failed");
				return -1;
			}

			if (!err){
				printf("Disconnected\n");
				return -1;
			}

			recv_cmd->len = btohs(recv_cmd->len);

			/* Check for our id */
			if (recv_cmd->ident != id)
				continue;

			/* Check type */
			if (!reverse && recv_cmd->code == L2CAP_ECHO_RSP)
				break;

			if (recv_cmd->code == L2CAP_COMMAND_REJ) {
				printf("Peer doesn't support Echo packets\n");
				return -1;
			}

		}
		sent_pkt++;

		if (!lost) {
			recv_pkt++;

			gettimeofday(&tv_recv, NULL);
			timersub(&tv_recv, &tv_send, &tv_diff);

			if (verify) {
				/* Check payload length */
				if (recv_cmd->len != size) {
					fprintf(stderr, "Received %d bytes, expected %d\n",
						   recv_cmd->len, size);
					return -1;
				}

				/* Check payload */
				if (memcmp(&send_buf[L2CAP_CMD_HDR_SIZE],
						   &recv_buf[L2CAP_CMD_HDR_SIZE], size)) {
					fprintf(stderr, "Response payload different.\n");
					return -1;
				}
			}

			printf("%d bytes from %s id %d time %.2fms\n", recv_cmd->len, svr,
				   id - ident, tv2fl(tv_diff));

			if (delay)
				sleep(delay);
		} else {
			printf("no response from %s: id %d\n", svr, id - ident);
		}

		if (++id > 254)
			id = ident;
	}
	free(send_buf);
	free(recv_buf);
	return 0;
}
