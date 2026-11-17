// SQ MixPad 1.60.1 discovery: substitute local IPv4 unicast probes for the
// exact SQ Find broadcast. All other sendmsg calls retain their original path.
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <ifaddrs.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#ifndef SQ_SENDMSG
#define SQ_SENDMSG sendmsg
#endif
#ifndef SQ_GETSOCKOPT
#define SQ_GETSOCKOPT getsockopt
#endif
#ifndef SQ_GETSOCKNAME
#define SQ_GETSOCKNAME getsockname
#endif
#ifndef SQ_GETIFADDRS
#define SQ_GETIFADDRS getifaddrs
#endif
#ifndef SQ_FREEIFADDRS
#define SQ_FREEIFADDRS freeifaddrs
#endif
#ifndef SQ_IF_NAMETOINDEX
#define SQ_IF_NAMETOINDEX if_nametoindex
#endif

static ssize_t sq_forward(int socket, const struct msghdr *message, int flags,
                          int original_errno) {
    errno = original_errno;
    return SQ_SENDMSG(socket, message, flags);
}

__attribute__((visibility("default")))
ssize_t sq_find(int socket, const struct msghdr *message, int flags) {
    int original_errno = errno;
    if (!message || !message->msg_name ||
        message->msg_namelen < sizeof(struct sockaddr_in) ||
        message->msg_namelen > SOCK_MAXADDRLEN ||
        !message->msg_iov || message->msg_iovlen != 1 ||
        !message->msg_iov[0].iov_base || message->msg_iov[0].iov_len != 7)
        return sq_forward(socket, message, flags, original_errno);

    struct sockaddr_in destination;
    memcpy(&destination, message->msg_name, sizeof(destination));
    if (destination.sin_family != AF_INET ||
        destination.sin_port != htons(51320) ||
        destination.sin_addr.s_addr != htonl(INADDR_BROADCAST) ||
        memcmp(message->msg_iov[0].iov_base, "SQ Find", 7) != 0)
        return sq_forward(socket, message, flags, original_errno);

    int socket_type = 0;
    socklen_t length = sizeof(socket_type);
    if (SQ_GETSOCKOPT(socket, SOL_SOCKET, SO_TYPE, &socket_type, &length) < 0 ||
        length != sizeof(socket_type) || socket_type != SOCK_DGRAM)
        return sq_forward(socket, message, flags, original_errno);
    // Darwin has no SO_PROTOCOL. A UDP-specific read distinguishes UDP from
    // other IPv4 datagram protocols without changing a socket option.
    int no_checksum = 0;
    length = sizeof(no_checksum);
    if (SQ_GETSOCKOPT(socket, IPPROTO_UDP, UDP_NOCKSUM, &no_checksum, &length) < 0 ||
        length != sizeof(no_checksum))
        return sq_forward(socket, message, flags, original_errno);

    struct sockaddr_storage local_storage = {0};
    length = sizeof(local_storage);
    if (SQ_GETSOCKNAME(socket, (struct sockaddr *)&local_storage, &length) < 0)
        return -1;
    if (length < sizeof(struct sockaddr_in) || local_storage.ss_family != AF_INET)
        return sq_forward(socket, message, flags, original_errno);
    struct sockaddr_in local;
    memcpy(&local, &local_storage, sizeof(local));

    unsigned int bound_interface = 0;
    length = sizeof(bound_interface);
    if (SQ_GETSOCKOPT(socket, IPPROTO_IP, IP_BOUND_IF, &bound_interface, &length) < 0)
        return -1;
    if (length != sizeof(bound_interface)) {
        errno = EINVAL;
        return -1;
    }

    struct ifaddrs *interfaces = NULL;
    if (SQ_GETIFADDRS(&interfaces) < 0) return -1;
    // Preserve even a padded sockaddr length and bytes; only the IPv4 address
    // changes. The kernel accepts at most SOCK_MAXADDRLEN bytes for a name.
    union {
        struct sockaddr_in address;
        unsigned char bytes[SOCK_MAXADDRLEN];
    } probe_destination;
    memcpy(probe_destination.bytes, message->msg_name, message->msg_namelen);
    int send_error = ENETUNREACH;
    int succeeded = 0;
    for (const struct ifaddrs *interface = interfaces; interface; interface = interface->ifa_next) {
        unsigned int required = IFF_UP | IFF_RUNNING | IFF_BROADCAST;
        if ((interface->ifa_flags & required) != required ||
            (interface->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT)) ||
            !interface->ifa_name || !interface->ifa_addr || !interface->ifa_netmask ||
            interface->ifa_addr->sa_family != AF_INET ||
            interface->ifa_netmask->sa_family != AF_INET) continue;
        const struct sockaddr_in *address = (const struct sockaddr_in *)interface->ifa_addr;
        const struct sockaddr_in *netmask = (const struct sockaddr_in *)interface->ifa_netmask;
        if (local.sin_addr.s_addr != htonl(INADDR_ANY) &&
            address->sin_addr.s_addr != local.sin_addr.s_addr) continue;
        if (bound_interface && SQ_IF_NAMETOINDEX(interface->ifa_name) != bound_interface) continue;

        uint32_t own_address = ntohl(address->sin_addr.s_addr);
        uint32_t mask = ntohl(netmask->sin_addr.s_addr);
        uint32_t host_mask = ~mask;
        // Valid netmasks have contiguous high bits. /31 and /32 offer no
        // conventional host range; broader networks are restricted to this /24.
        if (!own_address || (host_mask & (host_mask + 1U)) != 0 || host_mask < 3U) continue;
        if (host_mask > 255U) mask = UINT32_C(0xffffff00);
        uint32_t first = own_address & mask;
        uint32_t last = first | ~mask;
        for (uint32_t host = first + 1U; host < last; host++) {
            if (host == own_address) continue;
            probe_destination.address.sin_addr.s_addr = htonl(host);
            struct msghdr probe = *message;
            probe.msg_name = probe_destination.bytes;
            if (SQ_SENDMSG(socket, &probe, flags) >= 0) succeeded = 1;
            else send_error = errno;
        }
    }
    SQ_FREEIFADDRS(interfaces);
    errno = succeeded ? original_errno : send_error;
    return succeeded ? 7 : -1;
}
