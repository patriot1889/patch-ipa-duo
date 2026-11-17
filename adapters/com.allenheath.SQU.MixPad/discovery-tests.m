// Deterministic host-native tests. Every network syscall is replaced; no packet
// is sent and no host interfaces are read. Compile this file alone with clang.
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(condition) do { checks++; if (!(condition)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); exit(1); } } while (0)
static struct ifaddrs entries[8];
static struct sockaddr_in addresses[8], masks[8], bound_address, target;
static struct iovec vector;
static char packet[8], ancillary[12];
static struct msghdr original;
static unsigned entry_count, calls, probes, frees, option_calls, name_calls, index_calls;
static uint32_t destinations[2048];
static int socket_type, type_error, udp_error, name_error, bound_error, enumeration_error;
static int short_option, fail_send_count;
static unsigned bound_index;
static ssize_t forward_result;
static int forward_error;

static ssize_t fake_sendmsg(int socket, const struct msghdr *message, int flags) {
    calls++;
    CHECK(socket == 42);
    CHECK(flags == (MSG_DONTROUTE | MSG_DONTWAIT));
    if (message == &original || message == NULL) {
        CHECK(errno == EDOM);
        errno = forward_error;
        return forward_result;
    }
    probes++;
    CHECK(message != &original);
    CHECK(message->msg_iov == original.msg_iov && message->msg_iovlen == original.msg_iovlen);
    CHECK(message->msg_control == original.msg_control && message->msg_controllen == original.msg_controllen);
    CHECK(message->msg_flags == original.msg_flags && message->msg_namelen == original.msg_namelen);
    CHECK(memcmp(message->msg_iov[0].iov_base, "SQ Find", 7) == 0);
    const struct sockaddr_in *to = message->msg_name;
    CHECK(to->sin_family == AF_INET && to->sin_port == htons(51320));
    CHECK(to->sin_len == target.sin_len);
    CHECK(memcmp((const char *)message->msg_name + sizeof(*to),
        (const char *)original.msg_name + sizeof(*to), original.msg_namelen - sizeof(*to)) == 0);
    CHECK(probes <= sizeof(destinations) / sizeof(destinations[0]));
    destinations[probes - 1] = ntohl(to->sin_addr.s_addr);
    CHECK(destinations[probes - 1] != INADDR_BROADCAST);
    if (fail_send_count == -1 || (fail_send_count == -2 && probes > 1) || (int)probes <= fail_send_count) { errno = EHOSTUNREACH; return -1; }
    return 7;
}
static int fake_getsockopt(int socket, int level, int option, void *value, socklen_t *length) {
    option_calls++;
    CHECK(socket == 42 && *length == sizeof(int));
    int result = 0, failure = 0;
    if (level == SOL_SOCKET && option == SO_TYPE) { result = socket_type; failure = type_error; }
    else if (level == IPPROTO_UDP && option == UDP_NOCKSUM) failure = udp_error;
    else { CHECK(level == IPPROTO_IP && option == IP_BOUND_IF); result = (int)bound_index; failure = bound_error; }
    if (failure) { errno = failure; return -1; }
    memcpy(value, &result, sizeof(result));
    if (short_option && option == IP_BOUND_IF) *length = 1;
    return 0;
}
static int fake_getsockname(int socket, struct sockaddr *address, socklen_t *length) {
    name_calls++;
    CHECK(socket == 42 && *length >= sizeof(bound_address));
    if (name_error) { errno = name_error; return -1; }
    memcpy(address, &bound_address, sizeof(bound_address));
    *length = sizeof(bound_address);
    return 0;
}
static int fake_getifaddrs(struct ifaddrs **result) {
    if (enumeration_error) { errno = enumeration_error; return -1; }
    *result = entry_count ? entries : NULL;
    return 0;
}
static void fake_freeifaddrs(struct ifaddrs *value) {
    CHECK(value == (entry_count ? entries : NULL));
    frees++;
    errno = EIO; // Deliberately clobber errno: wrapper must preserve its outcome.
}
static unsigned fake_if_nametoindex(const char *name) {
    index_calls++;
    return strcmp(name, "en0") == 0 ? 4 : 5;
}
#define SQ_SENDMSG fake_sendmsg
#define SQ_GETSOCKOPT fake_getsockopt
#define SQ_GETSOCKNAME fake_getsockname
#define SQ_GETIFADDRS fake_getifaddrs
#define SQ_FREEIFADDRS fake_freeifaddrs
#define SQ_IF_NAMETOINDEX fake_if_nametoindex
#include "discovery.m"

static void reset(void) {
    memset(entries, 0, sizeof(entries)); memset(addresses, 0, sizeof(addresses));
    memset(masks, 0, sizeof(masks)); memset(&original, 0, sizeof(original));
    memset(&target, 0, sizeof(target)); memset(&bound_address, 0, sizeof(bound_address));
    entry_count = calls = probes = frees = option_calls = name_calls = index_calls = 0;
    socket_type = SOCK_DGRAM; type_error = udp_error = name_error = bound_error = enumeration_error = 0;
    short_option = fail_send_count = 0; bound_index = 0; forward_result = 3; forward_error = EPIPE;
    memcpy(packet, "SQ Find", 8);
    target.sin_len = sizeof(target); target.sin_family = AF_INET;
    target.sin_port = htons(51320); target.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    bound_address.sin_len = sizeof(bound_address); bound_address.sin_family = AF_INET;
    vector = (struct iovec){packet, 7};
    original.msg_name = &target; original.msg_namelen = sizeof(target);
    original.msg_iov = &vector; original.msg_iovlen = 1;
    original.msg_control = ancillary; original.msg_controllen = sizeof(ancillary); original.msg_flags = MSG_EOR;
}
static void add_interface(const char *name, const char *address, const char *mask, unsigned flags) {
    CHECK(entry_count < 8);
    unsigned i = entry_count++;
    if (i) entries[i - 1].ifa_next = &entries[i];
    entries[i].ifa_name = (char *)name; entries[i].ifa_flags = flags;
    addresses[i].sin_family = masks[i].sin_family = AF_INET;
    CHECK(inet_pton(AF_INET, address, &addresses[i].sin_addr) == 1);
    CHECK(inet_pton(AF_INET, mask, &masks[i].sin_addr) == 1);
    entries[i].ifa_addr = (struct sockaddr *)&addresses[i];
    entries[i].ifa_netmask = (struct sockaddr *)&masks[i];
}
#define ACTIVE (IFF_UP | IFF_RUNNING | IFF_BROADCAST)
static ssize_t run(void) { errno = EDOM; return sq_find(42, &original, MSG_DONTROUTE | MSG_DONTWAIT); }
static void forwarded(void) {
    CHECK(run() == forward_result); CHECK(errno == forward_error);
    CHECK(calls == 1 && probes == 0 && frees == 0);
}
static void no_hosts(void) {
    CHECK(run() == -1); CHECK(errno == ENETUNREACH);
    CHECK(calls == 0 && frees == 1);
}
int main(void) {
    reset(); packet[0] = 'X'; forwarded(); CHECK(option_calls == 0);
    reset(); vector.iov_len = 6; forwarded();
    reset(); original.msg_iovlen = 2; forwarded();
    reset(); original.msg_iov = NULL; forwarded();
    reset(); vector.iov_base = NULL; forwarded();
    reset(); original.msg_name = NULL; forwarded();
    reset(); original.msg_namelen--; forwarded();
    reset(); original.msg_namelen = SOCK_MAXADDRLEN + 1; forwarded();
    reset(); target.sin_family = AF_INET6; forwarded();
    reset(); target.sin_port = htons(51321); forwarded();
    reset(); target.sin_addr.s_addr = inet_addr("192.168.1.255"); forwarded();
    reset(); socket_type = SOCK_STREAM; forwarded(); CHECK(name_calls == 0);
    reset(); type_error = EBADF; forwarded();
    reset(); udp_error = ENOPROTOOPT; forwarded(); CHECK(name_calls == 0);
    reset(); bound_address.sin_family = AF_INET6; forwarded();
    reset(); forward_result = -1; forward_error = ENOBUFS; packet[0] = 'X'; forwarded();
    reset(); forward_result = 7; forward_error = EDOM; packet[0] = 'X'; forwarded();
    reset(); errno = EDOM; CHECK(sq_find(42, NULL, MSG_DONTROUTE | MSG_DONTWAIT) == 3); CHECK(errno == EPIPE);

    reset(); add_interface("en0", "192.168.1.50", "255.255.255.0", ACTIVE);
    struct msghdr saved = original; struct sockaddr_in saved_target = target;
    CHECK(run() == 7 && errno == EDOM); CHECK(probes == 253 && frees == 1);
    CHECK(destinations[0] == ntohl(inet_addr("192.168.1.1")));
    CHECK(destinations[252] == ntohl(inet_addr("192.168.1.254")));
    for (unsigned i = 0; i < probes; i++) CHECK(destinations[i] != ntohl(inet_addr("192.168.1.50")));
    CHECK(memcmp(&saved, &original, sizeof(saved)) == 0 && memcmp(&saved_target, &target, sizeof(target)) == 0);

    reset(); add_interface("en0", "10.0.0.1", "255.255.255.252", ACTIVE);
    unsigned char padded_name[32]; memset(padded_name, 0xab, sizeof(padded_name));
    memcpy(padded_name, &target, sizeof(target)); original.msg_name = padded_name; original.msg_namelen = sizeof(padded_name);
    CHECK(run() == 7 && probes == 1);

    reset(); add_interface("en0", "10.42.6.2", "255.0.0.0", ACTIVE);
    CHECK(run() == 7 && probes == 253); CHECK(destinations[0] == ntohl(inet_addr("10.42.6.1")));
    CHECK(destinations[252] == ntohl(inet_addr("10.42.6.254")));
    reset(); add_interface("en0", "192.168.1.5", "255.255.255.252", ACTIVE);
    CHECK(run() == 7 && probes == 1); CHECK(destinations[0] == ntohl(inet_addr("192.168.1.6")));
    reset(); add_interface("en0", "255.255.255.253", "255.255.255.252", ACTIVE);
    CHECK(run() == 7 && probes == 1); CHECK(destinations[0] == UINT32_C(0xfffffffe));
    reset(); add_interface("en0", "10.2.3.4", "0.0.0.0", ACTIVE); CHECK(run() == 7 && probes == 253);

    reset(); add_interface("en0", "10.0.0.1", "255.255.255.254", ACTIVE); no_hosts();
    reset(); add_interface("en0", "10.0.0.1", "255.255.255.255", ACTIVE); no_hosts();
    reset(); add_interface("en0", "10.0.0.1", "255.0.255.0", ACTIVE); no_hosts();
    reset(); add_interface("en0", "0.0.0.0", "255.255.255.0", ACTIVE); no_hosts();
    reset(); no_hosts();
    unsigned excluded[] = {IFF_UP | IFF_BROADCAST, IFF_RUNNING | IFF_BROADCAST,
        IFF_UP | IFF_RUNNING, ACTIVE | IFF_LOOPBACK, ACTIVE | IFF_POINTOPOINT};
    for (unsigned i = 0; i < sizeof(excluded)/sizeof(excluded[0]); i++) {
        reset(); add_interface("en0", "10.0.0.1", "255.255.255.0", excluded[i]); no_hosts();
    }
    reset(); add_interface("en0", "10.0.0.1", "255.255.255.0", ACTIVE); entries[0].ifa_addr = NULL; no_hosts();
    reset(); add_interface("en0", "10.0.0.1", "255.255.255.0", ACTIVE); entries[0].ifa_netmask = NULL; no_hosts();
    reset(); add_interface("en0", "10.0.0.1", "255.255.255.0", ACTIVE); addresses[0].sin_family = AF_INET6; no_hosts();
    reset(); add_interface("en0", "10.0.0.1", "255.255.255.0", ACTIVE); masks[0].sin_family = AF_INET6; no_hosts();

    reset(); add_interface("en0", "10.0.0.1", "255.255.255.252", ACTIVE);
    add_interface("en1", "10.0.1.1", "255.255.255.252", ACTIVE); bound_address.sin_addr.s_addr = inet_addr("10.0.1.1");
    CHECK(run() == 7 && probes == 1 && destinations[0] == ntohl(inet_addr("10.0.1.2")));
    reset(); add_interface("en0", "10.0.0.1", "255.255.255.252", ACTIVE);
    add_interface("en1", "10.0.1.1", "255.255.255.252", ACTIVE); bound_index = 5;
    CHECK(run() == 7 && probes == 1 && index_calls == 2 && destinations[0] == ntohl(inet_addr("10.0.1.2")));
    reset(); add_interface("en0", "10.0.0.1", "255.255.255.252", ACTIVE); bound_index = 5; no_hosts();
    reset(); add_interface("en0", "10.0.0.1", "255.255.255.252", ACTIVE);
    bound_address.sin_addr.s_addr = inet_addr("10.0.1.1"); no_hosts();

    reset(); name_error = EBADF; CHECK(run() == -1 && errno == EBADF && calls == 0 && frees == 0);
    reset(); bound_error = EPERM; CHECK(run() == -1 && errno == EPERM && calls == 0 && frees == 0);
    reset(); short_option = 1; CHECK(run() == -1 && errno == EINVAL && calls == 0 && frees == 0);
    reset(); enumeration_error = ENOMEM; CHECK(run() == -1 && errno == ENOMEM && calls == 0 && frees == 0);
    reset(); add_interface("en0", "10.0.0.1", "255.255.255.248", ACTIVE); fail_send_count = -1;
    CHECK(run() == -1 && errno == EHOSTUNREACH && probes == 5 && frees == 1);
    reset(); add_interface("en0", "10.0.0.1", "255.255.255.248", ACTIVE); fail_send_count = 4;
    CHECK(run() == 7 && errno == EDOM && probes == 5 && frees == 1);
    reset(); add_interface("en0", "10.0.0.1", "255.255.255.248", ACTIVE); fail_send_count = -2;
    CHECK(run() == 7 && errno == EDOM && probes == 5 && frees == 1);
    printf("PASS: %u deterministic discovery assertions; no network syscalls\n", checks);
    return 0;
}
