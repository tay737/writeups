/* LD_PRELOAD resolver shim: map *.hercules.htb -> 10.129.242.196 (no /etc/hosts write needed) */
#define _GNU_SOURCE
#include <netdb.h>
#include <string.h>
#include <strings.h>
#include <dlfcn.h>

#define MAP_NAME "hercules.htb"
#define MAP_IP   "10.129.242.196"

typedef int (*ga_t)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef struct hostent *(*ghbn_t)(const char *);

static int is_target(const char *node)
{
    size_t ln, lm;
    if (!node) return 0;
    ln = strlen(node);
    lm = strlen(MAP_NAME);
    if (ln < lm) return 0;
    if (strcasecmp(node + ln - lm, MAP_NAME) != 0) return 0;
    if (ln == lm) return 1;
    return node[ln - lm - 1] == '.';
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res)
{
    static ga_t real = NULL;
    if (!real) real = (ga_t)dlsym(RTLD_NEXT, "getaddrinfo");
    if (is_target(node)) return real(MAP_IP, service, hints, res);
    return real(node, service, hints, res);
}

struct hostent *gethostbyname(const char *name)
{
    static ghbn_t real = NULL;
    if (!real) real = (ghbn_t)dlsym(RTLD_NEXT, "gethostbyname");
    if (is_target(name)) return real(MAP_IP);
    return real(name);
}

struct hostent *gethostbyname2(const char *name, int af)
{
    static struct hostent *(*real)(const char *, int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "gethostbyname2");
    if (is_target(name)) return real(MAP_IP, af);
    return real(name, af);
}
