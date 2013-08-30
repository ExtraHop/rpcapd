/*
 * Copyright (c) 1987, 1993, 1994
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>		// for PCAP_ERRBUF_SIZE

#ifdef linux
#include <netinet/in.h>
#include <linux/if_packet.h>
#endif

#include "rpcapd.h"
#include "pcap-remote.h"
#include "sockutils.h"


extern char hostlist[MAX_HOST_LIST + 1];		//!< Keeps the list of the hosts that are allowed to connect to this server
extern struct active_pars activelist[MAX_ACTIVE_LIST];		//!< Keeps the list of the hosts (host, port) on which I want to connect to (active mode)
extern int nullAuthAllowed;					//!< '1' if we permit NULL authentication, '0' otherwise
extern char loadfile[MAX_LINE + 1];			//!< Name of the file from which we have to load the configuration

struct ipaddr_spec {
    int sa_family;
    short prefix_len;
    uint32_t addr[4];
    uint32_t mask[4];
};


int strrem(char *string, char chr);

static void
fileconf_sockaddr_to_text(struct sockaddr *addr, char *addrstr, int addrstrsize)
{
    char buf[64];
    socklen_t sockaddrlen;
#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif
    buf[0] = '\0';
    addrstr[0] = '\0';
    if (getnameinfo(addr, sockaddrlen, buf, sizeof(buf), NULL, 0,
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
#ifdef AF_PACKET
        if (addr->sa_family == AF_PACKET) {
            const struct sockaddr_ll *sll = (struct sockaddr_ll *)addr;
            if (sll->sll_halen == 6) {
                snprintf(addrstr, addrstrsize,
                         "mac %02X:%02X:%02X:%02X:%02X:%02X",
                         sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2],
                         sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]);
            }
        }
#endif
        if (addrstr[0] == '\0') {
            snprintf(addrstr, addrstrsize, "unknown sa_family=%d",
                     (int)addr->sa_family);
        }
    }
    else if (addr->sa_family == AF_INET) {
        snprintf(addrstr, addrstrsize, "ip %s", buf);
    }
    else if (addr->sa_family == AF_INET6) {
        snprintf(addrstr, addrstrsize, "ipv6 %s", buf);
    }
    else {
        snprintf(addrstr, addrstrsize, "%s", buf);
    }
}

static inline void
ip6_make_mask(uint32_t *c, int n)
{

    c[0] = c[1] = c[2] = c[3] = 0;

    while (n > 32) {
        *c++ = 0xffffffffU;
        n -= 32;
    }
    if (n != 0) {
        *c = htonl(0xffffffffU << (32 - n));
    }
}

static inline uint32_t
ip4_maskcmp(uint32_t *a, uint32_t *b, uint32_t *mask)
{
    return ((a[0] & mask[0]) ^ (b[0] & mask[0]));
}

static inline uint32_t
ip6_maskcmp(uint32_t *a, uint32_t *b, uint32_t *mask)
{
    return ((a[0] & mask[0]) ^ (b[0] & mask[0])) |
           ((a[1] & mask[1]) ^ (b[1] & mask[1])) |
           ((a[2] & mask[2]) ^ (b[2] & mask[2])) |
           ((a[3] & mask[3]) ^ (b[3] & mask[3]));
}

static int
ipaddr_spec_parse(char *addrstr, int addrstrlen,
                  struct ipaddr_spec *spec)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL, *rp;
    int rc = -1;
    char ipstr[64];
    char *p;
    int prefix_len;

    p = memchr(addrstr, '/', addrstrlen);
    if (p != NULL) {
        p[0] = '\0';
        p++;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    if (getaddrinfo(addrstr, NULL, &hints, &res) != 0) {
        log_warn("ERROR: getaddrinfo '%s' failed", addrstr);
        goto out;
    }
    if ((res == NULL) || (res->ai_addr == NULL) ||
        ((res->ai_addr->sa_family != AF_INET) &&
         (res->ai_addr->sa_family != AF_INET6))) {
        log_warn("ERROR: bad addr '%s'", addrstr);
        goto out;
    }
    spec->sa_family = res->ai_addr->sa_family;
    if (spec->sa_family == AF_INET) {
        memcpy(spec->addr, &((struct sockaddr_in *)res->ai_addr)->sin_addr, 4);
    }
    else {
        memcpy(spec->addr, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
               16);
    }
    if (p == NULL) {
        prefix_len = (spec->sa_family == AF_INET) ? 32 : 128;
    }
    else {
        prefix_len = atoi(p);
        if ((prefix_len < 0) ||
            ((spec->sa_family == AF_INET) && (prefix_len > 32)) ||
            ((spec->sa_family == AF_INET6) && (prefix_len > 128))) {
            log_warn("ERROR: bad prefix %d", prefix_len);
            goto out;
        }
    }
    spec->prefix_len = prefix_len;
    ip6_make_mask(spec->mask, prefix_len);
    rc = 0;

 out:
    if (res != NULL) {
        freeaddrinfo(res);
    }
    return rc;
}

static int
ipaddr_spec_cmp(struct ipaddr_spec *spec, struct sockaddr *sa)
{
    if (spec->sa_family != sa->sa_family) {
        return -1;
    }
    if (spec->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)sa;
        return ip4_maskcmp(spec->addr, (uint32_t *)(&in->sin_addr),
                           spec->mask);
    }
    else {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;
        return ip6_maskcmp(spec->addr, (uint32_t *)(&in6->sin6_addr),
                           spec->mask);
    }
    return 0;
}

static void
ipaddr_spec_to_text(struct ipaddr_spec *spec, char *buf, int bufsize)
{
    union {
        struct sockaddr sa;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    } u;
    int rem_size;

    buf[0] = '\0';
    if ((bufsize == 0) || (spec->sa_family == 0)) {
        return;
    }
    memset(&u.in6, 0, sizeof(struct sockaddr_in6));
    u.sa.sa_family = spec->sa_family;
    if (spec->sa_family == AF_INET) {
        memcpy(&u.in.sin_addr, spec->addr, 4);
    }
    else {
        memcpy(&u.in6.sin6_addr, spec->addr, 16);
    }
    fileconf_sockaddr_to_text(&u.sa, buf, bufsize);
    rem_size = bufsize - strlen(buf);
    buf = &buf[strlen(buf)];
    snprintf(buf, rem_size, "/%d", spec->prefix_len);
}

static void
fileconf_print_pcap_interfaces(pcap_if_t *alldevs)
{
    char addrstr[64];
    pcap_if_t *d;
    struct pcap_addr *addr;

    log_warn("========== available pcap interfaces ==========");
    for (d = alldevs; d != NULL; d = d->next) {
        log_warn("   ifname=%s desc='%s'", d->name,
                 (d->description != NULL) ? d->description : "");
        for (addr = d->addresses; addr != NULL; addr = addr->next) {
            fileconf_sockaddr_to_text(addr->addr,
                                      addrstr, sizeof(addrstr));
            log_warn("       addr %s", addrstr);
        }
    }
    log_warn("===============================================");
}

static int
fileconf_select_ifname(struct active_pars *ap, char *ifname,
                       struct ipaddr_spec *ifaddr)
{
    static int have_printed_ifs;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    pcap_if_t *alldevs = NULL, *d;
    struct pcap_addr *addr;
    int rc = 1;

    errbuf[0] = '\0';

    if ((ifname == NULL) && (ifaddr->sa_family == 0)) {
        // no preselected interface
        rc = 0;
        goto out;
    }

    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        log_warn("ERROR: pcap_findalldevs: %s", errbuf);
        goto out;
    }
    for (d = alldevs; d != NULL; d = d->next) {
        int name_matches = 0;
        int ip_matches = 0;

        if ((ifname != NULL) && (strcmp(d->name, ifname) == 0)) {
            name_matches = 1;
        }
        for (addr = d->addresses; addr != NULL; addr = addr->next) {
            if ((addr->addr != NULL) && (ifaddr->sa_family != 0) &&
                (ipaddr_spec_cmp(ifaddr, addr->addr) == 0)) {
                ip_matches = 1;
            }
        }
        if (((ifname == NULL) || name_matches) &&
            ((ifaddr->sa_family == 0) || ip_matches)) {
            snprintf(ap->ifname, sizeof(ap->ifname), "%s", d->name);
            rc = 0;
            break;
        }
    }
    if (alldevs == NULL) {
        log_warn("ERROR: pcap_findalldevs returned no interfaces.");
        log_warn("ERROR: Please run rpcapd as administrator or root.");
    }
    else if (rc != 0) {
        char ifaddr_buf[100];
        ipaddr_spec_to_text(ifaddr, ifaddr_buf, sizeof(ifaddr_buf));
        log_warn("WARNING: Could not find interface with"
                 " ifname='%s' ifaddr='%s'.",
                 (ifname != NULL) ? ifname : "",
                 ifaddr_buf);
        if (!have_printed_ifs) {
            have_printed_ifs = 1;
            fileconf_print_pcap_interfaces(alldevs);
        }
    }
 out:
    if (alldevs != NULL) {
        pcap_freealldevs(alldevs);
    }
    return rc;
}

static int
fileconf_parse_activeclient_kv(struct active_pars *ap)
{
    static int printed_space_warning;
    struct ipaddr_spec ifaddr_spec;
    char *kv;
    char *key, *val;
    char *p;
    char *ifname = NULL;
    char *ifaddr = NULL;
    int rc = 0;

    ifaddr_spec.sa_family = 0;

    while ((kv = strtok(NULL, RPCAP_HOSTLIST_SEP)) != NULL) {
        key = kv;
        val = NULL;
        p = strchr(kv, '=');
        if (p != NULL) {
            p[0] = '\0';
            val = p + 1;
        }
        else if (!printed_space_warning) {
            printed_space_warning = 1;
            log_warn("WARNING: Make sure there are no spaces on"
                     " ActiveClient lines.");
        }
        if ((strcmp(key, "ifname") == 0) && (val != NULL) &&
            (strlen(val) > 0)) {
            ifname = val;
        }
        else if ((strcmp(key, "ifaddr") == 0) && (val != NULL) &&
                 (strlen(val) > 0)) {
            if (ipaddr_spec_parse(val, strlen(val), &ifaddr_spec) != 0) {
                ifaddr_spec.sa_family = 0;
                rc = -1;
            }
        }
        else {
           log_warn("WARNING: Could not parse ActiveClient option '%s'.", kv);
           if (rc == 0) {
               rc = -1;
           }
        }
    }
    if (rc == 0) {
        rc = fileconf_select_ifname(ap, ifname, &ifaddr_spec);
    }
    return rc;
}

void fileconf_read(int sign)
{
FILE *fp;
int i;

#ifndef WIN32
	signal(SIGHUP, fileconf_read);
#endif

	if ((fp= fopen(loadfile, "r") ) != NULL)
	{
	char line[MAX_LINE + 1];
	char linecopy[MAX_LINE + 1];
	char *ptr;
	int linenum = 0;

		hostlist[0]= 0;
		i= 0;

		while ( fgets(line, MAX_LINE, fp) != NULL )
		{
		    linenum++;
			if (line[0] == '\n') continue;	// Blank line
			if (line[0] == '\r') continue;	// Blank line
			if (line[0] == '#') continue;	// Comment

			if ( (ptr= strstr(line, "ActiveClient")) )
			{
			char *address, *port;

			    // copy the line since strtok will add nulls
			    strcpy(linecopy, line);
			    if (strlen(linecopy) > 0) {
			        // remove trailing '\n'
			        linecopy[strlen(linecopy) - 1] = '\0';
			    }

				ptr= strchr(ptr, '=') + 1;
				address= strtok(ptr, RPCAP_HOSTLIST_SEP);

				if ( (address != NULL) && (i < MAX_ACTIVE_LIST) )
				{
					port = strtok(NULL, RPCAP_HOSTLIST_SEP);
					snprintf(activelist[i].address, MAX_LINE, "%s", address);

					if (strcmp(port, "DEFAULT") == 0) // the user choose a custom port
						snprintf(activelist[i].port, MAX_LINE, RPCAP_DEFAULT_NETPORT_ACTIVE);
					else
						snprintf(activelist[i].port, MAX_LINE, "%s", port);

					if (port != NULL) {
					    int rc = fileconf_parse_activeclient_kv(&activelist[i]);
					    if (rc != 0) {
					        log_warn("    %s line %d:", loadfile, linenum);
					        log_warn("        %s", linecopy);
					    }
					}

					activelist[i].address[MAX_LINE] = 0;
					activelist[i].port[MAX_LINE] = 0;
				}
				else
					log_warn("Only MAX_ACTIVE_LIST active connections are currently supported.");

				i++;
				continue;
			}

			if ( (ptr= strstr(line, "PassiveClient")) )
			{
				ptr= strchr(ptr, '=') + 1;
				strncat(hostlist, ptr, MAX_HOST_LIST);
				strncat(hostlist, ",", MAX_HOST_LIST);
				continue;
			}

			if ( (ptr= strstr(line, "NullAuthPermit")) )
			{
				ptr= strstr(ptr, "YES");
				if (ptr)
					nullAuthAllowed= 1;
				else
					nullAuthAllowed= 0;
				continue;
			}
		}

		// clear the remaining fields of the active list 
		while (i < MAX_ACTIVE_LIST)
		{
			activelist[i].address[0] = 0;
			activelist[i].port[0] = 0;
			i++;
		}

		// Remove all '\n' and '\r' from the strings
		strrem(hostlist, '\r');
		strrem(hostlist, '\n');

		//log_info("New passive host list: %s\n\n", hostlist);
		fclose(fp);
	}
}



int fileconf_save(const char *savefile)
{
FILE *fp;

	if ((fp= fopen(savefile, "w") ) != NULL)
	{
	char *token; /*, *port;*/					// temp, needed to separate items into the hostlist
	char temphostlist[MAX_HOST_LIST + 1];
	int i= 0;

		fprintf(fp, "# Configuration file help.\n\n");

		// Save list of clients which are allowed to connect to us in passive mode
		fprintf(fp, "# Hosts which are allowed to connect to this server (passive mode)\n");
		fprintf(fp, "# Format: PassiveClient = <name or address>\n\n");

		strncpy(temphostlist, hostlist, MAX_HOST_LIST);
		temphostlist[MAX_HOST_LIST]= 0;
	
		token= strtok(temphostlist, RPCAP_HOSTLIST_SEP);
		while( token != NULL )
		{
			fprintf(fp, "PassiveClient = %s\n", token);
			token = strtok(NULL, RPCAP_HOSTLIST_SEP);
		}


		// Save list of clients which are allowed to connect to us in active mode
		fprintf(fp, "\n\n");
		fprintf(fp, "# Hosts to which this server is trying to connect to (active mode)\n");
		fprintf(fp, "# Format: ActiveClient = <name or address>, <port | DEFAULT>\n\n");


		while ( (activelist[i].address[0] != 0) && (i < MAX_ACTIVE_LIST) )
		{
			fprintf(fp, "ActiveClient = %s, %s\n", activelist[i].address, activelist[i].port);
			i++;
		}

		// Save if we want to permit NULL authentication
		fprintf(fp, "\n\n");
		fprintf(fp, "# Permit NULL authentication: YES or NOT\n\n");

		if (nullAuthAllowed)
			fprintf(fp, "NullAuthPermit = YES\n");
		else
			fprintf(fp, "NullAuthPermit = NO\n");

		fclose(fp);
		return 0;
	}
	else
	{
		return -1;
	}

}



int strrem(char *string, char chr)
{
char *pos;
int num= 0;
int len, i;

	while ( (pos= strchr(string, chr) ) != NULL)
	{
		num++;
		len= strlen(pos);
		for (i=0; i<len; i++)
			pos[i]= pos[i+1];
	}

	return num;
}
