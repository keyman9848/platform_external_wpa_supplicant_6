/*
 * WPA Supplicant - wired Ethernet driver interface
 * Copyright (c) 2005-2007, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"
#include <sys/ioctl.h>
#include <net/if.h>
#ifdef __linux__
#include <netpacket/packet.h>
#endif /* __linux__ */
#if defined(__FreeBSD__) || defined(__DragonFly__)
#include <net/if_dl.h>
#endif /* defined(__FreeBSD__) || defined(__DragonFly__) */

#include "common.h"
#include "driver.h"
#include "common/ieee802_11_defs.h"

#define DRIVER_CONFIG_FAKE_SSID "WiredSSID"

static const u8 pae_group_addr[ETH_ALEN] =
{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };


struct wpa_driver_wired_data {
	void *ctx;
	int pf_sock;
	char ifname[IFNAMSIZ + 1];
	int membership, multi, iff_allmulti, iff_up;

        int associated;
};


static int wpa_driver_wired_get_ssid(void *priv, u8 *ssid)
{
        strcpy(ssid, DRIVER_CONFIG_FAKE_SSID);
	return 0;
}


static int wpa_driver_wired_get_bssid(void *priv, u8 *bssid)
{
	/* Report PAE group address as the "BSSID" for wired connection. */
	os_memcpy(bssid, pae_group_addr, ETH_ALEN);
	return 0;
}


static int wpa_driver_wired_get_ifflags(const char *ifname, int *flags)
{
	struct ifreq ifr;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(s, SIOCGIFFLAGS, (caddr_t) &ifr) < 0) {
		perror("ioctl[SIOCGIFFLAGS]");
		close(s);
		return -1;
	}
	close(s);
	*flags = ifr.ifr_flags & 0xffff;
	return 0;
}


static int wpa_driver_wired_set_ifflags(const char *ifname, int flags)
{
	struct ifreq ifr;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags = flags & 0xffff;
	if (ioctl(s, SIOCSIFFLAGS, (caddr_t) &ifr) < 0) {
		perror("ioctl[SIOCSIFFLAGS]");
		close(s);
		return -1;
	}
	close(s);
	return 0;
}


static int wpa_driver_wired_multi(const char *ifname, const u8 *addr, int add)
{
	struct ifreq ifr;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
#ifdef __linux__
	ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
	os_memcpy(ifr.ifr_hwaddr.sa_data, addr, ETH_ALEN);
#endif /* __linux__ */
#if defined(__FreeBSD__) || defined(__DragonFly__)
	{
		struct sockaddr_dl *dlp;
		dlp = (struct sockaddr_dl *) &ifr.ifr_addr;
		dlp->sdl_len = sizeof(struct sockaddr_dl);
		dlp->sdl_family = AF_LINK;
		dlp->sdl_index = 0;
		dlp->sdl_nlen = 0;
		dlp->sdl_alen = ETH_ALEN;
		dlp->sdl_slen = 0;
		os_memcpy(LLADDR(dlp), addr, ETH_ALEN); 
	}
#endif /* defined(__FreeBSD__) || defined(__DragonFly__) */
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	{
		struct sockaddr *sap;
		sap = (struct sockaddr *) &ifr.ifr_addr;
		sap->sa_len = sizeof(struct sockaddr);
		sap->sa_family = AF_UNSPEC;
		os_memcpy(sap->sa_data, addr, ETH_ALEN);
	}
#endif /* defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__) */

	if (ioctl(s, add ? SIOCADDMULTI : SIOCDELMULTI, (caddr_t) &ifr) < 0) {
		perror("ioctl[SIOC{ADD/DEL}MULTI]");
		close(s);
		return -1;
	}
	close(s);
	return 0;
}


static int wpa_driver_wired_membership(struct wpa_driver_wired_data *drv,
				       const u8 *addr, int add)
{
#ifdef __linux__
	struct packet_mreq mreq;

	if (drv->pf_sock == -1)
		return -1;

	os_memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = if_nametoindex(drv->ifname);
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETH_ALEN;
	os_memcpy(mreq.mr_address, addr, ETH_ALEN);

	if (setsockopt(drv->pf_sock, SOL_PACKET,
		       add ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP,
		       &mreq, sizeof(mreq)) < 0) {
		perror("setsockopt");
		return -1;
	}
	return 0;
#else /* __linux__ */
	return -1;
#endif /* __linux__ */
}


static void * wpa_driver_wired_init(void *ctx, const char *ifname)
{
	struct wpa_driver_wired_data *drv;
	int flags;

	drv = os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;
	os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));
	drv->ctx = ctx;

#ifdef __linux__
	drv->pf_sock = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (drv->pf_sock < 0)
		perror("socket(PF_PACKET)");
#else /* __linux__ */
	drv->pf_sock = -1;       
#endif /* __linux__ */
	
	if (wpa_driver_wired_get_ifflags(ifname, &flags) == 0 &&
	    !(flags & IFF_UP) &&
	    wpa_driver_wired_set_ifflags(ifname, flags | IFF_UP) == 0) {
		drv->iff_up = 1;
	}

	if (wpa_driver_wired_membership(drv, pae_group_addr, 1) == 0) {
		wpa_printf(MSG_DEBUG, "%s: Added multicast membership with "
			   "packet socket", __func__);
		drv->membership = 1;
	} else if (wpa_driver_wired_multi(ifname, pae_group_addr, 1) == 0) {
		wpa_printf(MSG_DEBUG, "%s: Added multicast membership with "
			   "SIOCADDMULTI", __func__);
		drv->multi = 1;
	} else if (wpa_driver_wired_get_ifflags(ifname, &flags) < 0) {
		wpa_printf(MSG_INFO, "%s: Could not get interface "
			   "flags", __func__);
		os_free(drv);
		return NULL;
	} else if (flags & IFF_ALLMULTI) {
		wpa_printf(MSG_DEBUG, "%s: Interface is already configured "
			   "for multicast", __func__);
	} else if (wpa_driver_wired_set_ifflags(ifname,
						flags | IFF_ALLMULTI) < 0) {
		wpa_printf(MSG_INFO, "%s: Failed to enable allmulti",
			   __func__);
		os_free(drv);
		return NULL;
	} else {
		wpa_printf(MSG_DEBUG, "%s: Enabled allmulti mode",
			   __func__);
		drv->iff_allmulti = 1;
	}

        drv->associated = 0;

	return drv;
}


static void wpa_driver_wired_deinit(void *priv)
{
	struct wpa_driver_wired_data *drv = priv;
	int flags;

	if (drv->membership &&
	    wpa_driver_wired_membership(drv, pae_group_addr, 0) < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to remove PAE multicast "
			   "group (PACKET)", __func__);
	}

	if (drv->multi &&
	    wpa_driver_wired_multi(drv->ifname, pae_group_addr, 0) < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to remove PAE multicast "
			   "group (SIOCDELMULTI)", __func__);
	}

	if (drv->iff_allmulti &&
	    (wpa_driver_wired_get_ifflags(drv->ifname, &flags) < 0 ||
	     wpa_driver_wired_set_ifflags(drv->ifname,
					  flags & ~IFF_ALLMULTI) < 0)) {
		wpa_printf(MSG_DEBUG, "%s: Failed to disable allmulti mode",
			   __func__);
	}

	if (drv->iff_up &&
	    wpa_driver_wired_get_ifflags(drv->ifname, &flags) == 0 &&
	    (flags & IFF_UP) &&
	    wpa_driver_wired_set_ifflags(drv->ifname, flags & ~IFF_UP) < 0) {
		wpa_printf(MSG_DEBUG, "%s: Failed to set the interface down",
			   __func__);
	}

	if (drv->pf_sock != -1)
		close(drv->pf_sock);
	
	os_free(drv);
}

static int wpa_driver_wired_scan(void *priv,
                               struct wpa_driver_scan_params *params)
{
       struct wpa_driver_wired_data *drv = priv;

       wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS, NULL);

       return 0;
}

static struct wpa_scan_results * wpa_driver_wired_get_scan_results(void *priv)
{
       struct wpa_scan_results *res;
       struct wpa_scan_res *r;

       res = os_zalloc(sizeof(*res));
       if (res == NULL)
               return NULL;

       res->res = os_zalloc(1 * sizeof(struct wpa_scan_res *));
       if (res->res == NULL) {
               os_free(res);
               return NULL;
       }

       r = os_malloc(sizeof(*r) + 2 + strlen(DRIVER_CONFIG_FAKE_SSID));
       os_memset(r, 0, sizeof(*r));
       os_memcpy(r->bssid, pae_group_addr, ETH_ALEN);
       r->freq = 2412;
       r->beacon_int = 0;
       r->caps = 0;
       r->qual = 0;
       r->noise = 0;
       r->level = -55;
       r->tsf = 0;
       r->ie_len = 2+strlen(DRIVER_CONFIG_FAKE_SSID);
       char *p = (char *)(r+1);
       *p++ = (char)WLAN_EID_SSID;
       *p++ = (char)strlen(DRIVER_CONFIG_FAKE_SSID);
       memcpy(p, DRIVER_CONFIG_FAKE_SSID, strlen(DRIVER_CONFIG_FAKE_SSID));
       p += strlen(DRIVER_CONFIG_FAKE_SSID);
       res->res[0] = r;
       res->num = 1;

       return res;
}

static int wpa_driver_wired_associate(
       void *priv, struct wpa_driver_associate_params *params)
{
       struct wpa_driver_wired_data *drv = priv;

       drv->associated = 1;
       wpa_supplicant_event(drv->ctx, EVENT_ASSOC, NULL);

       return 0;
}

static int wpa_driver_wired_disassociate(void *priv, const u8 *addr,
                                       int reason_code)
{
       struct wpa_driver_wired_data *drv = priv;

       drv->associated = 0;
       wpa_supplicant_event(drv->ctx, EVENT_DISASSOC, NULL);

       return 0;
}

static int wpa_driver_wired_get_capa(void *priv, struct wpa_driver_capa *capa)
{
       struct wpa_driver_wired_data *drv = priv;

       os_memset(capa, 0, sizeof(*capa));
       capa->key_mgmt = WPA_DRIVER_CAPA_KEY_MGMT_WPA |
               WPA_DRIVER_CAPA_KEY_MGMT_WPA_NONE;
       capa->enc = 0;
       capa->auth = WPA_DRIVER_AUTH_OPEN;

       return 0;
}

const struct wpa_driver_ops wpa_driver_wired_ops = {
	.name = "wired",
	.desc = "wpa_supplicant wired Ethernet driver",
	.get_ssid = wpa_driver_wired_get_ssid,
	.get_bssid = wpa_driver_wired_get_bssid,
	.init = wpa_driver_wired_init,
	.deinit = wpa_driver_wired_deinit,
        .scan = wpa_driver_wired_scan,
        .get_scan_results = wpa_driver_wired_get_scan_results,
        .disassociate = wpa_driver_wired_disassociate,
        .associate = wpa_driver_wired_associate,
        .get_capa = wpa_driver_wired_get_capa,
};
