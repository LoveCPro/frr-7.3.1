#include <zebra.h>
#include <arpa/inet.h>
#include <lib/srcdest_table.h>

#include "command.h"
#include "linklist.h"
#include "lib/memory.h"
#include "prefix.h"
#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "zclient.h"
#include "vty.h"
#include "table.h"
#include "bfd.h"
#include "static_bfd.h"
#include "static_zebra.h"
#include "static_memory.h"
#include "static_vrf.h"

#include "staticd/static_routes.h"

extern struct zclient *zclient;
extern struct thread_master *master;
/** Global empty address for IPv4/IPv6. */
const struct in6_addr i6a_zero;

static bool _bfd_session_params_valid(const struct bfd_session_params *bsp)
{
	/* Peer/local address not configured. */
	if (bsp->bsp_args.family == 0)
		return false;

	/* Address configured but invalid. */
	if (bsp->bsp_args.family != AF_INET
			&& bsp->bsp_args.family != AF_INET6) {
		zlog_warn("%s: invalid session family: %d", __func__,
				bsp->bsp_args.family);
		return false;
	}

	/* Multi hop requires local address. */
	if (bsp->bsp_args.mhop
		&& memcmp(&i6a_zero, &bsp->bsp_args.src, sizeof(i6a_zero)) == 0) {
			zlog_warn("%s: asked multi hop, but no local address provided",
				__func__);
			return false;
	}

	/* Check VRF ID. */
	if (bsp->bsp_args.vrf_id == VRF_UNKNOWN) {
		zlog_warn("%s: asked for unknown VRF", __func__);
		return false;
	}

	return true;
}



static struct bfd_session_params *bfd_session_params_new(bsp_status_update updatecb,
						struct route_node *rn, struct static_route *si, safi_t safi)
{
	struct bfd_session_params *bsp;

	bsp = XCALLOC(MTYPE_STATIC_ROUTE, sizeof(*bsp));

	/* Save application data. */
	bsp->bsp_updatecb = updatecb;
	bsp->rn =  rn;
	bsp->si = si;
	bsp->safi = safi;

	bsp->bsp_args.vrf_id = VRF_DEFAULT;
	if (!bsp->bsp_args.bfd_info)
		bsp->bsp_args.bfd_info = bfd_info_create();

	bsp->bsp_args.bfd_info->detect_mult = BFD_DEF_DETECT_MULT;
	bsp->bsp_args.bfd_info->desired_min_tx = BFD_DEF_MIN_TX;
	bsp->bsp_args.bfd_info->required_min_rx = BFD_DEF_MIN_RX;

	/* Register in global list. */
	TAILQ_INSERT_TAIL(&bsglobal.bsg_bsplist, bsp, bsp_entry);
	return bsp;
}

static int _bfd_session_params_send(struct thread *t)
{
	struct bfd_session_params *bsp = THREAD_ARG(t);

	/* Validate configuration before trying to send bogus data. */
	if (!_bfd_session_params_valid(bsp))
		return 0;

	if (bsp->bsp_lastev == BSE_INSTALL) {
		bsp->bsp_args.command = bsp->bsp_installed
				? ZEBRA_BFD_DEST_UPDATE
				: ZEBRA_BFD_DEST_REGISTER;
	} else
		bsp->bsp_args.command = ZEBRA_BFD_DEST_DEREGISTER;

	/* If not installed and asked for uninstall, do nothing. */
	if (!bsp->bsp_installed
		&& bsp->bsp_args.command == ZEBRA_BFD_DEST_DEREGISTER)
		return 0;

	zlog_info("static route bsp mhop:%d", bsp->bsp_args.mhop);
	bfd_peer_sendmsg(zclient, bsp->bsp_args.bfd_info, AF_INET, &bsp->bsp_args.dst,
		&bsp->bsp_args.src, bsp->bsp_args.ifname,0, bsp->bsp_args.mhop, bsp->bsp_args.cbit,bsp->bsp_args.command ,0, bsp->bsp_args.vrf_id);
	/* Command was sent successfully. */

	if (bsp->bsp_args.command == ZEBRA_BFD_DEST_DEREGISTER)
		bsp->bsp_installed = false;
	else if (bsp->bsp_args.command == ZEBRA_BFD_DEST_REGISTER)
		bsp->bsp_installed = true;

	return 0;
}

static void bfd_session_params_install(struct bfd_session_params *bsp)
{

	/* Don't attempt to install/update when disabled. */
	if (!bsp->bsp_enabled)
		return;
	bsp->bsp_lastev = BSE_INSTALL;
	thread_add_event(bsglobal.bsg_tm, _bfd_session_params_send, bsp, 0,
			 &bsp->bsp_installev);
}

static void _bfd_session_remove(struct bfd_session_params *bsp)
{
	/* Not installed, nothing to do. */
	if (!bsp->bsp_installed)
		return;

	/* Cancel any pending installation request. */
	THREAD_OFF(bsp->bsp_installev);

	/* Send request to remove any session. */
	bsp->bsp_lastev = BSE_UNINSTALL;
	thread_execute(bsglobal.bsg_tm, _bfd_session_params_send, bsp, 0);
}

/*
 * Next hop BFD monitoring settings.
 */
static void static_next_hop_bfd_change(const struct bfd_session_status *bss, struct route_node *rn,
						struct static_route *si, safi_t safi)
{
	switch (bss->bss_state) {
	case BSS_UNKNOWN:
		/* FALLTHROUGH: no known state yet. */
	case BSS_ADMIN_DOWN:
		/* NOTHING: we or the remote end administratively shutdown. */
		break;
	case BSS_DOWN:
		/* Peer went down, remove this next hop. */
		zlog_info("%s: next hop is down, remove it from RIB", __func__);
		static_zebra_route_add(rn, si, si->vrf_id, safi, false);
		break;
	case BSS_UP:
		zlog_info("%s: next hop is up, add it to RIB", __func__);
		struct static_route *si2;
		si2 = rn->info;
		if (si2)
			static_zebra_route_add(rn, si, si2->vrf_id, safi, true);
		/* Peer is back up, add this next hop. */
		break;
	}
}

static void static_next_hop_bfd_updatecb(
	__attribute__((unused)) const struct bfd_session_status *bss, struct route_node *rn,
						struct static_route *si, safi_t safi)
{
	static_next_hop_bfd_change(bss, rn, si, safi);
}
//when bfd enable
void static_next_hop_bfd_monitor_enable(afi_t afi, safi_t safi, uint8_t type, struct prefix *p,
		     struct prefix_ipv6 *src_p, union g_addr *gatep,
		     const char *ifname, route_tag_t tag, struct static_vrf *svrf,
		     struct static_nh_label *snh_label, uint32_t table_id, int  mhop, union g_addr *bfd_dst, union g_addr *bfd_src, uint8_t bfd_type)
{
	zlog_info("static_bfd: dst:%s, func=%s", inet_ntoa(gatep->ipv4), __func__);
	int family;
	struct bfd_session_params *bsp = NULL;
	struct route_node *rn;
	struct static_route *si;
	struct route_table *stable;

	
	switch (type) {
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:

		/* FALLTHROUGH */
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		if (type == STATIC_IPV4_GATEWAY
		    || type == STATIC_IPV4_GATEWAY_IFNAME)
			family = AF_INET;
		else
			family = AF_INET6;
		break;

	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
	default:
		zlog_err("%s: invalid next hop type", __func__);
		return;
	}

	/* Lookup table.  */
	stable = static_vrf_static_table(afi, safi, svrf);
	if (!stable)
		return ;

	/* Lookup static route prefix. */
	rn = srcdest_rnode_lookup(stable, p, src_p);
	if (!rn)
		return ;

	/* Find same static route is the tree */
	for (si = rn->info; si; si = si->next)
		if (type == si->type
			&& (!gatep
			|| ((afi == AFI_IP
				 && IPV4_ADDR_SAME(&gatep->ipv4, &si->addr.ipv4))
				|| (afi == AFI_IP6
				&& IPV6_ADDR_SAME(gatep, &si->addr.ipv6))))
			&& (!strcmp(ifname ? ifname : "", si->ifname))
			&& (!tag || (tag == si->tag))
			&& (table_id == si->table_id)
			&& (!snh_label->num_labels
			|| !memcmp(&si->snh_label, snh_label,
				   sizeof(struct static_nh_label))))
			break;
	
	/* Can't find static route. */
	if (!si) {
		route_unlock_node(rn);
		zlog_info("func = %s, can't find static route", __func__);
		return ;
	}

	/* Reconfigure or allocate new memory. */
	if (bsp == NULL)
		bsp = bfd_session_params_new(static_next_hop_bfd_updatecb,
						 rn , si, safi);

	/* Configure the session. TODO source address.*/
	if (family == AF_INET){
		_bfd_session_remove(bsp);
		bsp->bsp_args.family = AF_INET;
		if(bfd_type == STATIC_BFD_MHOP_DEST_SRC){
			memcpy(&bsp->bsp_args.dst, &bfd_dst->ipv4, sizeof(struct in_addr));
		}else{
			memcpy(&bsp->bsp_args.dst, &gatep->ipv4, sizeof(struct in_addr));
		}
		if(mhop && (bfd_type == STATIC_BFD_MHOP_SRC || bfd_type == STATIC_BFD_MHOP_DEST_SRC) ){
			memcpy(&bsp->bsp_args.src, &bfd_src->ipv4, sizeof(struct in_addr));
		}
	}

	/* If already installed, remove the old setting. */
	_bfd_session_remove(bsp);
	if (ifname == NULL) {
		bsp->bsp_args.ifname = NULL;
		bsp->bsp_args.ifnamelen = 0;

	}else{
		bsp->bsp_args.ifname = strdup(ifname);
		bsp->bsp_args.ifnamelen = strlen(bsp->bsp_args.ifname);
	}
	if(mhop){
		bsp->bsp_args.mhop = mhop;
		zlog_info("static_bfd: dst:%s, src:%s", inet_ntoa(gatep->ipv4), inet_ntoa(bfd_src->ipv4));
	}

	bsp->bsp_enabled = true;

	/* Install or update the session. */
	bfd_session_params_install(bsp);
}

void static_next_hop_bfd_monitor_disable( uint8_t type,
		     struct prefix_ipv6 *src_p, union g_addr *gatep,
		     const char *ifname, uint32_t vrf_id)
{
	uint32_t family;
	//get family
	switch (type) {
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:

		/* FALLTHROUGH */
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		if (type == STATIC_IPV4_GATEWAY
		    || type == STATIC_IPV4_GATEWAY_IFNAME)
			family = AF_INET;
		else
			family = AF_INET6;
		break;

	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
	default:
		zlog_err("%s: invalid next hop type", __func__);
		return;
	}

	size_t addrlen = 0;
	switch (family) {
	case AF_INET:
		addrlen = sizeof(struct in_addr);
		break;
	case AF_INET6:
		addrlen = sizeof(struct in6_addr);
		break;

	default:
		/* Unexpected value. */
		assert(0);
		break;
	}

	//del bfd param
	struct bfd_session_params *bsp;

	TAILQ_FOREACH (bsp, &bsglobal.bsg_bsplist, bsp_entry) {

		//vrf id
		if (bsp->bsp_args.vrf_id != vrf_id){
			continue;
		}
		/* Skip different families. */
		if (bsp->bsp_args.family != family){
			continue;
		}

		/* Skip different interface. */
		if (bsp->bsp_args.ifnamelen && ifname
		    && strcmp(bsp->bsp_args.ifname, ifname) != 0){
			continue;
		}else if((bsp->bsp_args.ifnamelen == 0) && (ifname != NULL)){
			continue;
		}else if(bsp->bsp_args.ifnamelen  && (ifname == NULL)){
			continue;
		}

		/* Skip non matching destination addresses. */
		if (memcmp(&bsp->bsp_args.dst, gatep, addrlen) != 0){
			continue;
		}
		/* If source was provided, check with our configuration. */

		_bfd_session_remove(bsp);
		/* Remove from global list. */
		TAILQ_REMOVE(&bsglobal.bsg_bsplist, bsp, bsp_entry);
		/* Free the memory and point to NULL. */
		route_unlock_node(bsp->rn);
		if(bsp){
			free(bsp);
		}
	}
}


static int static_bfd_interface_dest_update(ZAPI_CALLBACK_ARGS)
{
	struct bfd_session_params *bsp;
	size_t sessions_updated = 0;
	struct interface *ifp;
	int remote_cbit = false;
	int status = BFD_STATUS_UNKNOWN;
	size_t addrlen;
	struct prefix dp;
	struct prefix sp;
	char ifstr[128], cbitstr[32];

	ifp = bfd_get_peer_info(zclient->ibuf, &dp, &sp, &status, &remote_cbit,
				vrf_id);

	if (bsglobal.bsg_debugging) {
		ifstr[0] = 0;
		if (ifp)
			snprintf(ifstr, sizeof(ifstr), " (interface %s)",
				 ifp->name);

		snprintf(cbitstr, sizeof(cbitstr), " (CPI bit %s)",
			 remote_cbit ? "yes" : "no");

		zlog_debug("%s: %pFX -> %pFX%s VRF %s(%u)%s: %s", __func__, &sp,
			   &dp, ifstr, vrf_id_to_name(vrf_id), vrf_id, cbitstr,
			   bfd_get_status_str(status));
	}

	switch (dp.family) {
	case AF_INET:
		addrlen = sizeof(struct in_addr);
		break;
	case AF_INET6:
		addrlen = sizeof(struct in6_addr);
		break;

	default:
		/* Unexpected value. */
		assert(0);
		break;
	}

	/* Notify all matching sessions about update. */
	TAILQ_FOREACH (bsp, &bsglobal.bsg_bsplist, bsp_entry) {
		/* Skip different VRFs. */
		if (bsp->bsp_args.vrf_id != vrf_id){
				continue;
			}
		/* Skip different families. */
		if (bsp->bsp_args.family != dp.family){
			continue;
		}
		/* Skip different interface. */
		if (bsp->bsp_args.ifnamelen && ifp
		    && strcmp(bsp->bsp_args.ifname, ifp->name) != 0){
			continue;
		}
		/* Skip non matching destination addresses. */
		if (memcmp(&bsp->bsp_args.dst, &dp.u, addrlen) != 0){
			continue;
		}
		/* If source was provided, check with our configuration. */
		if (sp.family
		    && memcmp(&bsp->bsp_args.src, &i6a_zero, addrlen) != 0
		    && memcmp(&bsp->bsp_args.src, &sp.u, addrlen) != 0){
			continue;
		   }

		bsp->bsp_bss.bss_state = status;
		bsp->bsp_bss.bss_remote_cbit = remote_cbit;
		bsp->bsp_updatecb(&bsp->bsp_bss, bsp->rn, bsp->si, bsp->safi);
		sessions_updated++;
	}

	if (bsglobal.bsg_debugging)
		zlog_debug("%s:   sessions updated: %zu", __func__,
			   sessions_updated);
	return 0;
}

/**
 * Callback for reinstallation of all registered BFD sessions.
 *
 * Use this as `zclient` `bfd_dest_replay` callback.
 */
static int static_bfd_nbr_replay(ZAPI_CALLBACK_ARGS)
{
	struct bfd_session_params *bsp;

	if (bsglobal.bsg_debugging)
		zlog_debug("%s: sending all sessions registered", __func__);

	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, vrf_id);

	/* Replay all activated peers. */
	TAILQ_FOREACH (bsp, &bsglobal.bsg_bsplist, bsp_entry) {
		/* Skip disabled sessions. */
		if (!bsp->bsp_enabled)
			continue;

		/* We are reconnecting, so we must send installation. */
		bsp->bsp_installed = false;

		/* Cancel any pending installation request. */
		THREAD_OFF(bsp->bsp_installev);

		/* Ask for installation. */
		bsp->bsp_lastev = BSE_INSTALL;
		thread_execute(bsglobal.bsg_tm, _bfd_session_params_send, bsp,0);
	}
	return 0;
}


void static_bfd_init(void){
	/* Initialize data structure. */
	TAILQ_INIT(&bsglobal.bsg_bsplist);

	/* Set default debug state. */
	bsglobal.bsg_debugging = false;

	/* Copy pointers. */
	bsglobal.bsg_zc = zclient;
	bsglobal.bsg_tm = master;

	/* Install our callbacks. */
	zclient->interface_bfd_dest_update = static_bfd_interface_dest_update;
	zclient->bfd_dest_replay = static_bfd_nbr_replay;

	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, VRF_DEFAULT);
}




