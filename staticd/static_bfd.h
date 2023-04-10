#ifndef _STATIC_BFD_H
#define _STATIC_BFD_H

#include "lib/zclient.h"
#include "lib/bfd.h"
#include "staticd/static_routes.h"
#include <zebra.h>
#include <arpa/inet.h>

#include "command.h"
#include "linklist.h"
#include "lib/memory.h"
#include "prefix.h"
#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "vty.h"
#include "table.h"
#include "static_memory.h"
#include "static_vrf.h"
/*
 * BFD new API.
 */

/* Forward declaration of argument struct. */
struct bfd_session_params;

/** Session state definitions. */
enum bfd_session_state {
	/** Session state is unknown or not initialized. */
	BSS_UNKNOWN = BFD_STATUS_UNKNOWN,
	/** Local or remote peer administratively shutdown the session. */
	BSS_ADMIN_DOWN = BFD_STATUS_ADMIN_DOWN,
	/** Session is down. */
	BSS_DOWN = BFD_STATUS_DOWN,
	/** Session is up and working correctly. */
	BSS_UP = BFD_STATUS_UP,
};

/** BFD session status information */
struct bfd_session_status {
	/** Current session state. */
	enum bfd_session_state bss_state;
	/** Remote Control Plane Independent bit state. */
	bool bss_remote_cbit;
};


/**
 * Session status update callback.
 *
 * \param bsp BFD session parameters.
 * \param bss BFD session status.
 * \param arg application independent data.
 */
typedef void (*bsp_status_update)(const struct bfd_session_status *bss,
				  struct route_node *rn, struct static_route *si, safi_t safi);


/**
* BFD protocol integration configuration.
 */

/** Events definitions. */
enum bfd_session_event {
	/** Remove the BFD session configuration. */
	BSE_UNINSTALL,
	/** Install the BFD session configuration. */
	BSE_INSTALL,
};

/**
	* BFD session registration arguments.
*/
struct bfd_session_arg {
	/**
	 * BFD command.
	 *
		 * Valid commands:
		 * - `ZEBRA_BFD_DEST_REGISTER`
		 * - `ZEBRA_BFD_DEST_DEREGISTER`
		 */
	int32_t command;
	/**
	 * BFD family type.
	 *
	 * Supported types:
	 * - `AF_INET`
	 * - `AF_INET6`.
	 */
	uint32_t family;
	/** Source address. */
	struct in6_addr src;
	/** Source address. */
	struct in6_addr dst;

	/** Multi hop indicator. */
	uint8_t mhop;
	/** Expected TTL. */
	uint8_t ttl;
	/** C bit (Control Plane Independent bit) indicator. */
	uint8_t cbit;

	/** Interface name size. */
	uint8_t ifnamelen;
	/** Interface name. */
	char * ifname;

	/** Daemon or session VRF. */
	vrf_id_t vrf_id;

	/** Profile name length. */
	uint8_t profilelen;
	/** Profile name. */
	char profile[32];


	/** BFD client information output. */
	struct bfd_info *bfd_info;

	/** Write registration indicator. */
	uint8_t set_flag;
};


/**
 * Data structure to do the necessary tricks to hide the BFD protocol
 * integration internals.
 */
struct bfd_session_params {
	/** Contains the session parameters and more. */
	struct bfd_session_arg bsp_args;
	/** Contains the session state. */
	struct bfd_session_status bsp_bss;
	/** Protocol implementation status update callback. */
	bsp_status_update bsp_updatecb;

	struct route_node *rn;
	struct static_route *si;
	safi_t safi;

	/**
	 * Next event.
	 *
	 * This variable controls what action to execute when the command batch
	 * finishes. Normally we'd use `thread_add_event` value, however since
	 * that function is going to be called multiple times and the value
	 * might be different we'll use this variable to keep track of it.
	 */
	enum bfd_session_event bsp_lastev;
	/**
	 * BFD session configuration event.
	 *
	 * Multiple actions might be asked during a command batch (either via
	 * configuration load or northbound batch), so we'll use this to
	 * install/uninstall the BFD session parameters only once.
	 */
	struct thread *bsp_installev;

	/** BFD session installation state. */
	bool bsp_installed;
	/** BFD session enabled. */
	bool bsp_enabled;

	/** Global BFD paramaters list. */
	TAILQ_ENTRY(bfd_session_params) bsp_entry;
};
struct bfd_sessions_global {
	/**
	 * Global BFD session parameters list for (re)installation and update
	 * without code duplication among daemons.
	 */
	TAILQ_HEAD(bsplist, bfd_session_params) bsg_bsplist;

	/** Pointer to FRR's event manager. */
	struct thread_master *bsg_tm;
	/** Pointer to zebra client data structure. */
	struct zclient *bsg_zc;

	/** Debugging state. */
	bool bsg_debugging;
};

/** Global configuration variable. */
 struct bfd_sessions_global bsglobal;


 void static_next_hop_bfd_monitor_enable(afi_t afi, safi_t safi, uint8_t type, struct prefix *p,
				  struct prefix_ipv6 *src_p, union g_addr *gatep,
				  const char *ifname, route_tag_t tag, struct static_vrf *svrf,
				  struct static_nh_label *snh_label, uint32_t table_id, int mhop, union g_addr *bfd_dst, union g_addr *bfd_src, uint8_t bfd_type);


 void static_next_hop_bfd_monitor_disable( uint8_t type,
			  struct prefix_ipv6 *src_p, union g_addr *gatep,
			  const char *ifname, uint32_t vrf_id);


 void static_bfd_init(void);

#endif

