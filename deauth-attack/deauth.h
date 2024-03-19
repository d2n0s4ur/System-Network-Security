#ifndef DEAUTH_ATTACK_H
# define DEAUTH_ATTACK_H

# include <stdio.h>
# include "mac.h"
# include <pcap.h>
# include <arpa/inet.h>
# include "radiotaphdr.h"
# include "dot11hdr.h"
# include <unistd.h>

# define DEAUTH_TRY_COUNT	1000
# define AUTH_TRY_COUNT		1000

struct DeAuthPacket final {
	RadioTapHdr	radiotap_hdr_;
	Dot11Hdr	dot11_hdr_;
	u_int16_t	reason_code_;
};

struct AuthPacket final {
	ExtendedRadioTapHdr	radiotap_hdr_;
	Dot11Hdr			dot11_hdr_;
	u_int16_t			auth_algo_;
	u_int16_t			auth_seq_;
	u_int16_t			status_code_;
};

struct AssociationRequestPacket final {
	RadioTapHdr	radiotap_hdr_;
	Dot11Hdr	dot11_hdr_;
	u_int16_t	capability_;
	u_int16_t	listen_interval_;
};

#endif