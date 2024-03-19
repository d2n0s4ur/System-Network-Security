#ifndef PCAP_TEST_H
# define PCAP_TEST_H

# pragma once
# include <stdint.h>
# define MAC_ADDR_LEN 6
# define ETH_TYPE_IPV4 0x0008
# define IPV4_PROT_TCP 0x06

# define u_int32_t uint32_t
# define u_int16_t uint16_t
# define u_int8_t uint8_t

# pragma pack(push, 1)
typedef struct s_ethernet_hdr {
	unsigned char	mac_dst_addr[MAC_ADDR_LEN];
	unsigned char	mac_src_addr[MAC_ADDR_LEN];
	u_int16_t		ether_type;
}	t_ethernet_hdr;

typedef union s_ip_addr {
	u_int8_t	byte[4];
	u_int16_t	word[2];
	u_int32_t	dword;
}	t_ip_addr;

typedef struct s_ipv4_hdr {
// #  if __BYTE_ORDER == __BIG_ENDIAN
// 	unsigned int		ip_ver:4;
// 	unsigned int		ip_len:4;
// #  endif
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int		ip_len:4;
	unsigned int		ip_ver:4;
#  endif
// dscp & ecn
	unsigned int		ip_ecn:2;
	unsigned int		ip_dscp:6;
	u_int16_t			ip_tot_len;
	u_int16_t			ip_id;
	u_int16_t			ip_frag_off;
#  define IP_RF 0x8000
#  define IP_DF 0x4000
#  define IP_MF 0x2000
#  define IP_OFFSET_MASK 0x1FFF
	u_int8_t			ip_ttl;
	u_int8_t			ip_prot;
	u_int16_t			ip_cs;
	union s_ip_addr		ip_src;
	union s_ip_addr		ip_dst;
}	t_ipv4_hdr;

typedef struct s_tcp_hdr {
	u_int16_t			tcp_src_port;
	u_int16_t			tcp_dst_port;
	u_int32_t			tcp_seq;
	u_int32_t			tcp_ack;
// #  if __BYTE_ORDER == __BIG_ENDIAN
// 	unsigned int		tcp_offset:4;
// 	unsigned int		tcp_res:4;
// #  endif
#  if __BYTE_ORDER == __LITTLE_ENDIAN
 	unsigned int		tcp_res:4;
 	unsigned int		tcp_offset:4;
#  endif
	u_int8_t			tcp_flags;
	u_int16_t			tcp_win;
	u_int16_t			tcp_cs;
	u_int16_t			tcp_urgp;
}	t_tcp_hdr;

void	print_mac_addr(void *addr);
void	print_ip_addr(t_ip_addr ip);
void	print_payload(const unsigned char *addr, int len);

#endif
