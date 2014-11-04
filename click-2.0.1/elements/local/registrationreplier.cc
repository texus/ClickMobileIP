#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include "registrationreplier.hh"
#include "registrationrequester.hh"

CLICK_DECLS

RegistrationReplier::RegistrationReplier() {}

RegistrationReplier::~RegistrationReplier() {}

int RegistrationReplier::configure(Vector<String>& conf, ErrorHandler *errh) {
}

void push(int, Packet *p) {
	// it is assumed that all incoming packets are registration requests
	// get relevant headers
	click_ip *req_ip = (click_ip*)p->data();
	click_udp *req_udp = (click_udp*)p->data();
	registration_request_header *req_rh = (registration_request_header*)(req_udp + 1);

	// decide to accept or deny
	// if accepted, save info into homeagentinfobase
	// send reply

	int packet_size = sizeof(click_ip) + sizeof(registration_reply_header);
	int headroom = sizeof(click_ether);
	WritablePacket *packet = Packet::make(headroom, 0, packet_size, 0);

	// add IP header
	click_ip *ip_head = (click_ip*)packet->data();
	ip_head->ip_v = 4;
	ip_head->ip_hl = 5; //TODO check if this is correct
	ip_head->ip_tos = 0; // Best-Effort
	ip_head->ip_len = htons(packet_size);
	//ip_head->ip_id //TODO necessary?
	ip_head->ip_ttl = 64;
	ip_head->ip_p = 17; // UDP protocol
	ip_head->ip_src = req_ip->ip_dst; // copied from destination address of the Registration Request //TODO see section 3.7.2.3, 3.8.3.1
	ip_head->ip_dst = req_ip->ip_src; // copied form source address of Registration Request to wich agent is replying	
	ip_head->ip_sum = click_in_cksum((unsigned char*)ip_head, sizeof(click_ip));

	// set destination in annotation
	packet->set_dst_ip_anno(ip_head->ip_dst);

	// add UDP header
	click_udp *udp_head = (click_udp*)packet->data();
	//udp_head->uh_sport = ? //TODO from which port?
	udp_head->uh_dport = req_udp->uh_sport; // copied from source port of corresponding Registration Request
	uint16_t len = packet->length() - sizeof(click_ip);
	udp_head->uh_ulen = htons(len);
	udp_head->uh_sum = 0; //TODO non-zero UDP checksum?

	// add mobile IP fields
	registration_reply_header *reph = (registration_reply_header*)(udp_head + 1);

	reph->type = 3; // Registration Reply
	reph->code = 0; //TODO send code according to acceptance/denial of request
	/*
	Accepted
		0	registration accepted
		1 	registratin accepted but simultaneous mobility bindings denied
	Denied by foreign agent
		64	reason unspecified
		...
		70	poorly formed Request
		71	poorly formed Reply
		72	requested encapsulation unavailable
		...
		80	home network unreachable (ICMP error received)
		...
	Denied by home agent
		128	reason unspecified
		...
		134	poorly formed Request
		135 too many simultaneous mobility bindings
		136	unknown home agent address
	*/
	reph->lifetime = 0xffff; //TODO make this not infinite
	reph->home_addr = req_rh->home_addr;
	reph->home_agent = req_rh->home_agent; //TODO send home agent address when mobile node is discovering home agent address
	//reph->id = 0; //TODO calculate this from id sent in request
	
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RegistrationReplier)
