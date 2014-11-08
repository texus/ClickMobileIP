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
	if(cp_va_kparse(conf, this, errh, "INFOBASE", cpkP + cpkM, cpElement, &_infobase, cpEnd) < 0)
		return -1;
}

void RegistrationReplier::push(int, Packet *p) {
	// it is assumed that all incoming packets are registration requests
	// get relevant headers
	click_ip *req_ip = (click_ip*)p->data();
	click_udp *req_udp = (click_udp*)(req_ip + 1);
	registration_request_header *req_rh = (registration_request_header*)(req_udp + 1);

	// decide to accept or deny
	uint8_t code = check_acceptability(p);

	// if accepted, save info into homeagentinfobase
    if(code == 0 || code == 1) {MobileNodeInfo info; //TODO check if all info correct
        info.address = req_ip->ip_src;
        info.careOfAddress = IPAddress(req_rh->co_addr);
        info.identification = req_rh->id;
        info.remainingLifetime = req_rh->lifetime;
        _infobase->mobileNodesInfo.push_back(info);
    }

	// send reply
	int packet_size = sizeof(click_ip) + sizeof(click_udp) + sizeof(registration_reply_header);
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
	click_udp *udp_head = (click_udp*)(ip_head + 1);
	udp_head->uh_sport = req_udp->uh_dport; // copied form dst port of corresponding Registration Request
	udp_head->uh_dport = req_udp->uh_sport; // copied from source port of corresponding Registration Request
	uint16_t len = packet->length() - sizeof(click_ip);
	udp_head->uh_ulen = htons(len);
	udp_head->uh_sum = 0; //TODO non-zero UDP checksum?

	// add mobile IP fields
	registration_reply_header *reph = (registration_reply_header*)(udp_head + 1);

	reph->type = 3; // Registration Reply
	reph->code = code;
	reph->lifetime = req_rh->lifetime;
	reph->home_addr = req_rh->home_addr;

    if(code == 136) {
        //TODO send home agent address when mobile node is discovering home agent address
    }
    else {
	    reph->home_agent = req_rh->home_agent; 
    }

	reph->id = req_rh->id;

	// send reply to output 0
	output(0).push(packet);
}

uint8_t RegistrationReplier::check_acceptability(Packet *packet) {
	/*
	Accepted
		0	registration accepted
		1 	registratin accepted but simultaneous mobility bindings denied
	Denied by home agent
		128	reason unspecified
		...
		134	poorly formed Request
		135 too many simultaneous mobility bindings
		136	unknown home agent address
	*/
	click_ip *req_ip = (click_ip*)packet->data();
	click_udp *req_udp = (click_udp*)(req_ip + 1);
	registration_request_header *req_rh = (registration_request_header*)(req_udp + 1);

	// if r or x flags in request not 0, return 'Poorly formed request' code (134)
	uint8_t flags = req_rh->flags;
	if((flags & 1) || ((flags >> 2) & 1)) {
		return 134;
	}

	// if S bit set and already bound, return 'Too many simultaneous mobility bindings' code //TODO or also when just S bit set?
	//if(((flags >> 7) & 1) && ) {
	//}

	// if HomeAgent field in request is not unicast, return 'Unknown home agent address' code //TODO

	// if something else is wrong, return 'Reason unspecified' code //TODO when?

	return 1; //TODO always return 1 when S not supported? Or only when S bit set?
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RegistrationReplier)
