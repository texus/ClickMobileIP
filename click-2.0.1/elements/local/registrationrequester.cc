#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include "registrationrequester.hh"
#include "mobilityagentadvertiser.hh"

CLICK_DECLS

RegistrationRequester::RegistrationRequester() {}

RegistrationRequester::~RegistrationRequester() {}

int RegistrationRequester::configure(Vector<String>& conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1; //TODO add constructor arguments
	return 0;
}

void RegistrationRequester::push(int, Packet *p) {
	click_chatter("Got a packet");
	// it is assumed that all incoming packets are advertisments // TODO should this be checked in element?

	// check care
    mobile_advertisement_header *adv = (mobile_advertisement_header*)p->data();
	uint32_t co_addr = adv->address;

	// if source == home agent, check if still registered as 'away'
	// if yes, send deregistration request to home agent
	// if no, do nothing

	// else check if current registration still valid
	// if no, send registration request trough foreign agent
	// make packet
	int packet_size = sizeof(click_ip) + sizeof(registration_request_header);
	int headroom = sizeof(click_ether);

	WritablePacket *packet = Packet::make(headroom, 0, packet_size, 0);
	// errors?

	

	// add IP header

	click_ip *ip_head = (click_ip*)packet->data();
			// source address = interface address of mobile agent
			// destination address = address of foreign agent
	// add UDP header
			// source port
			// destination port = 434
	// add Mobile IP fields
	registration_request_header* req_head;
	req_head->type = 1;

	//set flags
	req_head->flags =	(0 << 7)	// Simultaneous bindings // TODO check if supported
						+ (0 << 6)	// Broadcast datagrams //TODO check correct val
						+ (0 << 5)	// Decapsulation by Mobile Node (always 0 for this project: Co-located COA not supported)
						+ (0 << 4)	// Minimal encapuslation // TODO check if always 0
						+ (0 << 3)	// GRE encapsulation // TODO check if always 0
						+ (0 << 2)	// r (reserved, always 0)
						+ (0 << 1)	// Reverse Tunnelling // TODO check if supported
						+ (0)		// x (always 0)
	
	req_head->lifetime = htons(0xffff); //TODO not infinite
	//req_head->home_addr = home_address if known, otherwise ... // TODO look this up
	//req_head->home_agent = home_agent if known, otherwise ... // TODO look this up
	req_head->co_addr = co_addr;
	//uint64_t id;		// TODO need to do something with this?

	output(0).push(packet);
	
	// if yes, do nothing
}

/**

    memset(packet->data(), 0, packet->length());
    _sequenceNr++;

    click_ip* iph = (click_ip*)packet->data();
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = htons(packetsize);
    iph->ip_id = htons(_sequenceNr);
    iph->ip_ttl = 1; // TTL must be 1 in advertisement
    iph->ip_p = 1; // protocol = ICMP
    iph->ip_src.s_addr = _srcIp;
    iph->ip_dst.s_addr = 0xffffffff;
    iph->ip_sum = click_in_cksum((unsigned char*)packet->data(), packet->length());

//    packet->set_dst_ip_anno(iph->ip_dst);  ///TODO: Needed?

    madvh->flags =  (1 << 7) // Registration required
                  + (0 << 6) // Busy
                  + (_homeAgent << 5) // Home agent
                  + (_foreignAgent << 4) // Foreign agent
                  + (0 << 3) // Minimal encapsulation  ///TODO: Check correct value
                  + (0 << 2) // GRE encapsulation  ///TODO: Check correct value
                  + (0 << 1) // ignore
                  + 0;       // Foreign agent supports reverse tunneling  ///TODO: Check correct value

    // Calculate the ICMP header checksum
    advh->checksum = click_in_cksum((unsigned char*)advh, packetsize - sizeof(click_ip));

    output(0).push(packet);
*/

CLICK_ENDDECLS

EXPORT_ELEMENT(RegistrationRequester)
