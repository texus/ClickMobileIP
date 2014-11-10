#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <click/timestamp.hh>

#include "registrationrequester.hh"
#include "mobilityagentadvertiser.hh"

CLICK_DECLS

RegistrationRequester::RegistrationRequester(): _timer(this) {}

RegistrationRequester::~RegistrationRequester() {}

int RegistrationRequester::configure(Vector<String>& conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, 
			"INFOBASE", cpkP + cpkM, cpElement, &_infobase, 
			cpEnd) < 0) 
		return -1; //TODO add constructor arguments

    _timer.initialize(this);
    _timer.schedule_after_msec(1000);
	return 0;
}

void RegistrationRequester::push(int, Packet *p) {
	// It is assumed that all incoming packets are advertisments //TODO other methods of discovering FA's

	// Get relevant advertisement headers
	click_ip *adv_iph = (click_ip*)p->data();
	advertisement_header *adv_advh = (advertisement_header*)(adv_iph + 1);
	mobile_advertisement_header *adv_mobileh = (mobile_advertisement_header*)(adv_advh + 1);
	//TODO discard to an output[1]?
	//p->kill();

	// Check source address of advertisement
	in_addr adv_src_addr = adv_iph->ip_src;
	// Check if in home network //TODO check advertisement flags (home agent bit set, etc...)?
	if(adv_src_addr == _infobase->homeAgent) {
		if(_infobase->foreignAgent != _infobase->homeAgent) {
			// send deregistration request
			Packet *packet = createRequest(adv_src_addr, 0, _infobase->homeAddress);
			if(packet != 0){
				output(0).push(packet);
			}
		}
	}
	else {
		// ProcessAdvertisements element checks if advertisement needs to be sent to requester
		// Only sends advertisement if either registration lifetime is ending OR no more advertisements are being
		// received for current COA
		uint32_t adv_co_addr = adv_mobileh->address;
		Packet *packet = createRequest(adv_src_addr, adv_mobileh->lifetime, adv_co_addr);
		if(packet != 0) {
			output(0).push(packet);
		}
	}
}

void RegistrationRequester::run_timer(Timer *timer) {

    // decrease remaining lifetime of pending requests
    for(Vector<pending_request>::iterator it = _infobase->pending.begin(); it != _infobase->pending.end(); ++it) {
        uint16_t lifetime = ntohs(it->remaining_lifetime);
        if(lifetime > 1) {
            --lifetime;
            it->remaining_lifetime = htons(lifetime);
        }
        else {
            // remove pending requests whose lifetime has expired
        }
        // when no reply has been received within reasonable time, another registration request may be transmitted! //TODO
    }

    timer->schedule_after_msec(1000);
}

Packet* RegistrationRequester::createRequest(in_addr ip_dst, uint16_t lifetime, uint32_t co_addr) {

	pending_request new_req;
	//TODO save link layer address for foreign agent?
	new_req.ip_dst = ip_dst;
	new_req.co_addr = co_addr;
	//TODO id?
	new_req.requested_lifetime = lifetime;
	new_req.remaining_lifetime = lifetime;
	_infobase->pending.push_back(new_req);

	// Make the registration request packet
	int packet_size = sizeof(click_ip) + sizeof(click_udp) + sizeof(registration_request_header);
	int headroom = sizeof(click_ether);

	WritablePacket *packet = Packet::make(headroom, 0, packet_size, 0);

	// Check if packet correctly created
	if(packet == 0) {
		click_chatter("Could not make packet");
		return 0;
	}

	memset(packet->data(), 0, packet->length());

	// add the IP header
	click_ip *ip_head = (click_ip*)packet->data();
	// set IP fields to correct values
	ip_head->ip_v = 4;
	ip_head->ip_hl = 5;
	ip_head->ip_tos = 0; // Best-Effort
	ip_head->ip_len = htons(packet_size);
	//TODO ip-id necessary?
	ip_head->ip_ttl = 64; //TODO set to 1 if broadcasting request to all mobile agents
	ip_head->ip_p = 17; //UDP protocol
	ip_head->ip_src = _infobase->homeAddress; // Home address is assumed to be known in this project
	ip_head->ip_dst = ip_dst; //TODO if foreign agent IP-address is not known, set to 255.255.255.255 ("all mobility agents"). Don't we always know it???
	ip_head->ip_sum = click_in_cksum((unsigned char*)ip_head, sizeof(click_ip));
	// set destination in annotation
	packet->set_dst_ip_anno(ip_head->ip_dst);

	// add the UDP header
	click_udp *udp_head = (click_udp*)(ip_head + 1);
	udp_head->uh_sport = htons(6789); //TODO From which port are requests sent?
	udp_head->uh_dport = htons(434); // Destination port for registration requests is 434
	uint16_t len = packet->length() - sizeof(click_ip);
	udp_head->uh_ulen = htons(len);
	udp_head->uh_sum = 0;

	// add Mobile IP fields
	registration_request_header *req_head = (registration_request_header*)(udp_head+1);

	// Set type
	req_head->type = 1; //Type = 1 (Registration Request)
	// Set flags
	req_head->flags =	(0 << 7)		// Simultaneous bindings: not supported in this project
						+ (0 << 6)	// Broadcast datagrams //TODO check when to turn on
						+ (0 << 5)	// Decapsulation by mobile node: only when registering co-located COA (not supported)
						+ (0 << 4)	// Minimal encapsulation //TODO check when to turn on.
						+ (0 << 3)	// GRE encapsulation //TODO check when to turn on
						+ (0 << 2)	// r, always sent as 0
						+ (0 << 1)	// Reverse tunnelling //TODO check if supported?
						+ (0);		// x, always sent as 0

	// Set lifetime
	req_head->lifetime = lifetime; //TODO If not specified in advertisement, use (ADJUSTABLE) default ICMP Router Advertisement lifetime 

	//Set home address 
	req_head->home_addr = _infobase->homeAddress.addr();
	req_head->home_agent = _infobase->homeAgent.addr();
	req_head->co_addr = co_addr;
    
    Timestamp stamp;
    stamp.assign_now();
    uint32_t id = stamp.subsec(); //TODO what is the right value to use?
    req_head->id = id;

	return packet;
}

CLICK_ENDDECLS

EXPORT_ELEMENT(RegistrationRequester)
