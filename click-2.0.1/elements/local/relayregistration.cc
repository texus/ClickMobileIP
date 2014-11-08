#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "relayregistration.hh"
#include "registrationrequester.hh"
#include "registrationreplier.hh"

CLICK_DECLS

RelayRegistration::RelayRegistration(): _timer(this) {}

RelayRegistration::~RelayRegistration() {}

int RelayRegistration::configure(Vector<String> &conf, ErrorHandler *errh) {
    if(cp_va_kparse(conf, this, errh, "INFOBASE", cpkP + cpkM, cpElement, &_infobase, cpEnd) < 0) return -1;

    _timer.initialize(this);
    _timer.schedule_after_msec(1000);
    return 0;
}

void RelayRegistration::push(int, Packet *p) {
    click_ip *ip_h = (click_ip *)p->data();
    uint32_t packet_size = p->length();
    if(packet_size = sizeof(click_ip) + sizeof(click_udp) + sizeof(registration_request_header)) {
        registration_request_header *req_h = (registration_request_header*)(ip_h + 1); //TODO check if this returns correct header
        if(req_h->type == 1) {
            // relaying registration request
            // check if home address does not belong to network interface of foreign agent //TODO
            // if acting as home agent, send packet to registration replier //TODO
            // else, reject using code 136

            // if home address not in network 
            // if non-zero UDP, discard silently
            // if non-zero flags in zero-bits of request, reject with code 70 (poorly formed request)
            // add pending request to visitor list
            // relay to home agent
            WritablePacket *packet = p->uniqueify();
            ip_h = (click_ip *)packet->data();
            click_udp *udp_h = (click_udp *)packet->data();
            // set IP fields
            // ip_h->ip_src = _infobase->interface_addr;
            ip_h->ip_dst = req_h->home_agent;
            // set UDP fields
            udp_h->uh_sport = 
        }
        
    }
    else if(packet_size = sizeof(click_ip) + sizeof(click_udp) + sizeof(registration_reply_header)) {
        registration_reply_header *rep_h = (registration_reply_header*)(ip_h + 1); //TODO check if this return correct header
        if(rep_h->type == 3) {
            // relaying registration reply
        }
    }
 
    // if request, check if ill-formed
    // if  well-formed, send on to home agent
    // + add information to visitor table
            // link-layer source address of mobile node
            // IP Source Address (= mobile node Home Address)
            // IP Destination Address
            // UDP Source Port
            // Home Agent Address
            // Identification field
            // requested registration Lifetime
            // remaining Lifetime of pending or current registration
    // if non-zero UDP, discard silently
    // if non-zero flags
    // if reply, check if ill-formed
    // if well-formed, relay to mobile node
    // else, adapt reply (code 71) and relay to mobile node


    /*
    * Registration denied by foreign agent
    *   64      reason unspecified
    *   ...
    *   (66      insufficient resources (if max number of pending registrations exceeded))
    *   ...
    *   70      poorly formed Request
    *   71      poorly formed Reply
    *   72      requested encapsulation unavailable
    *   ...
    *   (78      registration timeout)
    *   ...
    *   80      home network unreachable (ICMP error received)
    *   ...
    */
}

void RelayRegistration::run_timer(Timer *timer) {
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RelayRegistration)
