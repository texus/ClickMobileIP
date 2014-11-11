#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/udp.h>
#include "registrationreplier.hh"
#include "registernode.hh"

CLICK_DECLS

RegisterNode::RegisterNode() :_timer(this) {}

RegisterNode::~RegisterNode() {}

int RegisterNode::configure(Vector<String> &conf, ErrorHandler *errh) {
    if(cp_va_kparse(conf, this, errh, "INFOBASE", cpkP + cpkM, cpElement, &_infobase, cpEnd) < 0) return -1;

    _timer.initialize(this);
    return 0;
}

void RegisterNode::push(int, Packet *p) {
    // receive reply
    click_ip *ip_h = (click_ip *)p->data();
    click_udp *udp_h = (click_udp *)(ip_h + 1);
    registration_reply_header *rep_h = (registration_reply_header *)(udp_h + 1);

    // get corresponding pending request
    Vector<pending_request>::iterator most_recent;
    bool corresponding_found = false;
    for(Vector<pending_request>::iterator it = _infobase->pending.begin();it != _infobase->pending.end(); ++it) {
        if(it->ip_dst == ip_h->ip_src) {
            corresponding_found = true;
            most_recent = it;
            break;
        }
    }
    
    if(!corresponding_found) {  
        return;
     }

    // if non-zero UDP checksum, discard silently
    if(udp_h->uh_sum != 0) {
        //p->kill(); //TODO kill ok or send to an output(1)?
        // remove pending request
        _infobase->pending.erase(most_recent);
        return;
    }   
   
    // compare ID of reply to ID of most recent request sent to replying agent
    // if not matching, discard silently
    int id1 = rep_h->id;
    int id2 = most_recent->id;
    if(rep_h->id != most_recent->id) {
        //TODO kill?
        return;
    }

    // check if accepted
    uint8_t code = rep_h->code;
    if(code == 0 || code == 1) {
        _timer.clear();
    
        // request accepted, adapt mobile node infobase
        if(/*rep_h->lifetime == 0 && */ip_h->ip_src == _infobase->homeAgent) {
            // returning to home network // TODO should this be done BEFORE sending deregistration request?
            _infobase->connected = true;
            _infobase->foreignAgent = _infobase->homeAgent;
            _infobase->lifetime = 0;
        }
        else {
            // registering on foreign network
            _infobase->connected = true;
            _infobase->foreignAgent = IPAddress(most_recent->ip_dst);
            // set lifetime
            uint16_t granted_lifetime = ntohs(rep_h->lifetime);
            uint16_t requested_lifetime = most_recent->requested_lifetime;
            uint16_t decreased = requested_lifetime - granted_lifetime;
            uint16_t lifetime = most_recent->remaining_lifetime - decreased;
            _infobase->lifetime = lifetime;
            
            _timer.schedule_after_sec(1);
        }
    
        // remove pending request
        _infobase->pending.erase(most_recent);
    }
    else {
        // act according to reply code
        // log error
        String message = "Request denied: ";
        switch(code) {
            case 64: case 128:
                message += "reason unspecified";
                break;
            case 70: case 134:
                message += "poorly formed Request";
                break;
            case 71: 
                message += "poorly formed Reply";
                break;
            case 72:
                message += "requested encapsulation unavailable";
                break;
            case 80:
                message += "home network unreachable (ICMP error received)";
                break;
            case 135:
                message += "too many simultaneous mobility bindings";
                break;
            case 136:
                message += "unknown home agent address"; 
                break;
            default:
                message += "unknown exception code";
                break;
        }
        click_chatter(message.data());

        // remove pending request
        _infobase->pending.erase(most_recent);

        if(code == 136) {
            // if request was denied because home agent address was unknown, error can be 'repaired'
            // TODO set home agent address in infobase & retransmit request
        }
    }  
}

void RegisterNode::run_timer(Timer* timer)
{
    // Decrease the registration lifetime
    if (_infobase->lifetime > 0)
    {
        _infobase->lifetime--;

        if (_infobase->lifetime == 3) //TODO get good value for this
        {
            // when registration almost expired, look for advertisement of current foreign agent
            // & relay to element that sends requests
            Packet *p = _infobase->advertisements[_infobase->foreignAgent];
            if(p != 0)
                output(0).push(p);
        }
        if (_infobase->lifetime == 0) 
        {
            _infobase->connected = false;
            //TODO should something else happen here?
        }
    }

    _timer.schedule_after_sec(1);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RegisterNode);
