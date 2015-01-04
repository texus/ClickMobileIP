#ifndef CLICK_REGISTRATION_REQUESTER_HH
#define CLICK_REGISTRATION_REQUESTER_HH

#include <click/element.hh>
#include <click/timer.hh>
#include "mobilenodeinfobase.hh"

CLICK_DECLS


/**
*
* RegistrationRequester receives MobilityAdvertisements and (if necessary) sends
* (de)registration requests to foreign or home agent.
*/
class RegistrationRequester : public Element {
    public:
        RegistrationRequester();
        ~RegistrationRequester();

        const char *class_name() const { return "RegistrationRequester"; }
        const char *port_count() const { return "1/1"; }
        const char *processing() const { return PUSH; }

        int configure(Vector<String>&, ErrorHandler*);

        void push(int, Packet*);

        void run_timer(Timer*);

    private:
        MobileNodeInfobase *_infobase;
        uint16_t _default_lifetime; // default ICMP Router Advertismeent Lifetime, defaults to 1800 seconds
        Timer _timer;

        bool _simultaneousBindings;

        Packet* createRequest(in_addr ip_dst, uint16_t lifetime, uint32_t co_addr);
};

struct registration_request_header {
    uint8_t type;           /* 0        Type = 1 (Registration Request) */
    uint8_t flags;          /* 1        Flags: S (Simultaneous bindings), B (Broadcast datagrams),
                                        D (Decapsulation by Mobile Node), M (Minimal encapsulation),
                                        G (GRE encapsulation), r (0), T (reverse tunnelling), x (0) */
    uint16_t lifetime;      /* 2-3      Registration lifetime */
    uint32_t home_addr;     /* 4-7      IP-address of mobile node */
    uint32_t home_agent;    /* 8-11     IP-address of mobile node's home agent */
    uint32_t co_addr;       /* 12-15    IP-address for the end of the tunnel */
    uint64_t id;            /* 16-23    Identification */
};

CLICK_ENDDECLS

#endif
