#ifndef CLICK_RELAY_REGISTRATION_HH
#define CLICK_RELAY_REGISTRATION_HH

#include <click/element.hh>
#include <click/timer.hh>
#include "foreignagentinfobase.hh"

CLICK_DECLS

/**
* Element allows mobile agent acting as foreign agent to
* relay mobile registration request and reply messages
*/
class RelayRegistration: public Element {
public:
    RelayRegistration();
    ~RelayRegistration();

    const char *class_name() const { return "RelayRegistration"; }
    const char *port_count() const { return "1/2"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String>&, ErrorHandler*);

    void push(int, Packet*);

    void run_timer(Timer*);

private:
    ForeignAgentInfobase *_infobase;
    IPAddress _privateIP;
    Timer _timer;

    void relayRequest(Packet *p);
    void relayReply(Packet *p);
    Packet* createReply(uint8_t code, in_addr ip_src, in_addr ip_dst, uint16_t udp_dst, uint64_t id, in_addr home_agent);

};

CLICK_ENDDECLS

#endif
