#ifndef CLICK_FOREIGN_AGENT_INFOBASE_HH
#define CLICK_FOREIGN_AGENT_INFOBASE_HH

#include <click/element.hh>
#include <click/hashmap.hh>

CLICK_DECLS

struct visitor_entry {
    // link-layer source address of the mobile node //TODO
    IPAddress ip_src; // mobile node IP home address
    IPAddress ip_dst; // destination IP address
    uint16_t udp_src; // UDP source port
    IPAddress home_agent; // Home Agent address
    uint64_t id; // identification field
    uint16_t requested_lifetime; // requested registration lifetime
    uint16_t remaining_lifetime; // remaining lifetime
};

//TODO : one infobase for 'mobile agent' instead of separate for home and foreign agent functions?
class ForeignAgentInfobase: public Element {
public:
    ForeignAgentInfobase();
    ~ForeignAgentInfobase();

    const char *class_name() const { return "ForeignAgentInfobase"; }
    const char *port_count() const { return "0/0"; }

    int configure(Vector<String>&, ErrorHandler*);

    Vector<visitor_entry> pending_requests;
    HashMap<IPAddress, visitor_entry> current_registrations;

    // TODO care of address

    IPAddress address;

    // TODO maximum number of pending registrations? (optional)

};

CLICK_ENDDECLS

#endif
