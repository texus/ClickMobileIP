#ifndef CLICK_FOREIGN_AGENT_INFOBASE_HH
#define CLICK_FOREIGN_AGENT_INFOBASE_HH

#include <click/element.hh>
#include <click/hashmap.hh>

CLICK_DECLS

struct visitor_entry {
    // link-layer source address of the mobile node //TODO
    // IP-source address (mobile node's home address)
    IPAddress ip_src;
    // IP Destination Address
    IPAddress ip_dst;
    // UDP source port
    
    // Home Agent address
    IPAddress home_addr;
    // Identification field
    uint64_t id;
    // requested registration Lifetime
    uint16_t requested_lifetime;
    // remaining Lifetime
    uint16_t remaining_lifetime;
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
