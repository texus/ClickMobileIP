#ifndef CLICK_FOREIGN_AGENT_INFOBASE_HH
#define CLICK_FOREIGN_AGENT_INFOBASE_HH

#include <click/element.hh>
#include <click/hashtable.hh>
#include <click/etheraddress.hh>

CLICK_DECLS

struct visitor_entry {
    EtherAddress eth_src; // link-layer source address of the mobile node
    IPAddress ip_src; // mobile node IP home address
    IPAddress ip_dst; // destination IP address
    uint16_t udp_src; // UDP source port
    IPAddress home_agent; // Home Agent address
    uint64_t id; // identification field
    uint16_t requested_lifetime; // requested registration lifetime
    uint16_t remaining_lifetime; // remaining lifetime
};

class ForeignAgentInfobase: public Element {
public:
    ForeignAgentInfobase();
    ~ForeignAgentInfobase();

    const char *class_name() const { return "ForeignAgentInfobase"; }
    const char *port_count() const { return "0/0"; }

    int configure(Vector<String>&, ErrorHandler*);

    Vector<visitor_entry> pending_requests;
    HashTable<IPAddress, visitor_entry> current_registrations;

    IPAddress address;
};

CLICK_ENDDECLS

#endif
