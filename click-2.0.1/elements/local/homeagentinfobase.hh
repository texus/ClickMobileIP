#ifndef CLICK_HOMEAGENTINFOBASE_HH
#define CLICK_HOMEAGENTINFOBASE_HH
#include <click/element.hh>
#include <click/timer.hh>

CLICK_DECLS

struct MobileNodeInfo
{
    IPAddress address;
    IPAddress careOfAddress;
    uint64_t  identification;
    uint8_t   remainingLifetime;
};

class HomeAgentInfobase : public Element {
    public:
        HomeAgentInfobase();
        ~HomeAgentInfobase();

        const char *class_name() const { return "HomeAgentInfobase"; }
        const char *port_count() const { return "0/0"; }

        int configure(Vector<String>&, ErrorHandler*);

    public:
        IPAddress home_agent_address;

        Vector<MobileNodeInfo> mobileNodesInfo;
};

CLICK_ENDDECLS
#endif
