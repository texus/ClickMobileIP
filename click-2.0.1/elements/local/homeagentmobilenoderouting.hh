#ifndef CLICK_HOMEAGENTMOBILENODEROUTING_HH
#define CLICK_HOMEAGENTMOBILENODEROUTING_HH
#include <click/element.hh>
#include <click/timer.hh>

#include "homeagentinfobase.hh"

CLICK_DECLS

class HomeAgentMobileNodeRouting : public Element {
    public:
        HomeAgentMobileNodeRouting();
        ~HomeAgentMobileNodeRouting();

        const char *class_name() const { return "HomeAgentMobileNodeRouting"; }
        const char *port_count() const { return "1/2"; }
        const char *processing() const { return PUSH; }

        int configure(Vector<String>&, ErrorHandler*);

        void push(int, Packet*);

    private:
        HomeAgentInfobase* _infobase;
};

CLICK_ENDDECLS
#endif
