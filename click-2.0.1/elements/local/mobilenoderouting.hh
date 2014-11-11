#ifndef CLICK_MOBILENODEROUTING_HH
#define CLICK_MOBILENODEROUTING_HH
#include <click/element.hh>
#include <click/timer.hh>

#include "mobilenodeinfobase.hh"

CLICK_DECLS

class MobileNodeRouting : public Element {
    public:
        MobileNodeRouting();
        ~MobileNodeRouting();

        const char *class_name() const { return "MobileNodeRouting"; }
        const char *port_count() const { return "1/1"; }
        const char *processing() const { return PUSH; }

        int configure(Vector<String>&, ErrorHandler*);

        void push(int, Packet*);

    private:
        MobileNodeInfobase* _infobase;
};

CLICK_ENDDECLS
#endif
