#ifndef CLICK_REGISTER_NODE_HH
#define CLICK_REGISTER_NODE_HH

#include <click/element.hh>
#include "mobilenodeinfobase.hh"

CLICK_DECLS

/**
* Element receives registration replies directed to mobile node,
* and adds info about current registration to mobile node infobase.
* Also resends request when denial code indicates that denial is 'reparable'.
*/
class RegisterNode: public Element {
public:
    RegisterNode();
    ~RegisterNode();

    const char *class_name() const { return "RegisterNode"; }
    const char *port_count() const { return "1/1"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String>&, ErrorHandler*);
    void push(int, Packet*);

private:
    void run_timer(Timer* timer);

private:
    MobileNodeInfobase *_infobase;

    unsigned int _almostExpiredLifetime;

    Timer _timer;
};

CLICK_ENDDECLS

#endif
