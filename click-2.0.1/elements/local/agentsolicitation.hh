#ifndef CLICK_AGENTSOLICITATION_HH
#define CLICK_AGENTSOLICITATION_HH
#include <click/element.hh>
#include <click/timer.hh>

#include "mobilenodeinfobase.hh"

CLICK_DECLS

class AgentSolicitation : public Element {
    public:
        AgentSolicitation();
        ~AgentSolicitation();

        const char *class_name() const { return "AgentSolicitation"; }
        const char *port_count() const { return "0/1"; }
        const char *processing() const { return PUSH; }

        int configure(Vector<String>&, ErrorHandler*);

        void run_timer(Timer*);

    private:
        MobileNodeInfobase* _infobase;
        IPAddress _srcIp;
        Timer _timer;

        unsigned int _messagesSendInRow;
        unsigned int _maxRetries;
};

struct agent_solicitation_header {
    uint8_t     type;           /* 0     Type = 10 (Agent Solicitation) */
    uint8_t     code;           /* 1     Code = 0 */
    uint16_t    checksum;       /* 2-3   Checksum */
    uint8_t     addresses;      /* 4-7   Reserved */
};

CLICK_ENDDECLS
#endif
