#ifndef CLICK_REGISTRATION_REPLIER_HH
#define CLICK_REGISTRATION_REPLIER_HH

#include <click/element.hh>
#include "homeagentinfobase.hh"

CLICK_DECLS

/**
* RegistrationReplier receives registration request and answers with acceptation or refusal.
*/
class RegistrationReplier: public Element {
public:
	RegistrationReplier();
	~RegistrationReplier();

	const char *class_name() const { return "RegistrationReplier"; }
	const char *port_count() const { return "1/1"; }
	const char *processing() const { return PUSH; }

	int configure(Vector<String>&, ErrorHandler*);

	void push(int, Packet*);
	
private:
	HomeAgentInfobase *_infobase;
	uint8_t check_acceptability(Packet *packet);
};

struct __attribute__((__packed__)) registration_reply_header {
	uint8_t type;			/* 0		Type = 3 (Registration Reply) */
	uint8_t code;			/* 1		Result of Registration Request */
	uint16_t lifetime;		/* 2_3		Number of seconds remaining before registration expired */
	uint32_t home_addr;		/* 4-7		IP-address of mobile node */
	uint32_t home_agent;	/* 8-11		IP-address of mobile node's home agent */
    uint64_t id;
	/* 12-19 Identification is stored seperately to avoid padding problems */
};

CLICK_ENDDECLS

#endif
