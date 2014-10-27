#ifndef CLICK_REGISTRATION_REPLIER_HH
#define CLICK_REGISTRATION_REPLIER_HH

#include <click/element.hh>

CLICK_DECLS

/**
*
* @brief RegistrationReplier receives registration request and answers with acceptation or refusal.
*/
class RegistrationReplier: public Element {
	RegistrationReplier();
	~RegistrationReplier();

	const char *class_name() const { return "RegistrationReplier"; }
	const char *port_count() const { return "1/1"; }
	const char *processing() const { return PUSH; }

	int configure(Vector<String>&, ErrorHandler*);

	void pull(int, Packet*);
}:

struct registration_reply_header {
	uint8_t type		/* 0		Type = 3 (Registration Reply) */
	uint8_t code		/* 1		Result of Registration Request */
	uint16_t lifetime	/* 2_3		Number of seconds remaining before registration expired */
	in_addr home_addr	/* 4-7		IP-address of mobile node */
	in_addr home_agent	/* 8-11		IP-address of mobile node's home agent */
	uint64_t id			/* 12-19 	Identification */
};

CLICK_ENDDECLS

#endif