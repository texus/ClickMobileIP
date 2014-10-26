#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "registrationreplier.hh"
#include "registrationrequester.hh"

CLICK_DECLS

RegistrationReplier::RegistrationReplier() {}

RegistrationReplier::~RegistrationReplier() {}

int RegistrationReplier::configure(Vector<String>& conf, ErrorHandler *errh) {
}

void push(int, Packet *p) {
	// it is assumed that all incoming packets are registration requests // TODO should this be checked in element?
	// read registration request
	// decide to accept or deny
	// send reply
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RegistrationReplier)
