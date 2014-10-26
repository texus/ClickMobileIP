#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "registrationrequester.hh"

CLICK_DECLS

RegistrationRequester::RegistrationRequester() {}

RegistrationRequester::~RegistrationRequester() {}

int RegistrationRequester::configure(Vector<String>& conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1; //TODO add constructor arguments
	return 0;
}

Packet* pull(int) {
	// check for incoming advertisements
	Packet *p = input(0).pull();
	if(p == 0) {
		// TODO check if timer has expired
		return 0;
	}

	// check source of advertisements

	// if source == home agent, check if still registered as 'away'
	// if yes, send deregistration request to home agent
	// if no, do nothing

	// else check if current registration still valid
	// if no, send registration request trough foreign agent
	// if yes, do nothing
}

CLICK_ENDDECLS

EXPORT_ELEMENT(RegistrationRequester)
