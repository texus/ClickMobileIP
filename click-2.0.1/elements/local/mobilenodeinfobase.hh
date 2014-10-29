#ifndef CLICK_MOBILENODEINFOBASE_HH
#define CLICK_MOBILENODEINFOBASE_HH
#include <click/element.hh>

CLICK_DECLS

class MobileNodeInfobase : public Element {
	public:
		MobileNodeInfobase();
		~MobileNodeInfobase();

		const char *class_name() const	{ return "MobileNodeInfobase"; }
		const char *port_count() const 	{ return "0/0"; }

		int configure(Vector<String>&, ErrorHandler*);

	public:
	    IPAddress homeAgent;
	    IPAddress foreignAgent;
	    uint16_t  lifetime;
};

CLICK_ENDDECLS
#endif
