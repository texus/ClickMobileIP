#ifndef CLICK_FOREIGNAGENTROUTING_HH
#define CLICK_FOREIGNAGENTROUTING_HH
#include <click/element.hh>
#include <click/timer.hh>

#include "foreignagentinfobase.hh"

CLICK_DECLS

class ForeignAgentRouting : public Element {
	public:
		ForeignAgentRouting();
		~ForeignAgentRouting();

		const char *class_name() const	{ return "ForeignAgentRouting"; }
		const char *port_count() const 	{ return "1/1"; }
		const char *processing() const	{ return PUSH; }

		int configure(Vector<String>&, ErrorHandler*);

		void push(int, Packet*);

	private:
	    ForeignAgentInfobase* _infobase;
};

CLICK_ENDDECLS
#endif
