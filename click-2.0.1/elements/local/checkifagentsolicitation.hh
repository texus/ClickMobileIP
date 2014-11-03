#ifndef CLICK_CHECKIFAGENTSOLICITATION_HH
#define CLICK_CHECKIFAGENTSOLICITATION_HH
#include <click/element.hh>
#include <click/timer.hh>

CLICK_DECLS

class CheckIfAgentSolicitation : public Element {
	public:
		CheckIfAgentSolicitation();
		~CheckIfAgentSolicitation();

		const char *class_name() const	{ return "CheckIfAgentSolicitation"; }
		const char *port_count() const 	{ return "1/2"; }
		const char *processing() const	{ return PUSH; }

		int configure(Vector<String>&, ErrorHandler*);

		void push(int, Packet*);
};

CLICK_ENDDECLS
#endif
