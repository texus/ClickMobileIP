#ifndef CLICK_ENCAPSULATOR_HH
#define CLICK_ENCAPSULATOR_HH
#include <click/element.hh>
#include <click/timer.hh>

CLICK_DECLS

class Encapsulator : public Element {
	public:
		Encapsulator();
		~Encapsulator();

		const char *class_name() const	{ return "Encapsulator"; }
		const char *port_count() const 	{ return "1/1"; }
		const char *processing() const	{ return PUSH; }

		int configure(Vector<String>&, ErrorHandler*);

		void push(int, Packet*);

	private:
	    IPAddress _srcIp;
        IPAddress _dstIp;
};

CLICK_ENDDECLS
#endif
