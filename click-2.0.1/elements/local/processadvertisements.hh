#ifndef CLICK_PROCESSADVERTISEMENTS_HH
#define CLICK_PROCESSADVERTISEMENTS_HH
#include <click/element.hh>
#include <click/timer.hh>

#include "mobilenodeinfobase.hh"

CLICK_DECLS

class ProcessAdvertisements : public Element {
	public:
		ProcessAdvertisements();
		~ProcessAdvertisements();

		const char *class_name() const	{ return "ProcessAdvertisements"; }
		const char *port_count() const 	{ return "1/3"; }
		const char *processing() const	{ return PUSH; }

		int configure(Vector<String>&, ErrorHandler*);

		void push(int, Packet*);

		void run_timer(Timer*);

	private:
	    MobileNodeInfobase* _infobase;

	    Timer _timer;
};

CLICK_ENDDECLS
#endif
