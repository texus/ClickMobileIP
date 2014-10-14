#ifndef CLICK_MOBILITYAGENTADVERTISER_HH
#define CLICK_MOBILITYAGENTADVERTISER_HH
#include <click/element.hh>
#include <click/timer.hh>

CLICK_DECLS

class MobilityAgentAdvertiser : public Element { 
	public:
		MobilityAgentAdvertiser();
		~MobilityAgentAdvertiser();
		
		const char *class_name() const	{ return "MobilityAgentAdvertiser"; }
		const char *port_count() const 	{ return "0/1"; }
		const char *processing() const	{ return PUSH; }

		int configure(Vector<String>&, ErrorHandler*);
		
		void push(int, Packet *);

		void run_timer(Timer *);

	private:
	    IPAddress _srcIp;
	
		int _interval;
		Timer _timer;
		
		uint8_t _sequenceNr;
};

CLICK_ENDDECLS
#endif
