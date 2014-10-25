#ifndef CLICK_MOBILITYEMULATOR_HH
#define CLICK_MOBILITYEMULATOR_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <click/vector.hh>
CLICK_DECLS

class MobilityEmulator : public Element { 
	public:
		MobilityEmulator();
		~MobilityEmulator();
		
		const char *class_name() const	{ return "MobilityEmulator"; }
		const char *port_count() const 	{ return "1-/=-"; }
		const char *processing() const	{ return PUSH; }

		int initialize(ErrorHandler*errh);
		int configure(Vector<String>&, ErrorHandler*);
		
		void push(int, Packet *);

		void run_timer(Timer *);
		
		static String getConnectedNetwork(Element* f, void *);
		static int setConnectedNetwork(const String &conf, Element *e, void *, ErrorHandler * errh);
		void add_handlers();

	private:
		int _connectedNetwork;
		Vector<int> _connectedNetworkCycle;
		unsigned _currentIndex;
		int _interval;
		Timer _timer;
		
		bool _connectedNetworkPresent;
		bool _intervalPresent;
		bool _connectedNetworksPresent;
};

CLICK_ENDDECLS
#endif
