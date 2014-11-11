#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "mobilityemulator.hh"

CLICK_DECLS
MobilityEmulator::MobilityEmulator()
    : _connectedNetwork(0), _connectedNetworkCycle(), _currentIndex(0), _interval(0), _timer(this),
    _connectedNetworkPresent(false), _intervalPresent(false), _connectedNetworksPresent(false)
{}

MobilityEmulator::~MobilityEmulator()
{}

int MobilityEmulator::configure(Vector<String> &conf, ErrorHandler *errh) {

    String connectedNetworks;
    if (cp_va_kparse(conf, this, errh,
                "CONNECTED_NETWORK", cpkC, &_connectedNetworkPresent, cpInteger, &_connectedNetwork,
                "INTERVAL", cpkC, &_intervalPresent, cpUnsigned, &_interval,
                "CONNECTED_NETWORKS", cpkC, &_connectedNetworksPresent, cpString, &connectedNetworks,
                cpEnd) < 0)
        return -1;

    if (_connectedNetworkPresent && (_intervalPresent || _connectedNetworksPresent)) {
        return errh->error("CONNECTED_NETWORK can not be used at the same time as INTERVAL and CONNECTED_NETWORKS");
    }

    if (_intervalPresent && !_connectedNetworksPresent) {
        return errh->error("INTERVAL also requires CONNECTED_NETWORKS to be present");
    }

    if (!_intervalPresent && _connectedNetworksPresent) {
        return errh->error("INTERVAL can not be used at the same time as INTERVAL and  CONNECTED_NETWORKS");
    }

    if (_connectedNetworkPresent) {
        if (_connectedNetwork <= 0)
            return errh->error("CONNECTED_NETWORK should be larger or equal to 1");
        return 0;
    }


    if (_intervalPresent && _connectedNetworksPresent) {
        connectedNetworks = connectedNetworks.trim_space();
//        click_chatter("%s", connectedNetworks.c_str());
        int pos = connectedNetworks.find_left(',');
        while (pos > 0) {
            unsigned int temp = 0;
//            click_chatter("%s", connectedNetworks.substring(0, pos).c_str());
            if (cp_va_kparse(connectedNetworks.substring(0, pos), this, errh, "CONNECTED_NETWORK", cpkP, cpUnsigned, &temp, cpEnd) < 0) return -1;
            if (temp >= unsigned(ninputs())) return errh->error("%d is not a valid port (only %d ports so max is %d)", temp, ninputs(), ninputs()-1);
            if (temp == 0) return errh->error("Not allowed to use 0 in the cycle");
//            click_chatter("%d is a valid port", temp);
            _connectedNetworkCycle.push_back(temp);
            connectedNetworks = connectedNetworks.substring(pos+1);
//            click_chatter("left: %s", connectedNetworks.c_str());
            pos = connectedNetworks.find_left(',');
        }

        unsigned int temp = 0;
//        click_chatter("%s", connectedNetworks.c_str());
        if (cp_va_kparse(connectedNetworks, this, errh, "CONNECTED_NETWORK", cpkP, cpUnsigned, &temp, cpEnd) < 0) return -1;
        if (temp >= unsigned(ninputs())) return errh->error("%d is not a valid port (only %d ports so max is %d)", temp, ninputs(), ninputs()-1);
        if (temp == 0) return errh->error("Not allowed to use 0 in the cycle");
//        click_chatter("%d is a valid port", temp);
        _connectedNetworkCycle.push_back(temp);

        _connectedNetwork = _connectedNetworkCycle[0];
        click_chatter("\033[43mMOBILITY EMULATOR: Switched to network %i \033[0m\n",_connectedNetworkCycle[0]);

    }
    return 0;
}

int MobilityEmulator::initialize(ErrorHandler*) {
    if (_intervalPresent && _connectedNetworksPresent) {
        _timer.initialize(this);
        _timer.schedule_after_msec(_interval*1000);
    }

    return 0;
}

void MobilityEmulator::run_timer(Timer *) {
    _currentIndex = (_currentIndex + 1) % _connectedNetworkCycle.size();
    click_chatter("\033[43mMOBILITY EMULATOR: Switched to network %i \033[0m\n",_connectedNetworkCycle[_currentIndex]);
    _connectedNetwork = _connectedNetworkCycle[_currentIndex];

    _timer.schedule_after_msec(_interval*1000);
}

void MobilityEmulator::push(int input, Packet *p){
    if (input == 0) {
        output(_connectedNetwork).push(p);
    } else if (input == _connectedNetwork) {
        output(0).push(p);
    } else {
        p->kill();
    }
}

String
MobilityEmulator::getConnectedNetwork(Element* f, void *) {
    MobilityEmulator* me = (MobilityEmulator*)f;
    String s;
    s += String(me->_connectedNetwork) + "\n";
    return s;
}

int
MobilityEmulator::setConnectedNetwork(const String &conf, Element *e, void *, ErrorHandler * errh)
{
    MobilityEmulator* me = (MobilityEmulator *) e;
    if (me->_intervalPresent && me->_connectedNetworksPresent) {
        click_chatter("Not support when configured with INTERVAL and CONNECTED_NETWORKS");
        return errh->error("Not supported when configured with INTERVAL and CONNECTED_NETWORKS");
    }
    int connectedNetwork;
    if (cp_va_kparse(conf, me, errh, "CONNECTED_NETWORK", cpkM+cpkP, cpInteger, &connectedNetwork, cpEnd) < 0)
        return -1;
    if (connectedNetwork <= 0)
        return errh->error("CONNECTED_NETWORK should be larger or equal to 1");
    me->_connectedNetwork = connectedNetwork;
    return 0;
}


void
MobilityEmulator::add_handlers()
{
    add_read_handler("get_connected_network", getConnectedNetwork, (void *)0);
    add_write_handler("set_connected_network", &setConnectedNetwork, (void *)0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MobilityEmulator)
