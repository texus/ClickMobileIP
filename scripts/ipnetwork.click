///================================================================///
///
/// This script implements a small IP network inside click. Several
/// compound elements are used to create the different network entities.
///
/// Authors: Bart Braem & Michael Voorhaen
///================================================================///

require(library routers/globaliprouter.click);
require(library routers/iprouter1int.click);
require(library routers/iprouter2int.click);
require(library routers/mobilenode.click);
require(library routers/homeagent.click);
require(library routers/foreignagent.click);

///===========================================================================///
/// Definitions of the different hosts and related address information.
AddressInfo(global_router_address 192.168.1.254/16 00:50:BA:85:84:E1);
global_router :: GlobalIPRouter(global_router_address);

home_network :: ListenEtherSwitch;
AddressInfo(home_agent_private_address 192.168.2.254/24 00:50:BA:85:84:A1);
AddressInfo(home_agent_public_address 192.168.1.2/16 00:50:BA:85:84:A2);
home_agent :: HomeAgent(home_agent_private_address, home_agent_public_address, global_router_address);

AddressInfo(mobile_node_address 192.168.2.1/24 00:50:BA:85:84:B1);
mobile_node :: MobileNode(mobile_node_address, home_agent_private_address);

foreign_network1 :: ListenEtherSwitch;
AddressInfo(foreign_agent_private_address 192.168.3.254/24 00:50:BA:85:84:C1);
AddressInfo(foreign_agent_public_address 192.168.1.3/16 00:50:BA:85:84:C2);
foreign_agent1 :: ForeignAgent(foreign_agent_private_address, foreign_agent_public_address, global_router_address);

AddressInfo(corresponding_node 192.168.1.1/24 00:50:BA:85:84:D1);
corresponding_node :: IPRouter1int(corresponding_node, global_router_address);

/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
/// !!!!!!! DO NOT EDIT BELOW THIS LINE: Any changes made below, will be replaced prior to the project defense !!!!!!!!
/// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

/// Note: The ListenEtherSwitch is used to emulate a local LAN network.
/// Note: The GlobalIPRouter is used to eliminate the need of a routing protocol
/// at the top level. When adding a new network, please make sure you add a route
/// to this network in the routing table of the Global Router.
ip_cloud :: ListenEtherSwitch;

///===========================================================================///
/// The configuration of our small IP network

/// packets not destined for the global router
global_router[0]
// 	-> Print("global router -- sending a packet on IP cloud")
	-> [0]ip_cloud[0]
// 	-> Print("global router -- Received a packet on IP cloud")
	-> global_router;

/// packets destined for the global router
global_router[1]
// 	->  IPPrint("global router -- Received a packet")
	-> Discard; 

/// packets destined for the home network
home_agent[0]
// 	-> Print("Home Agent -- sending a packet on home network")
	-> [1]home_network[1]
// 	-> Print("Home Agent -- Received a packet on home network")
	-> [0]home_agent;

/// packets destined for the ip cloud
home_agent[1]
// 	-> Print("Home Agent -- Sending a packet on IP cloud")
	-> [2]ip_cloud[2]
// 	-> Print("Home Agent -- Received a packet on IP cloud")
	-> [1]home_agent;

/// packets destined for the home agent
home_agent[2]
// 	-> IPPrint("Home Agent -- Received a packet")
	-> Discard; 

/// packets destined for the foreign network
foreign_agent1[0]
// 	-> Print("Foreign Agent -- Sending a packet on foreign network")
 	-> [1]foreign_network1[1]
// 	-> Print("Foreign Agent -- Received a packet on foreign network")
 	-> [0]foreign_agent1;

/// packets destined for the ip cloud
foreign_agent1[1]
// 	-> Print("Foreign Agent -- Sending a packet to ip cloud")
 	-> [3]ip_cloud[3]
 	-> [1]foreign_agent1;

/// packets destined for the foreign agent
foreign_agent1[2]
// 	-> IPPrint("Foreign Agent -- Received a packet")
	-> Discard; 

/// let the corresponding node send a ping
icmpsrc :: ICMPPingSource(192.168.1.1, 192.168.2.1)
	-> EtherEncap(0x0800, corresponding_node:eth, corresponding_node:eth) /// The MAC addresses here can be dummy once, they are stripped of in the router. This is to make sure whe only need one input on the IPRouter1int
//	-> IPPrint("ping")
	-> [0]corresponding_node;

/// packets destined for the foreign network
corresponding_node[0]
// 	-> Print("Corresponding Node -- Sending a packet to the foreign network")
	-> [1]ip_cloud[1]
// 	-> Print("Corresponding Node -- Receiving a packet on the foreign network")
	-> corresponding_node;

/// packets destined for the corresponding node
corresponding_node[1]
// 	-> IPPrint("Corresponding Node -- Received a packet") 
//	-> IPPrint("pong") 
	-> icmpsrc;

/// packets destined for the mobile node
mobile_node[1]
//	-> IPPrint("Mobile Node -- got ping") 
	-> ICMPPingResponder
//	-> IPPrint("Mobile Node -- sending pong")
	-> EtherEncap(0x0800, mobile_node_address:eth, mobile_node_address:eth) /// The MAC addresses here can be dummy once, they are stripped of in the router. This is to make sure whe only need one input on the IPRouter1int
	-> mobile_node;

mobility_emulator :: MobilityEmulator(INTERVAL 5, CONNECTED_NETWORKS "2, 1");

mobile_node[0]
	-> [0]mobility_emulator[0]
	-> mobile_node;
 
home_network[0]
	-> [1]mobility_emulator[1]
	-> [0]home_network;

foreign_network1[0]
 	-> [2]mobility_emulator[2]
 	-> [0]foreign_network1;

/// Dump the traffic sniffed at the ListenEtherSwitches
home_network[2]
	-> ToDump("homenetwork.dump");
foreign_network1[2]
	-> ToDump("foreignnetwork.dump");
ip_cloud[4]
	-> ToDump("ipcloud.dump");
