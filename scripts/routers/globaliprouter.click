
///===========================================================================///
/// Global IP Router
/// recommended: leave this compound element untouched except 
/// for the routing table 'rt', it is responsible for routing
/// on the backbone. When adding a new foreign network to the
/// IP cloud, you have to add a route to this networks default
/// router here.
///===========================================================================///

elementclass GlobalIPRouter 
{
$addr_info
|
	// Shared IP input path and routing table
	ip :: Strip(14)
	-> CheckIPHeader
	-> rt :: StaticIPLookup(
		$addr_info:ip/32 0,
		192.168.1.0/24 1,
		192.168.2.0/24 192.168.1.2 1,
		192.168.3.0/24 192.168.1.3 1);
	
	// ARP responses are copied to each ARPQuerier and the host.
	arpt :: Tee(1);
	
	// Input and output paths for eth0
	c0 :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
	input[0] -> HostEtherFilter($addr_info:eth) -> c0;
	c0[0] -> ar0 :: ARPResponder($addr_info) -> [0]output;
	arpq0 :: ARPQuerier($addr_info) -> [0]output;
	c0[1] -> arpt;
	arpt[0] -> [1]arpq0;
	c0[2] -> Paint(1) -> ip;
		
	// Local delivery
	rt[0] -> [1]output; 
	
	// Forwarding path for eth0
	rt[1] -> DropBroadcasts
	-> gio0 :: IPGWOptions($addr_info)
	-> FixIPSrc($addr_info)
	-> dt0 :: DecIPTTL
	-> fr0 :: IPFragmenter(1500)
	-> [0]arpq0;
	dt0[1] -> ICMPError($addr_info, timeexceeded) -> rt;
	fr0[1] -> ICMPError($addr_info, unreachable, needfrag) -> rt;
	gio0[1] -> ICMPError($addr_info, parameterproblem) -> rt;
	
}