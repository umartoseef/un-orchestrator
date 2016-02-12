#ifndef CONSTANTS_H_
#define CONSTANTS_H_ 1

#define MODULE_NAME 			"Local-Orchestrator"

/*
*	Connections
*/
#define OF_CONTROLLER_ADDRESS 		"127.0.0.1"
#define FIRTS_OF_CONTROLLER_PORT	6653

#define REST_PORT 				8080
#define BASE_URL_GRAPH			"NF-FG"
#define BASE_URL_IFACES			"interfaces"
#define BASE_URL_LOGIN			"login"
#define REST_URL 				"http://localhost"
#define REQ_SIZE 				2*1024*1024

/*
*	Rest methods
*/
#define PUT						"PUT"
#define GET						"GET"
#define DELETE					"DELETE"
#ifdef UNIFY_NFFG
	#define POST				"POST"
#endif

#define POST				"POST"

/*
*	HTTP headers
*/
#define JSON_C_TYPE				"application/json"
#define NO_CACHE				"no-cache"

/*
*	Costants in the JSON describing the graph
*	XXX: the list of supported matches and actions MUST be aligned with those
*	in [orchestrator]/node_resource_manager/virtualizer/constants.py
*/

#define TCP			"tcp"

#define FORWARDING_GRAPH	"forwarding-graph"
	//#define F_ID				"id"
	#define _NAME				"name"
	#define F_DESCR				"description"
	#define VNFS 				"VNFs"
		//#define VNF_NAME			"name"
		#define	VNF_TEMPLATE		"vnf_template"
		#define VNF_CONTROL			"unify-control"
			#define HOST_PORT			"host-tcp-port"
			#define VNF_PORT			"vnf-tcp-port"
		#define	VNF_PORTS			"ports"
			//#define PORT_ID			"id"
			//#define PORT_NAME		"name"
			#define PORT_MAC			"mac"
			#define PORT_IP				"unify-ip"
		#define	VNF_GROUPS		"groups"
	#define END_POINTS		"end-points"
		//#define EP_ID     		"id"
		//#define EP_NAME     		"name"
		#define EP_TYPE			"type"
		#define EP_REM			"remote_endpoint_id"
		#define EP_PR			"prepare_connection_to_remote_endpoint_ids"
		//#define EP_IFACE   		"interface"
		#define EP_IFACE_OUT	"interface-out"
			#define NODE_ID			"node-id"
			#define SW_ID			"switch-id"
			#define IFACE			"interface"
		#define EP_GRE			"gre-tunnel"
			//#define GRE				"gre"
			#define LOCAL_IP		"local-ip"
			#define REMOTE_IP		"remote-ip"
			#define TTL				"ttl"
			#define GRE_KEY			"gre-key"
			#define SAFE			"secure"
		#define VLAN			"vlan"
			#define V_ID			"vlan-id"
						
	#define BIG_SWITCH		"big-switch"
		#define FLOW_RULES		"flow-rules"
			#define _ID				"id"
			#define PRIORITY		"priority"
			#define MATCH			"match"
				#define HARD_TIMEOUT	"hard_timeout"
				#define VLAN_PRIORITY 	"vlan_priority"
				#define TOS_BITS		"tos_bits"
				#define	PORT_IN			"port_in"
					#define VNF 			"vnf"
				#define PROTOCOL		"protocol"
				#define ETH_SRC			"source_mac"
				#define ETH_SRC_MASK	"eth_src_mask"
				#define ETH_DST			"dest_mac"
				#define ETH_DST_MASK "eth_dst_mask"
				#define ETH_TYPE		"ether_type"
				#define VLAN_ID			"vlan_id"
					#define ANY_VLAN		"ANY"
					#define NO_VLAN			"NO_VLAN"
				#define VLAN_PCP	"vlan_pcp"
				#define IP_DSCP			"ip_dscp"
				#define IP_ECN			"ip_ecn"
				#define IP_PROTO	"ip_proto"
				#define IP_SRC			"source_ip"
				#define IPv4_SRC_MASK	"ipv4_src_mask"
				#define IP_DST			"dest_ip"
				#define IPv4_DST_MASK	"ipv4_dst_mask"
				#define IPv6_SRC_MASK	"ipv6_src_mask"
				#define IPv6_DST_MASK	"ipv6_dst_mask"
				#define IPv6_FLABEL		"ipv6_flabel"
				#define IPv6_ND_TARGET	"ipv6_nd_target"
				#define IPv6_ND_SLL		"ipv6_nd_sll"
				#define IPv6_ND_TLL		"ipv6_nd_tll"
				#define PORT_SRC		"source_port"
				#define PORT_DST		"dest_port"
				#define SCTP_SRC		"sctp_src"
				#define SCTP_DST		"sctp_dst"
				#define ICMPv4_TYPE		"icmpv4_type"
				#define ICMPv4_CODE		"icmpv4_code"
				#define ARP_OPCODE		"arp_opcode"
				#define ARP_SPA			"arp_spa"
				#define ARP_SPA_MASK	"arp_spa_mask"
				#define ARP_TPA			"arp_tpa"
				#define ARP_TPA_MASK	"arp_tpa_mask"
				#define ARP_SHA			"arp_sha"
				#define ARP_THA			"arp_tha"
				#define ICMPv6_TYPE		"icmpv6_type"
				#define ICMPv6_CODE		"icmpv6_code"
				#define MPLS_LABEL		"mpls_label"
				#define MPLS_TC			"mpls_tc"
				#define ACTIONS			"actions"
				#define OUTPUT				"output_to_port"
					#define	PORT				"port"
					//#define	VNF_ID				"id"
					#define ENDPOINT			"endpoint"
				#define SET_VLAN_ID			"set_vlan_id"
				#define SET_VLAN_PRIORITY	"set_vlan_priority"
				#define VLAN_PUSH			"push_vlan"
				#define VLAN_POP			"pop_vlan"
				#define SET_ETH_SRC_ADDR	"set_ethernet_src_address"
				#define SET_ETH_DST_ADDR	"set_ethernet_dst_address"
				#define SET_IP_SRC_ADDR		"set_ip_src_address"
				#define SET_IP_DST_ADDR		"set_ip_dst_address"
				#define SET_IP_TOS			"set_ip_tos"
				#define SET_L4_SRC_PORT		"set_l4_src_port"
				#define SET_L4_DST_PORT		"set_l4_dst_port"
				#define OUT_TO_QUEUE		"output_to_queue"
				#define DROP 				"drop"
				#define OUTPUT_TO_CTRL		"output_to_controller"
			
/*
*	Misc
*/
#define BUFFER_SIZE				20480
#define DATA_BUFFER_SIZE		20480
#define BUF_SIZE				64

/*
*	Network functions
*/
#define CORE_MASK				0x2

/**
*	@brief: Constants related to the configuration file containing the description of the physical ports
*
*	XXX This constants must be updated in case the XML schema is modified
*/
#define PHY_PORTS_XSD			"universal-node-schema.xsd"

#define RESOURCES_ELEMENT		"resources"
#define CPU_ELEMENT				"cpu"
#define MEMORY_ELEMENT			"memory"
#define STORAGE_ELEMENT			"storage"
#define AMOUNT_ATTRIBUTE		"amount"
#define UNIT_ATTRIBUTE			"unit"

#define PORTS_ELEMENT			"ports"
#define PORT_ELEMENT			"port"
#define NAME_ATTRIBUTE			"name"
#define TYPE_ATTRIBUTE			"type"
#define SIDE_ATTRIBUTE			"side"

#define VIRTUALIZED_ELEMENT		"virtualized"
#define AS_ATTRIBUTE			"as"
#define PORT_TYPE_ATTRIBUTE		"port-type"
#define SAP_ATTRIBUTE			"sap"

#define TYPE_ETHERNET			"ethernet"
#define TYPE_WIFI				"wifi"

#define SIDE_CORE				"core"
#define SIDE_EDGE				"edge"
#define SIDE_NONE				"none"

/*
 * Supported Openflow versions.
 */
typedef enum
{
	OFP_10 = 1,
	OFP_12,
	OFP_13
}ofp_version_t;
extern ofp_version_t OFP_VERSION;

/*
 * Constants used by Libvirt
 */
 #define MEMORY_SIZE 				"4194304"
 #define NUMBER_OF_CORES			 "4"

/*
 *	Misc
 */
 #define GRAPH_ID					"NF-FG"

/*
 * Constant required with the Unify NF-FG library is used
 */
#ifdef UNIFY_NFFG
	#define PYTHON_DIRECTORY    "node_resource_manager/virtualizer"
	#define PYTHON_MAIN_FILE    "virtualizer"

	/*
	* Python functionas
	*/
	#define PYTHON_INIT					"init"
	#define PYTHON_TERMINATE			"terminate"
	#define PYTHON_ADDRESOURCES			"addResources"
	#define PYTHON_ADDNODEPORT			"addNodePort"
	#define PYTHON_EDIT_PORT_ID			"editPortID"
	#define PYTHON_ADD_SUPPORTED_VNFs	"addSupportedVNFs"
	#define PYTHON_HANDLE_REQ			"handle_request"
	
	/*
	* File containing the NF-FG to be implemented
	*/
	#define NEW_GRAPH_FILE				"./node_resource_manager/virtualizer/.new_graph.json"
	
	/*
	* File containing the rules to be removed from the graph
	*/
	#define REMOVE_GRAPH_FILE			"./node_resource_manager/virtualizer/.remove_graph.json"
#endif	

/*
*	Name of the file used to print log information
*/
#ifdef LOG_ON_FILE
	#define LOG_FILE			"node-orchestrator.log"
#endif

#define ADMIN				"admin"
#define USER				"username"
#define PASS				"password"
#define HASH_SIZE			20
#define TOKEN_TYPE			"application/token"
#define DB_NAME				"users.db"
#define DEFAULT_FILE			"config/default-config.ini"

/*
*	OpenFlow
*/
#define HIGH_PRIORITY 		65535

/*
*	Misc
*/
#define DEFAULT_GRAPH 		"DEFAULT-GRAPH"

#endif //CONSTANTS_H_
