#ifndef HIGH_LEVEL_GRAPH_ENPOINT_GRE_H_
#define HIGH_LEVEL_GRAPH_ENPOINT_GRE_H_ 1

#include "../../../utils/logger.h"
#include "../../../utils/constants.h"

#include <iostream>
#include <sstream>

#include <string.h>

#include <json_spirit/json_spirit.h>
#include <json_spirit/value.h>
#include <json_spirit/writer.h>

using namespace json_spirit;
using namespace std;

namespace highlevel
{

class EndPointGre
{
private:
	/**
	*	@brief: the id of the endpoint (e.g., 00000003)
	*/
	string id;
	
	/**
	*	@brief: the name of the endpoint port (e.g., ingress)
	*/
	string name;
	
	/**
	*	@brief: the local ip of the gre tunnel (e.g., 10.0.0.1)
	*/
	string local_ip;
	
	/**
	*	@brief: the remote ip of the gre tunnel (e.g., 10.0.0.2)
	*/
	string remote_ip;
	
	/**
	*	@brief: the interface of the gre tunnel (e.g., 10.0.0.3)
	*/
	string interface;
	
	/**
	*	@brief: the key of the gre tunnel (e.g., 1)
	*/
	string gre_key;
	
	/**
	*	@brief: the ttl of the gre tunnel (e.g., 2)
	*/
	string ttl;
	
	/**
	*	@brief: true (GRE tunnel over IPsec), false (GRE tunnel)
	*/
	bool is_safe;
	
public:

	EndPointGre(string id, string name, string local_ip, string remote_ip, string interface, string gre_key, string ttl, bool is_safe);
	string getId();
	string getName();
	string getLocalIp();
	string getRemoteIp();
	string getInterface();
	string getGreKey();
	string getTtl();
	bool isSafe();
	
	~EndPointGre();
	
	bool operator==(const EndPointGre &other) const;
	
	void print();
	Object toJSON();
};

}

#endif //HIGH_LEVEL_GRAPH_ENPOINT_GRE_H_
