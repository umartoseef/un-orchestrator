#ifndef HIGH_LEVEL_GRAPH_VNFS_H_
#define HIGH_LEVEL_GRAPH_VNFS_H_ 1

#include "../../../utils/logger.h"
#include "../../../utils/constants.h"

#include <iostream>
#include <sstream>

#include <string.h>
#include <list>

#include <json_spirit/json_spirit.h>
#include <json_spirit/value.h>
#include <json_spirit/writer.h>

using namespace json_spirit;
using namespace std;

namespace highlevel
{

class VNFs
{
private:
	/**
	*	@brief: the id of the VNF (e.g., 00000003)
	*/
	string id;
	
	/**
	*	@brief: the name of the VNF (e.g., example)
	*/
	string name;
	
	/**
	*	@brief: the groups of the VNF (e.g., example)
	*/
	string groups;
	
	/**
	*	@brief: the vnf template of the VNF (e.g., example.json)
	*/
	string vnf_template;
	
	/**
	*	@brief: the list of ports configuration of the VNF
	*/
	list<vector<string> > ports;
	
	/**
	*	@brief: the list of control ports configuration of the VNF
	*/
	list<pair<string, string> > control_ports;
	
public:

	VNFs(string id, string name, string groups, string vnf_template, list<vector<string> > ports, list<pair<string, string> > control_ports);
	string getId();
	string getName();
	string getGroups();
	string getVnfTemplate();
	list<vector<string> > getPorts();
	list<pair<string, string> > getControlPorts();
	
	~VNFs();
	
	bool operator==(const VNFs &other) const;
	
	void print();
	Object toJSON();
};

}

#endif //HIGH_LEVEL_GRAPH_VNFS_H_
