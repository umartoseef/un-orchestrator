#include "high_level_graph_vnf.h"

namespace highlevel
{

VNFs::VNFs(string id, string name, string groups, string vnf_template, list<vector<string> > ports, list<pair<string, string> > control_ports) :
	id(id), name(name), groups(groups), vnf_template(vnf_template)
{
	for(list<vector<string> >::iterator p = ports.begin(); p != ports.end(); p++)
	{
		this->ports.push_back((*p));
	}
	
	for(list<pair<string, string> >::iterator c = control_ports.begin(); c != control_ports.end(); c++)
	{
		this->control_ports.push_back((*c));
	}
}

VNFs::~VNFs()
{

}

bool VNFs::operator==(const VNFs &other) const
{
	if(id == other.id && name == other.name)
		return true;
		
	return false;
}

string VNFs::getId()
{
	return id;
}

string VNFs::getName()
{
	return name;
}

string VNFs::getGroups()
{
	return groups;
}

string VNFs::getVnfTemplate()
{
	return vnf_template;
}

list <vector<string> > VNFs::getPorts()
{
	return ports;
}

void VNFs::print()
{
	if(LOGGING_LEVEL <= ORCH_DEBUG_INFO)
	{
		cout << "\t\tid:" << id << endl;
		cout << "\t\t\tname: " << name << endl;
		cout << "\t\t\tvnf_template: " << vnf_template << endl;
		cout << "\t\t\tgroups: " << groups << endl;
		cout << "\t\t\tports: " << endl << "\t\t{" << endl;
		for(list<vector<string> >::iterator p = ports.begin(); p != ports.end(); p++)
		{
			cout << "\t\t\tid: " << (*p)[0] << endl;
			cout << "\t\t\tname: " << (*p)[1] << endl;
			if(!(*p)[2].empty())
				cout << "\t\t\tmac: " << (*p)[2] << endl;
			if(!(*p)[3].empty())
				cout << "\t\t\tip: " << (*p)[3] << endl;
		}
		cout << "\t\t\tcontrol: " << endl << "\t\t{" << endl;
		for(list<pair<string, string> >::iterator c = control_ports.begin(); c != control_ports.end(); c++)
		{
			cout << "\t\t\thost-tcp-port: " << (*c).first << endl;
			cout << "\t\t\tvnf-tcp-port: " << (*c).second << endl;
		}
		cout << "\t\t}" << endl;
	}
}

Object VNFs::toJSON()
{
	Object vnf;
	Array portS, ctrl_ports;
	
	vnf[_ID] = id.c_str();
	vnf[_NAME] = name.c_str();
	vnf[VNF_TEMPLATE] = vnf_template.c_str();
	if(strcmp(groups.c_str(), "") != 0)
		vnf[VNF_GROUPS] = groups;
	
	for(list<vector<string> >::iterator p = ports.begin(); p != ports.end(); p++)
	{
		Object pp;
		
		pp[_ID] = (*p)[0].c_str();
		pp[_NAME] = (*p)[1].c_str();
		pp[PORT_MAC] = (*p)[2].c_str();
		pp[PORT_IP] = (*p)[3].c_str();
		
		portS.push_back(pp);
	}
	
	for(list<pair<string, string> >::iterator c = control_ports.begin(); c != control_ports.end(); c++)
	{
		Object cc;
		
		cc[HOST_PORT] = (*c).first.c_str();
		cc[VNF_PORT] = (*c).second.c_str();
		
		ctrl_ports.push_back(cc);
	}
	
	vnf[VNF_PORTS] = portS;
	vnf[VNF_CONTROL] = ctrl_ports;
	
	return vnf;
}

}
