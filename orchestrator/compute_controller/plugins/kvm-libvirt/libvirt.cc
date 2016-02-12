#include "libvirt.h"
#include "libvirt_constants.h"

#include <memory>

#ifndef DIRECT_KVM_IVSHMEM
	virConnectPtr Libvirt::connection = NULL;
#else
	pthread_mutex_t Libvirt::Libvirt_mutex = PTHREAD_MUTEX_INITIALIZER;
	unsigned int Libvirt::next_tcp_port = FIRST_PORT_FOR_MONITOR;
	map<string,string> Libvirt::monitor;
#endif

#ifndef DIRECT_KVM_IVSHMEM
void Libvirt::customErrorFunc(void *userdata, virErrorPtr err)
{
	logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Failure of libvirt library call:");
	logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "\tCode: %d", err->code);
	logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "\tDomain: %d", err->domain);
	logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "\tMessage: %s", err->message);
	logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "\tLevel: %d", err->level);
	logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "\tstr1: %s", err->str1);
	logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "\tstr2: %s", err->str2);
	logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "\tstr3: %s", err->str3);
	logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "\tint1: %d", err->int1);
	logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "\tint2: %d", err->int2);
}
#endif

Libvirt::Libvirt()
{
#ifndef DIRECT_KVM_IVSHMEM
	virSetErrorFunc(NULL, customErrorFunc);
	connect();
#endif
}

Libvirt::~Libvirt()
{
#ifndef DIRECT_KVM_IVSHMEM
	if(connection != NULL)
		disconnect();
#endif
}

string Libvirt::splitIpNetmask(string ip_netmask)
{
	char delimiter[] = "/";
	char tmp[BUFFER_SIZE];
	strcpy(tmp,ip_netmask.c_str());
	char *pnt=strtok((char*)ip_netmask.c_str(), delimiter);
	string ip_address;

	int i = 0;
	while( pnt!= NULL )
	{
		switch(i)
		{
			case 0:
				ip_address = string(pnt);
				return ip_address;
			break;
		}
		
		pnt = strtok( NULL, delimiter );
		i++;
	}
}

bool Libvirt::isSupported(Description&)
{
#ifndef DIRECT_KVM_IVSHMEM
	connect();

	if(connection == NULL)
		return false;
#endif

	//TODO check if it supported in case of plain QEMU
	return true;
}

#ifndef DIRECT_KVM_IVSHMEM
void Libvirt::connect()
{
	if(connection != NULL)
		//The connection is already open
		return;

	logger(ORCH_DEBUG_INFO, KVM_MODULE_NAME, __FILE__, __LINE__, "Connecting to Libvirt ...");
	connection = virConnectOpen("qemu:///system");
	if (connection == NULL)
		logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Failed to open connection to qemu:///system");
	else
		logger(ORCH_DEBUG_INFO, KVM_MODULE_NAME, __FILE__, __LINE__, "Open connection to qemu:///system successfull");
}

void Libvirt::disconnect()
{
	virConnectClose(connection);
	connection = NULL;
}
#endif

#ifdef VSWITCH_IMPLEMENTATION_ERFS
//#define VSWITCH_IMPLEMENTATION_ERFS_DIRECT_KVM
#endif

#ifdef VSWITCH_IMPLEMENTATION_ERFS_DIRECT_KVM
// No need for command line generator, ERFS generates the command line for Qemu
bool Libvirt::startNF(StartNFIn sni)
{
    const char *a = QEMU_BIN_PATH;
    const char *b = OVS_BASE_SOCK_PATH;
    if (a == b);

    stringstream ports;
    list<string> namesOfPortsOnTheSwitch = sni.getNamesOfPortsOnTheSwitch();
    int port_id = 0;
    for(list<string>::iterator name = namesOfPortsOnTheSwitch.begin(); name != namesOfPortsOnTheSwitch.end(); name++) {
        PortType port_type = description->getPortTypes().at(port_id);
        logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "KVM VNF Port %d (%s) is of type %d", port_id, (*name).c_str(), port_type);
        ports << port_id + 1 << ",";
        port_id++;
    }
    logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "ports: (%s)", ports.str().c_str());

    // Get image name
    stringstream command;
    char image_path[512];
    command << "cat " << description->getURI().c_str() << " | grep 'source file' | awk -F '\"' '{print $2}'";
    logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "command for getting image file: %s", command.str().c_str());
    FILE *out = popen(command.str().c_str(), "r");
    if (out) {
        int res = fscanf(out, "%s", image_path);
        if (res) {
            logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "image path: (%s)", image_path);
        }
        else {
            logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "error in getting image path");
            return false;
        }
    }
    else {
        logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "can not open file");
        return false;
    }

    // TODO: number of cores and core mask is to be added
    command.str("");
    command.clear();
    command << QEMU_ERFS << " " << sni.getLsiID() << " " << sni.getNfName();
    command << " " << image_path << " " << ports.str().c_str();
    logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "command for starting KVM: (%s)", command.str().c_str());

    int retVal = system(command.str().c_str());
    if(retVal != 0)
        return false;
    return true;
}
#else
#if not defined(DIRECT_KVM_IVSHMEM)
bool Libvirt::startNF(StartNFIn sni)
{
	virDomainPtr dom = NULL;
	char domain_name[64];
	const char *xmlconfig = NULL;

	string nf_name = sni.getNfName();
	string uri_image = description->getURI();

	/* Domain name */
	sprintf(domain_name, "%" PRIu64 "_%s", sni.getLsiID(), nf_name.c_str());

	logger(ORCH_DEBUG_INFO, KVM_MODULE_NAME, __FILE__, __LINE__, "Using Libvirt XML template %s", uri_image.c_str());
	xmlInitParser();

	xmlDocPtr doc;
	xmlXPathContextPtr xpathCtx;
	xmlXPathObjectPtr xpathObj;

	/* Load XML document */
	doc = xmlParseFile(uri_image.c_str());
	if (doc == NULL) {
		logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Unable to parse file \"%s\"", uri_image.c_str());
		return 0;
	}

	/* xpath evaluation for Libvirt various elements we may want to update */
	xpathCtx = xmlXPathNewContext(doc);
	if(xpathCtx == NULL) {
		logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Unable to create new XPath context");
		xmlFreeDoc(doc);
		return 0;
	}
	const xmlChar* xpathExpr = BAD_CAST "/domain/devices/interface|/domain/name|/domain/devices/emulator";
	xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
	if(xpathObj == NULL) {
		logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Error: unable to evaluate xpath expression \"%s\"", xpathExpr);
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return 0;
	}

	enum E_updates {
		EMULATOR_UPDATED = 0x01,
		DOMAIN_NAME_UPDATED = 0x02,
	};
	uint32_t update_flags = 0;

	xmlNodeSetPtr nodes = xpathObj->nodesetval;
	int size = (nodes) ? nodes->nodeNr : 0;
    logger(ORCH_DEBUG_INFO, KVM_MODULE_NAME, __FILE__, __LINE__, "xpath return size: %d", size);
	int i;
	for(i = size - 1; i >= 0; i--) {
	  	xmlNodePtr node = nodes->nodeTab[i];

		if (node != NULL) {
			switch (node->type) {
		   		case XML_ELEMENT_NODE:
		   			if (xmlStrcmp(node->name, (xmlChar*)"name") == 0) {
		   				xmlNodeSetContent(node, BAD_CAST domain_name);
		   				update_flags |= DOMAIN_NAME_UPDATED;
		   			}
		   			else if (xmlStrcmp(node->name, (xmlChar*)"emulator") == 0) {
		   				if (QEMU_BIN_PATH) {
		   					xmlNodeSetContent(node, (xmlChar*)QEMU_BIN_PATH);
							update_flags |= EMULATOR_UPDATED;
		   				}
		   			}
		   			else if (xmlStrcmp(node->name, (xmlChar*)"interface") == 0) {
		   				// Currently we just remove any net interface device present in the template and re-create our own
		   				// with the exception of bridged interfaces which are handy for managing the VM.
		   				xmlChar* type = xmlGetProp(node, (xmlChar*)"type");
		   				if (xmlStrcmp(type, (xmlChar*)"bridge") == 0) {
							xmlFree(type);
		   					continue;
		   				}
		   				xmlUnlinkNode(node);
		   				xmlFreeNode(node);
		   			}
		   			break;
		   		case XML_ATTRIBUTE_NODE:
		   			logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "ATTRIBUTE found here");
		   			break;
		   		default:
		   			logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Other type");
		   			break;
		   	}
		}

		/*
		 * All the elements returned by an XPath query are pointers to
		 * elements from the tree *except* namespace nodes where the XPath
		 * semantic is different from the implementation in libxml2 tree.
		 * As a result when a returned node set is freed when
		 * xmlXPathFreeObject() is called, that routine must check the
		 * element type. But node from the returned set may have been removed
		 * by xmlNodeSetContent() resulting in access to freed data.
		 * This can be exercised by running
		 *       valgrind xpath2 test3.xml '//discarded' discarded
		 * There is 2 ways around it:
		 *   - make a copy of the pointers to the nodes from the result set
		 *     then call xmlXPathFreeObject() and then modify the nodes
		 * or
		 *   - remove the reference to the modified nodes from the node set
		 *     as they are processed, if they are not namespace nodes.
		 */
		 if (nodes->nodeTab[i]->type != XML_NAMESPACE_DECL) {
		      nodes->nodeTab[i] = NULL;
		 }
	}

	/* Cleanup of XPath data */
	xmlXPathFreeObject(xpathObj);

    /* Add domain name if not present */
    if (0 == (update_flags & DOMAIN_NAME_UPDATED)) {
		xmlNewTextChild(xmlDocGetRootElement(doc), NULL, BAD_CAST "name", BAD_CAST domain_name);
    }

	/* Create xpath evaluation context for Libvirt domain/devices */
	/* Evaluate xpath expression */
	const xmlChar* xpathExpr_devs = BAD_CAST "/domain/devices";
	xpathObj = xmlXPathEvalExpression(xpathExpr_devs, xpathCtx);
	if(xpathObj == NULL) {
		logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Error: unable to evaluate xpath expression \"%s\"", xpathExpr);
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return 0;
	}
	nodes = xpathObj->nodesetval;
	if (!nodes || (nodes->nodeNr != 1)) {
		logger(ORCH_DEBUG_INFO, KVM_MODULE_NAME, __FILE__, __LINE__, "xpath(devices) failed accessing <devices> node");
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return 0;
	}

    xmlNodePtr devices = nodes->nodeTab[0];

    /* Add emulator if not present and must be modified */
    if ((0 == (update_flags & EMULATOR_UPDATED)) && (QEMU_BIN_PATH != NULL)) {
    	xmlNewTextChild(devices, NULL, BAD_CAST "emulator", BAD_CAST QEMU_BIN_PATH);
    }

	/* Create XML for VM */

	/* Create NICs */
	vector< pair<string, string> > ivshmemPorts; // name, alias

	map<unsigned int, string> namesOfPortsOnTheSwitch = sni.getNamesOfPortsOnTheSwitch();
	list<pair<string, string> > portsConfiguration = sni.getPortsConfiguration();
	list<pair<string, string> >::iterator pd = portsConfiguration.begin();
	string port_ip_address = pd->second;
	
	/* retrieve ip address */
	string ip_address = splitIpNetmask(port_ip_address);
	
	for(map<unsigned int, string>::iterator p = namesOfPortsOnTheSwitch.begin(); p != namesOfPortsOnTheSwitch.end(); p++)
	{
		const unsigned int port_id = p->first;
		const string& port_name = p->second;
		string port_mac_address = pd->first;

		PortType port_type = description->getPortTypes().at(port_id);
		logger(ORCH_DEBUG_INFO, KVM_MODULE_NAME, __FILE__, __LINE__, "NF Port \"%s\":%d (%s) is of type %s", nf_name.c_str(), port_id, port_name.c_str(), portTypeToString(port_type).c_str());

	    if (port_type == USVHOST_PORT) {
			xmlNodePtr ifn = xmlNewChild(devices, NULL, BAD_CAST "interface", NULL);
		    xmlNewProp(ifn, BAD_CAST "type", BAD_CAST "vhostuser");

			xmlNodePtr srcn = xmlNewChild(ifn, NULL, BAD_CAST "source", NULL);
			ostringstream sock_path_os;
			sock_path_os << OVS_BASE_SOCK_PATH << port_name;
			xmlNewProp(srcn, BAD_CAST "type", BAD_CAST "unix");
			xmlNewProp(srcn, BAD_CAST "path", BAD_CAST sock_path_os.str().c_str());
			xmlNewProp(srcn, BAD_CAST "mode", BAD_CAST "client");

		    xmlNodePtr modeln = xmlNewChild(ifn, NULL, BAD_CAST "model", NULL);
		    xmlNewProp(modeln, BAD_CAST "type", BAD_CAST "virtio");

		    xmlNodePtr drvn = xmlNewChild(ifn, NULL, BAD_CAST "driver", NULL);
		    xmlNodePtr drv_hostn = xmlNewChild(drvn, NULL, BAD_CAST "host", NULL);
		    xmlNewProp(drv_hostn, BAD_CAST "csum", BAD_CAST "off");
		    xmlNewProp(drv_hostn, BAD_CAST "gso", BAD_CAST "off");
		    xmlNodePtr drv_guestn = xmlNewChild(drvn, NULL, BAD_CAST "guest", NULL);
		    xmlNewProp(drv_guestn, BAD_CAST "tso4", BAD_CAST "off");
		    xmlNewProp(drv_guestn, BAD_CAST "tso6", BAD_CAST "off");
		    xmlNewProp(drv_guestn, BAD_CAST "ecn", BAD_CAST "off");
	    }
	    else if (port_type == IVSHMEM_PORT) {
			ostringstream local_name;  // Name of the port as known by the VNF internally - We set a convention here
			local_name << "p" << port_id;  // Will result in p<n>_tx and p<n>_rx rings

			ivshmemPorts.push_back(pair<string, string>(port_name, local_name.str()));
	    }
	    else if (port_type == VHOST_PORT) {
			xmlNodePtr ifn = xmlNewChild(devices, NULL, BAD_CAST "interface", NULL);
			xmlNewProp(ifn, BAD_CAST "type", BAD_CAST "direct");

			if(!port_mac_address.empty())
			{
				xmlNodePtr mac_addr = xmlNewChild(ifn, NULL, BAD_CAST "mac", NULL);
				xmlNewProp(mac_addr, BAD_CAST "address", BAD_CAST port_mac_address.c_str());
			}
#ifdef ENABLE_VNF_PORTS_IP_CONFIGURATION
			if(!ip_address.empty())
			{
				xmlNodePtr ip_addr = xmlNewChild(ifn, NULL, BAD_CAST "ip", NULL);
				xmlNewProp(ip_addr, BAD_CAST "address", BAD_CAST ip_address.c_str());
			}
#endif	
			xmlNodePtr srcn = xmlNewChild(ifn, NULL, BAD_CAST "source", NULL);
			xmlNewProp(srcn, BAD_CAST "dev", BAD_CAST port_name.c_str());
			xmlNewProp(srcn, BAD_CAST "mode", BAD_CAST "passthrough");

		    xmlNodePtr modeln = xmlNewChild(ifn, NULL, BAD_CAST "model", NULL);
		    xmlNewProp(modeln, BAD_CAST "type", BAD_CAST "virtio");

		    xmlNodePtr virt = xmlNewChild(ifn, NULL, BAD_CAST "virtualport", NULL);
		    xmlNewProp(virt, BAD_CAST "type", BAD_CAST "openvswitch");
	    }
	    else
	    {
	    	assert(0 && "There is a BUG! You cannot be here!");
	    	logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Something went wrong in the creation of the ports for the VNF...");
	    	return false;
	    }
	    
	    pd++;
	}

	if (! ivshmemPorts.empty()) {
		char cmdline[512];
        vector<string> ivshmemCmdElems;

#ifdef VSWITCH_IMPLEMENTATION_ERFS
        stringstream ports;

        ostringstream cmd;
        cmd << "group-ivshmems " << sni.getLsiID() << "." << sni.getNfName();
        for (vector< pair<string, string> >::iterator it = ivshmemPorts.begin(); it != ivshmemPorts.end(); ++it) {
            cmd << " IVSHMEM:" << sni.getLsiID() << "-" << it->first;
        }
        logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Generating IVSHMEM QEMU command line using ERFS cmd: %s", cmd.str().c_str());

        ostringstream oss;
        oss << "echo " << cmd.str().c_str() << " | nc localhost 16632"; // FIXME: this should be a parameter later
        logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "final command: %s", oss.str().c_str());

        int r = system(oss.str().c_str());
        if(r == -1 || WEXITSTATUS(r) == -1) {
            logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Error executing command line generator");
        }

        char name[256];
        sprintf(name, "/tmp/ivshmem_qemu_cmdline_%lu.%s", sni.getLsiID(), sni.getNfName().c_str());
        FILE *f = fopen(name, "r");
        if(f == NULL) {
            logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Error opening file");
            return false;
        }
        if(fgets(cmdline, sizeof(cmdline), f) == NULL) {
            logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__,"Error in reading file");
            return false;
        }
        logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__,"commandline: %s", cmdline);
        ivshmemCmdElems.push_back(cmdline);
#else

        IvshmemCmdLineGenerator ivshmemCmdGenerator;

#if 1
        if(!ivshmemCmdGenerator.get_single_cmdline(cmdline, sizeof(cmdline), domain_name, ivshmemPorts)) {
            return false;
        }

        logger(ORCH_DEBUG_INFO, KVM_MODULE_NAME, __FILE__, __LINE__, "Command line for ivshmem '%s'", cmdline);
        ivshmemCmdElems.push_back(cmdline);
#else
        // Mempool(s)
    	if(!ivshmemCmdGenerator.get_mempool_cmdline(cmdline, sizeof(cmdline))) {
    		return false;
    	}
        ivshmemCmdElems.push_back(cmdline);
        // Port rings
        for (vector< pair<string,string> >::iterator it = ivshmemPorts.begin(); it != ivshmemPorts.end(); ++it) {
            if(!ivshmemCmdGenerator.get_port_cmdline((it->first).c_str(), (it->second).c_str(), cmdline, sizeof(cmdline))) {
                return false;
            }
            ivshmemCmdElems.push_back(cmdline);
        }
#endif // 1
#endif // ERFS

		if (! ivshmemCmdElems.empty()) {
			xmlNodePtr rootEl = xmlDocGetRootElement(doc);
			xmlNodePtr cmdLineEl = xmlNewChild(rootEl, NULL, BAD_CAST "qemu:commandline", NULL);
			for (vector<string>::iterator it = ivshmemCmdElems.begin(); it != ivshmemCmdElems.end(); ++it) {
				const char* START_KEY = "-device ";
				if (it->compare(0, sizeof(START_KEY), START_KEY) == 0) {
					xmlNodePtr argEl = xmlNewChild(cmdLineEl, NULL, BAD_CAST "qemu:arg", NULL);
				    xmlNewProp(argEl, BAD_CAST "value", BAD_CAST it->substr(0, sizeof(START_KEY)-1).c_str());
				    argEl = xmlNewChild(cmdLineEl, NULL, BAD_CAST "qemu:arg", NULL);
				    xmlNewProp(argEl, BAD_CAST "value", BAD_CAST it->substr(sizeof(START_KEY)).c_str());
				}
				else {
					logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Unexpected result from IVSHMEM command line generation: %s", it->c_str());
					return false;
				}
			}
		}
	}

	/* Cleanup of XPath data */
	xmlXPathFreeContext(xpathCtx);

	/* Get resulting document */
	xmlChar* xml_buf; int xml_bufsz;
	xmlDocDumpMemory(doc, &xml_buf, &xml_bufsz);
	xmlconfig = (const char *)xml_buf;

	/* Final XML Cleanup */
	xmlFreeDoc(doc);
	
	/**
	*	IVANO: the following function MUST not be called here. In fact, according to the documentation
	*	"If your application is multithreaded or has a plugin support calling this may crash the application has
	*	another thread or plugin is still using libxml2."
	*/
	// xmlCleanupParser();

#ifdef DEBUG_KVM
	stringstream filename;
	filename << domain_name << ".xml";
	logger(ORCH_DEBUG_INFO, KVM_MODULE_NAME, __FILE__, __LINE__, "Dumping XML to %s", filename.str().c_str());
	FILE* fp = fopen(filename.str().c_str(), "w");
	if (fp) {
		fwrite(xmlconfig, 1, strlen(xmlconfig), fp);
		fclose(fp);
	}
#endif

	assert(connection != NULL);

	dom = virDomainCreateXML(connection, xmlconfig, 0);
	if (!dom) {
//		virDomainFree(dom);
		logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Domain definition failed");
		return false;
	}

	logger(ORCH_DEBUG_INFO, KVM_MODULE_NAME, __FILE__, __LINE__, "Boot guest");

	virDomainFree(dom);

	return true;
}
#else // if not defined(ENABLE_KVM_IVSHMEM)
bool Libvirt::startNF(StartNFIn sni)
{
	//XXX: Libvirt do not define xml tags to define an ivhsmem device to be attached with the virtual machine.
	//However, it define the <qemu:commandline> tag to provide to libvirt generic strings to be used in the
	//qemu command line. Unfortunately, through this mechanism we got an error when libvirt tries to boot the VM.
	//As a consequence, we decide to directly use the QEMU command line for ivshmem virtual machine. I know, this
	//way the code is dirty, but it seems to be the better (fastest) solution to implement ivhsmem support in the
	//universal node.

	//XXX: we ignore all the information written in the xml file, except the path with the VM image

	logger(ORCH_DEBUG_INFO, KVM_MODULE_NAME, __FILE__, __LINE__, "This function is KVM-IVSHMEM");


	char domain_name[64];
	string nf_name = sni.getNfName();
	string uri_image = description->getURI();

	/* Domain name */
	sprintf(domain_name, "%" PRIu64 "_%s", sni.getLsiID(), nf_name.c_str());

	//Parse the VM template

	xmlInitParser();
	xmlDocPtr doc;

	/* Load XML document */
	doc = xmlParseFile(uri_image.c_str());
	if (doc == NULL) {
		logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Unable to parse file \"%s\"", uri_image.c_str());
		return 0;
	}

	char *disk_path = NULL;

	xmlNodePtr root = xmlDocGetRootElement(doc);
	for(xmlNodePtr cur_root_child=root->xmlChildrenNode; cur_root_child!=NULL; cur_root_child=cur_root_child->next)
	{
		if ((cur_root_child->type == XML_ELEMENT_NODE)&&(!xmlStrcmp(cur_root_child->name, (const xmlChar*)"devices")))
		{
			//We are in the <devices> element
			xmlNodePtr devices = cur_root_child;
			for(xmlNodePtr device = devices->xmlChildrenNode; device != NULL; device = device->next)
			{
				if ((device->type == XML_ELEMENT_NODE)&&(!xmlStrcmp(device->name, (const xmlChar*)"disk")))
				{
					//We are in the <disk> element
					xmlChar* attr_type = xmlGetProp(device, (const xmlChar*)"type");
					xmlChar* attr_device = xmlGetProp(device, (const xmlChar*)"device");

					if(strcmp((const char*)attr_type,"file")==0 && strcmp((const char*)attr_device,"disk")==0)
					{
						xmlNodePtr disk = device;

						//we are in the proper disk
						for(xmlNodePtr indisk = disk->xmlChildrenNode; indisk != NULL; indisk = indisk->next)
						{

							if ((indisk->type == XML_ELEMENT_NODE)&&(!xmlStrcmp(indisk->name, (const xmlChar*)"source")))
							{
								//We are in the <source> element
								//Retrieve the path of the disk
								xmlChar* attr_file = xmlGetProp(indisk, (const xmlChar*)"file");

								disk_path  = (char*)malloc(sizeof(char) * (strlen((const char*)attr_file) + 1));
								memcpy(disk_path, attr_file, strlen((const char*)attr_file));
								disk_path[strlen((const char*)attr_file)] = '\0';
								goto after_parsing;
							}
						}

					}
				}
			}
		}

	}//end iteration over the document

after_parsing:

	if(disk_path == NULL)
	{
		logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Wrong XML file describing the VM to run: no path for VM disk found.");
		return false;
	}

	logger(ORCH_DEBUG_INFO, KVM_MODULE_NAME, __FILE__, __LINE__, "Virtual machine disk available at path: '%s'",disk_path);

	//Get the command line generator and prepare the command line
	IvshmemCmdLineGenerator cmdgenerator;


	stringstream ivshmemcmdline;
	//for(unsigned int i=1; i <= n_ports; i++)

	char cmdline[512];
	if(!cmdgenerator.get_mempool_cmdline(cmdline, sizeof(cmdline)))
		return false;

	ivshmemcmdline << " " << cmdline;

	list<string> namesOfPortsOnTheSwitch = sni.getNamesOfPortsOnTheSwitch();

	for(list<string>::iterator name = namesOfPortsOnTheSwitch.begin(); name != namesOfPortsOnTheSwitch.end(); name++)
	{
		//Retrieve the command line

		if(!cmdgenerator.get_port_cmdline((*name).c_str(), cmdline, sizeof(cmdline)))
			return false;

		ivshmemcmdline << " " << cmdline;
	}

	logger(ORCH_DEBUG_INFO, KVM_MODULE_NAME, __FILE__, __LINE__, "Command line part for ivshmem '%s'",ivshmemcmdline.str().c_str());

	pthread_mutex_lock(&Libvirt_mutex);

	stringstream command;
	command << QEMU << " " << domain_name << " " << next_tcp_port << " " << disk_path << "'" << ivshmemcmdline.str().c_str() << "'";

	stringstream portstream;
	portstream << next_tcp_port;
	monitor[domain_name] = portstream.str();
	next_tcp_port++;
	pthread_mutex_unlock(&Libvirt_mutex);

	int retVal = system(command.str().c_str());
	retVal = retVal >> 8;

	if(retVal == 0)
		return false;

	return true;
}
#endif // if not defined(ENABLE_KVM_IVSHMEM)
#endif // ERFS_DIRECT_KVM

bool Libvirt::stopNF(StopNFIn sni)
{
	/*image_name*/
	char *vm_name = new char[64];
	sprintf(vm_name, "%" PRIu64 "_%s", sni.getLsiID(), sni.getNfName().c_str());

#ifndef DIRECT_KVM_IVSHMEM

	assert(connection != NULL);

	/*destroy the VM*/
	if(virDomainDestroy(virDomainLookupByName(connection, vm_name)) != 0){
		logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "failed to stop (destroy) VM. %s", vm_name);
		return false;
	}
#else
	//To stop the VNF, use its own network monitor
	assert(monitor.count(vm_name) == 1);

	string tcpport = monitor.find(vm_name)->second;

	struct addrinfo *AddrInfo;
	struct addrinfo Hints;
	char ErrBuf[BUFFER_SIZE];
	int socket;						// keeps the socket ID for this connection
	int WrittenBytes;				// Number of bytes written on the socket

	char *command= QUIT_COMMAND;

	memset(&Hints, 0, sizeof(struct addrinfo));

	Hints.ai_family= AF_INET;
	Hints.ai_socktype= SOCK_STREAM;

	if (sock_initaddress ("127.0.0.1", tcpport.c_str(), &Hints, &AddrInfo, ErrBuf, sizeof(ErrBuf)) == sockFAILURE)
	{
		logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Error resolving given address/port (%s/%s): %s",  "127.0.0.1",  tcpport.c_str(), ErrBuf);
		return false;
	}

	if ( (socket= sock_open(AddrInfo, 0, 0,  ErrBuf, sizeof(ErrBuf))) == sockFAILURE)
	{
		// AddrInfo is no longer required
		logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Cannot contact the VM: %s", ErrBuf);
		return false;
	}

	WrittenBytes= sock_send(socket, command, strlen(command), ErrBuf, sizeof(ErrBuf));
	if (WrittenBytes == sockFAILURE)
	{
		logger(ORCH_ERROR, KVM_MODULE_NAME, __FILE__, __LINE__, "Error sending data: %s", ErrBuf);
		return false;

	}

#endif
	return true;
}

