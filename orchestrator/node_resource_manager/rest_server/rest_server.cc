#include "rest_server.h"

GraphManager *RestServer::gm = NULL;
#ifdef UNIFY_NFFG
	bool RestServer::firstTime = true;
#endif

/*
*
* SQLiteManager pointer
*
*/
SQLiteManager *dbmanager = NULL;
bool client_auth = false;

bool RestServer::init(SQLiteManager *dbm, bool cli_auth, char *nffg_filename,int core_mask, char *ports_file_name, string local_ip, bool control, char *control_interface, char *ipsec_certificate)
{	
	char *nffg_file_name = new char[BUFFER_SIZE];
	if(nffg_filename != NULL && strcmp(nffg_filename, "") != 0)
		strcpy(nffg_file_name, nffg_filename);
	else
		nffg_file_name = NULL;
#ifdef UNIFY_NFFG
	if(nffg_filename != NULL)
	{
		logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "You are using the NF-FG defined in the Unify project.");
		logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "The NF-FG from configuration file is not supported in this case!",nffg_filename);
		return false;
	}
#endif

	try
	{
		gm = new GraphManager(core_mask,string(ports_file_name),local_ip,control,string(control_interface),string(ipsec_certificate));
		
	}catch (...)
	{
		return false;		
	}

	//Handle the file containing the first graph to be deployed
	if(nffg_file_name != NULL)
	{	
		sleep(2); //XXX This give time to the controller to be initialized

		if(!readGraphFromFile(nffg_file_name))
		{
			delete gm;
			return false;
		}
	}
	
	client_auth = cli_auth;
	
	if(client_auth)
		dbmanager = dbm;	
	
	return true;
}

bool RestServer::readGraphFromFile(char *nffg_filename)
{
	logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Considering the graph described in file '%s'",nffg_filename);
	
	std::ifstream file;
	file.open(nffg_filename);
	if(file.fail())
	{
		logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "Cannot open the file %s",nffg_filename);
		return false;
	}

	stringstream stream;
	string str;
	while (std::getline(file, str))
	    stream << str << endl;
	
	if(createGraphFromFile(stream.str()) == 0)
		return false;
		
	return true;
}

#ifdef UNIFY_NFFG
bool RestServer::toBeRemovedFromFile(char *filename)
{
	logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Removing NFs and rules defined in file '%s'",filename);
	
	std::ifstream file;
	file.open(filename);
	if(file.fail())
	{
		logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "Cannot open the file %s",filename);
		return false;
	}

	stringstream stream;
	string str;
	while (std::getline(file, str))
	    stream << str << endl;
	
	list<string> vnfsToBeRemoved;
	list<string> rulesToBeRemoved;
	
	//Parse the content of the file
	Value value;
	read(stream.str(), value);
	try
	{
		Object obj = value.getObject();
		
	  	bool foundFlowGraph = false;
		
		//Identify the flow rules
		for( Object::const_iterator i = obj.begin(); i != obj.end(); ++i )
		{
	 	    const string& name  = i->first;
		    const Value&  value = i->second;
		
		    if(name == FLOW_GRAPH)
		    {
		    	foundFlowGraph = true;
		    	
		    	bool foundVNFs = false;
		    	bool foundFlowRules = false;
		    	
		  		Object flow_graph = value.getObject();
		    	for(Object::const_iterator fg = flow_graph.begin(); fg != flow_graph.end(); fg++)
		    	{
		    		const string& fg_name  = fg->first;
				    const Value&  fg_value = fg->second;
				    if(fg_name == VNFS)
				    {
				    	foundVNFs = true;
				    	const Array& vnfs_array = fg_value.getArray();
				    					    	
				    	//Iterate on the VNFs
				    	for( unsigned int vnf = 0; vnf < vnfs_array.size(); ++vnf )
						{
							//This is a VNF, with an ID and a template
							Object network_function = vnfs_array[vnf].getObject();
							bool foundID = false;
							//Parse the rule
							for(Object::const_iterator nf = network_function.begin(); nf != network_function.end(); nf++)
							{
								const string& nf_name  = nf->first;
								const Value&  nf_value = nf->second;
					
								if(nf_name == _ID)
								{
									foundID = true;
									string theID = nf_value.getString();
									vnfsToBeRemoved.push_back(theID);
								}
								else
								{
									logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Invalid key \"%s\" in a VNF of \"%s\"",nf_name.c_str(),VNFS);
									return false;
								}
							}
							if(!foundID)
							{
								logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\" not found in an element of \"%s\"",_ID,VNFS);
								return false;
							}
						}
				    }//end if(fg_name == VNFS)
				    else if (fg_name == FLOW_RULES)
				    {
				    	const Array& ids_array = fg_value.getArray();
						foundFlowRules = true;
					
						//Iterate on the IDs
						for( unsigned int id = 0; id < ids_array.size(); ++id )
						{
							Object id_object = ids_array[id].getObject();
					
							bool foundID = false;
					
							for( Object::const_iterator currentID = id_object.begin(); currentID != id_object.end(); ++currentID )
							{
								const string& idName  = currentID->first;
								const Value&  idValue = currentID->second;
						
								if(idName == _ID)
								{
									foundID = true;
									string theID = idValue.getString();
									rulesToBeRemoved.push_back(theID);
								}
								else	
								{
									logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Invalid key \"%s\"",name.c_str());
									return false;
								}
							}
							if(!foundID)
							{
								logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"id\" not found in an elmenet of \"%s\"",FLOW_RULES);
								return false;
							}
						}
				    }// end  if (fg_name == FLOW_RULES)
				    else
					{
					    logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Invalid key \"%s\" in \"%s\"",fg_name.c_str(),FLOW_GRAPH);
						return false;
					}
		    	}
		    	if(!foundFlowRules)
				{
					logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\" not found in \"%s\"",FLOW_RULES,FLOW_GRAPH);
					return false;
				}
				if(!foundVNFs)
					logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\" not found in \"%s\"",VNFS,FLOW_GRAPH);
		    }
		    else
		    {
				logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Invalid key: %s",name.c_str());
				return false;
		    }
		}
		if(!foundFlowGraph)
		{
			logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\" not found",FLOW_GRAPH);
			return false;
		}
	}catch(exception& e)
	{
		logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "The content does not respect the JSON syntax: ",e.what());
		return false;
	}
	
	for(list<string>::iterator tbr = rulesToBeRemoved.begin(); tbr != rulesToBeRemoved.end(); tbr++)
	{
		if(!gm->deleteFlow(GRAPH_ID,*tbr))
			return false;
	}
	
	for(list<string>::iterator tbr = vnfsToBeRemoved.begin(); tbr != vnfsToBeRemoved.end(); tbr++)
	{
		if(!gm->stopNetworkFunction(GRAPH_ID,*tbr))
			return false;
	}
	
	return true;
}
#endif

void RestServer::terminate()
{
	delete(gm);
}

void RestServer::request_completed (void *cls, struct MHD_Connection *connection,
						void **con_cls, enum MHD_RequestTerminationCode toe)
{
	struct connection_info_struct *con_info = (struct connection_info_struct *)(*con_cls);

	if (NULL == con_info)
		return;

	if(con_info->length != 0)
	{
		free(con_info->message);
		con_info->message = NULL;
	}
	
	free (con_info);
	*con_cls = NULL;
}

int RestServer::answer_to_connection (void *cls, struct MHD_Connection *connection,
			const char *url, const char *method, const char *version,
			const char *upload_data,
			size_t *upload_data_size, void **con_cls)
{
	
	if(NULL == *con_cls)
	{
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "New %s request for %s using version %s", method, url, version);
		if(LOGGING_LEVEL <= ORCH_DEBUG)
			MHD_get_connection_values (connection, MHD_HEADER_KIND, &print_out_key, NULL);
	
		struct connection_info_struct *con_info;
		con_info = (struct connection_info_struct*)malloc (sizeof (struct connection_info_struct));
		
		assert(con_info != NULL);		
		if (NULL == con_info)
			return MHD_NO;
		
		if ((0 == strcmp (method, PUT)) || (0 == strcmp (method, POST)) || (0 == strcmp (method, DELETE)) )
		{
			con_info->message = (char*)malloc(REQ_SIZE * sizeof(char));
			con_info->length = 0;
		}
		else if (0 == strcmp (method, GET))
			con_info->length = 0;
		else
		{
			con_info->message = (char*)malloc(REQ_SIZE * sizeof(char));
			con_info->length = 0;
		}
	
		*con_cls = (void*) con_info;
		return MHD_YES;
	}

#ifdef UNIFY_NFFG
	
	struct connection_info_struct *con_info = (struct connection_info_struct *)(*con_cls);
	assert(con_info != NULL);
	if (0 != strcmp (method, GET))
	{
        //Extract the body of the HTTP request		
		if (*upload_data_size != 0)
		{
			strcpy(&con_info->message[con_info->length],upload_data);
			con_info->length += *upload_data_size;
			*upload_data_size = 0;
			return MHD_YES;
		}
		else if (NULL != con_info->message)
		{
			con_info->message[con_info->length] = '\0';
		}
	}
	
	/**
	*	"answer" is handled as described here:
	*	http://stackoverflow.com/questions/2838038/c-programming-malloc-inside-another-function
	*/
	char *answer;
	handleRequest_status_t retVal = Virtualizer::handleRestRequest(con_info->message, &answer,url,method);
	
	if(retVal == HR_INTERNAL_ERROR)
	{
		struct MHD_Response *response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		MHD_destroy_response (response);
		return ret;
	}
	else
	{
		if(retVal == HR_EDIT_CONFIG)
		{
			//Handle the graph received from the network
			//Handle the rules to be removed as required
			if(!readGraphFromFile(NEW_GRAPH_FILE) || !toBeRemovedFromFile(REMOVE_GRAPH_FILE))
			{
				//Something wrong happened during the manipulation of the graph
				logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "An error occurred during the manipulation of the graph!");
				logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "Please, reboot the orchestrator (and the vSwitch) in order to avoid inconsist state in the universal node");
				
				struct MHD_Response *response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
				int ret = MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
				MHD_destroy_response (response);
				return ret;
			}
		}
	
		struct MHD_Response *response = MHD_create_response_from_buffer (strlen(answer),(void*)answer, MHD_RESPMEM_PERSISTENT);
	    stringstream absolute_url;
		absolute_url << REST_URL << ":" << REST_PORT << url;
		MHD_add_response_header (response, "Cache-Control",NO_CACHE);
		MHD_add_response_header (response, "Location", absolute_url.str().c_str());
		int ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
		return ret;
	}

#else
	if (0 == strcmp (method, GET))
		return doGet(connection,url);
	else if( (0 == strcmp (method, PUT)) || (0 == strcmp (method, POST)) || (0 == strcmp (method, DELETE)))
	{	
		struct connection_info_struct *con_info = (struct connection_info_struct *)(*con_cls);
		assert(con_info != NULL);
		if (*upload_data_size != 0)
		{
			strcpy(&con_info->message[con_info->length],upload_data);
			con_info->length += *upload_data_size;
			*upload_data_size = 0;
			return MHD_YES;
		}
		else if (NULL != con_info->message)
		{
			con_info->message[con_info->length] = '\0';
			if(0 == strcmp (method, PUT))
				return doPut(connection,url,con_cls);
			else if(0 == strcmp (method, POST))
				return doPost(connection,url,con_cls,client_auth);
			else
				return doDelete(connection,url,con_cls);
		}
	}
	else
	{
		//Methods not implemented
		struct connection_info_struct *con_info = (struct connection_info_struct *)(*con_cls);
		assert(con_info != NULL);
		if (*upload_data_size != 0)
		{
			strcpy(&con_info->message[con_info->length],upload_data);
			con_info->length += *upload_data_size;
			*upload_data_size = 0;
			return MHD_YES;
		}
		else
		{
			con_info->message[con_info->length] = '\0';
			logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "++++Method \"%s\" not implemented",method);
			struct MHD_Response *response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
			int ret = MHD_queue_response (connection, MHD_HTTP_NOT_IMPLEMENTED, response);
			MHD_destroy_response (response);
			return ret;
		}
	}
#endif	
	
	//Just to remove a warning in the compiler
	return MHD_YES;
}


int RestServer::print_out_key (void *cls, enum MHD_ValueKind kind, const char *key, const char *value)
{
	logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "%s: %s", key, value);
	return MHD_YES;
}

int RestServer::doPost(struct MHD_Connection *connection, const char *url, void **con_cls, bool client_auth)
{
	struct MHD_Response *response;

	struct connection_info_struct *con_info = (struct connection_info_struct *)(*con_cls);
	assert(con_info != NULL);

	//Check the URL
	char delimiter[] = "/";
 	char * pnt;

	int ret = 0, rc = 0;
	unsigned char hash_token[HASH_SIZE], temp[BUFFER_SIZE];
	
	char hash_pwd[BUFFER_SIZE], nonce[BUFFER_SIZE], timestamp[BUFFER_SIZE];

	char *user, *pass;
	
	char tmp[BUFFER_SIZE], user_tmp[BUFFER_SIZE];
	strcpy(tmp,url);
	pnt=strtok(tmp, delimiter);
	int i = 0;
	
	while( pnt!= NULL )
	{
		switch(i)
		{
			case 0:
				if(strcmp(pnt,BASE_URL_LOGIN) != 0)
				{
put_malformed_url:
					logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Resource \"%s\" does not exist", url);
					response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
					int ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
					MHD_destroy_response (response);
					return ret;
				}
				else
				{
					if(!client_auth)
					{
						con_info->message[con_info->length] = '\0';
						logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Resource \"%s\" only exists if client authentication is required", url);
						struct MHD_Response *response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
						int ret = MHD_queue_response (connection, MHD_HTTP_NOT_IMPLEMENTED, response);
						MHD_destroy_response (response);
						return ret;
					}
				}
				break;
		}
		
		pnt = strtok( NULL, delimiter );
		i++;
	}
	if(i != 1)
	{
		//the URL is malformed
		goto put_malformed_url;
	}
	
	logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "User login");
	logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Content:");
	logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "%s",con_info->message);
	
	if(MHD_lookup_connection_value (connection,MHD_HEADER_KIND, "Host") == NULL)
	{
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "\"Host\" header not present in the request");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
		MHD_destroy_response (response);
		return ret;
	}
	
	if(!parsePostBody(*con_info,&user,&pass))
	{
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Malformed content");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
		MHD_destroy_response (response);
		return ret;
	}
	
	try
	{
		if(user != NULL && pass != NULL){
		
			SHA256((const unsigned char*)pass, sizeof(pass) - 1, hash_token);
		    
		    	strcpy(tmp, "");
		    	strcpy(hash_pwd, "");
		    
		    	for (int i = 0; i < HASH_SIZE; i++) {
        			sprintf(tmp, "%x", hash_token[i]);
        			strcat(hash_pwd, tmp);
    			}

			strcpy(user_tmp, user);

			dbmanager->selectUsrPwd(user, (char *)hash_pwd);
			
			if(strcmp(dbmanager->getUser(), user_tmp) == 0 && strcmp(dbmanager->getPwd(), (char *)hash_pwd) == 0){
				if(strcmp(dbmanager->getToken(), "") == 0){

					rc = RAND_bytes(temp, sizeof(temp));
					if(rc != 1)
					{
						logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "An error occurred while generating nonce!");
						response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
						ret = MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
						MHD_destroy_response (response);
						return ret;
					}
					
					strcpy(tmp, "");
					strcpy(hash_pwd, "");
					
					for (int i = 0; i < HASH_SIZE; i++) {
        					sprintf(tmp, "%x", temp[i]);
        					strcat(nonce, tmp);
    					}
					
					/*
					*
					* Calculating a timestamp
					*
					*/
					time_t now = time(0);

					tm *ltm = localtime(&now);

					strcpy(timestamp, "");
					sprintf(timestamp, "%d/%d/%d %d:%d", ltm->tm_mday, 1 + ltm->tm_mon, 1900 + ltm->tm_year, ltm->tm_hour, 1 + ltm->tm_min);

					dbmanager->updateTokenAndTimestamp(user_tmp, (char *)nonce, (char *)timestamp);
				}
				
				response = MHD_create_response_from_buffer (strlen((char *)nonce),(void*) nonce, MHD_RESPMEM_PERSISTENT);
				MHD_add_response_header (response, "Content-Type",TOKEN_TYPE);
				MHD_add_response_header (response, "Cache-Control",NO_CACHE);
				ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
				MHD_destroy_response (response);
				
				return ret;
			} 
			
			logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "Client unauthorized");
			response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
			ret = MHD_queue_response (connection, MHD_HTTP_UNAUTHORIZED, response);
			MHD_destroy_response (response);
			
			return ret;
		}else{
			logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "Client unauthorized");
			response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
			ret = MHD_queue_response (connection, MHD_HTTP_UNAUTHORIZED, response);
			MHD_destroy_response (response);
			return ret;
		}
	}catch (...)
	{
		logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "An error occurred during user login!");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		ret = MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		MHD_destroy_response (response);
		return ret;
	}
	
	//TODO: put the proper content in the answer
	response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
	stringstream absolute_url;
	absolute_url << REST_URL << ":" << REST_PORT << url;
	MHD_add_response_header (response, "Location", absolute_url.str().c_str());
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);

	MHD_destroy_response (response);
	return ret;	
}

bool RestServer::parsePostBody(struct connection_info_struct &con_info,char **user, char **pwd)
{
	Value value;
	read(con_info.message, value);
	return parseLoginForm(value, user, pwd);
}

bool RestServer::parseLoginForm(Value value, char **user, char **pwd)
{
	try
	{
		Object obj = value.getObject();
		
	  	bool foundUser = false, foundPwd = false;
		
		//Identify the flow rules
		for( Object::const_iterator i = obj.begin(); i != obj.end(); ++i )
		{
	 	    const string& name  = i->first;
		    const Value&  value = i->second;
		
		    if(name == USER)
		    {
		  		foundUser = true;
		  		(*user) = (char *)value.getString().c_str();
		    }
		    else if(name == PASS)
		    {
				foundPwd = true;
		    		(*pwd) = (char *)value.getString().c_str();
		    }
		    else
		    {
				logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Invalid key: %s",name.c_str());
				return false;
		    }
		}
		if(!foundUser)
		{
			logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\" not found",USER);
			return false;
		}
		else if(!foundPwd)
		{
			logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\" not found",PASS);
			return false;
		}
	}catch(exception& e)
	{
		logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "The content does not respect the JSON syntax: ",e.what());
		return false;
	}
	
	return true;
}

int RestServer::doPut(struct MHD_Connection *connection, const char *url, void **con_cls)
{
	struct MHD_Response *response;
	
	struct connection_info_struct *con_info = (struct connection_info_struct *)(*con_cls);
	assert(con_info != NULL);

	//Check the URL
	char delimiter[] = "/";
 	char * pnt;

	char graphID[BUFFER_SIZE];
	
	char tmp[BUFFER_SIZE];
	strcpy(tmp,url);
	pnt=strtok(tmp, delimiter);
	int i = 0;
	while( pnt!= NULL )
	{
		switch(i)
		{
			case 0:
				if(strcmp(pnt,BASE_URL_GRAPH) != 0)
				{
put_malformed_url:
					logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Resource \"%s\" does not exist", url);
					response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
					int ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
					MHD_destroy_response (response);
					return ret;
				}
				break;
			case 1:
				strcpy(graphID,pnt);
		}
		
		pnt = strtok( NULL, delimiter );
		i++;
	}
	if(i != 2)
	{
		//the URL is malformed
		goto put_malformed_url;
	}
	
	if(MHD_lookup_connection_value (connection,MHD_HEADER_KIND, "Host") == NULL)
	{
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "\"Host\" header not present in the request");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
		MHD_destroy_response (response);
		return ret;
	}
	
	/*	const char *c_type = MHD_lookup_connection_value (connection,MHD_HEADER_KIND, "Content-Type");
	if(strcmp(c_type,JSON_C_TYPE) != 0)
	{
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Content-Type must be: "JSON_C_TYPE);
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response (connection, MHD_HTTP_UNSUPPORTED_MEDIA_TYPE, response);
		MHD_destroy_response (response);
		return ret;
	}*/
	
	bool newGraph = !(gm->graphExists(graphID));
	
	string gID(graphID);
	highlevel::Graph *graph = new highlevel::Graph(gID);
	
	if(!parsePutBody(*con_info,*graph,newGraph))
	{
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Malformed content");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
		MHD_destroy_response (response);
		return ret;
	}
	
		graph->print();
	try
	{
		//if client authentication is required
		if(dbmanager != NULL){
			const char *token = MHD_lookup_connection_value (connection,MHD_HEADER_KIND, "X-Auth-Token");
	
			if(!checkAuthentication(connection, token, dbmanager))
			{
				//User unauthenticated!
				response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
				int ret = MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
				MHD_destroy_response (response);
				return ret;
			}
		}

		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Resource to be created/updated: %s",graphID);
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Content:");
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "%s",con_info->message);

		if(newGraph)
		{
			logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "A new graph must be created");		
			if(!gm->newGraph(graph))
			{
				logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "The graph description is not valid!");
				response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
				int ret = MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
				MHD_destroy_response (response);
				return ret;
			}
		}
		else
		{
			logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "An existing graph must be updated");
			if(!gm->updateGraph(graphID,graph))
			{
				delete(graph);
				logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "The graph description is not valid!");
				response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
				int ret = MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
				MHD_destroy_response (response);
				return ret;		
			}	
		}
	}catch (...)
	{
		logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "An error occurred during the %s of the graph!",(newGraph)? "creation" : "update");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		MHD_destroy_response (response);
		return ret;
	}
	
	logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "The graph has been properly %s!",(newGraph)? "created" : "updated");
	logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "");
	
	//TODO: put the proper content in the answer
	response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
	stringstream absolute_url;
	absolute_url << REST_URL << ":" << REST_PORT << url;
	MHD_add_response_header (response, "Location", absolute_url.str().c_str());
	int ret = MHD_queue_response (connection, MHD_HTTP_CREATED, response);

	MHD_destroy_response (response);
	return ret;	
}

int RestServer::createGraphFromFile(string toBeCreated)
{
	char graphID[BUFFER_SIZE];
	strcpy(graphID,GRAPH_ID);
	
	logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Graph ID: %s",graphID);
	logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Graph content:");
	logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "%s",toBeCreated.c_str());
	
	string gID(graphID);
	highlevel::Graph *graph = new highlevel::Graph(gID);
	
	if(!parseGraphFromFile(toBeCreated,*graph,true))
	{
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Malformed content");
		return 0;
	}
	
	graph->print();
	try
	{
#ifndef UNIFY_NFFG
		if(!gm->newGraph(graph))
#else
		//In case of NF-FG defined in the Unify project, only the first time a new graph must be created
		//In fact, all the rules refer to a single NF-FG, and then the following times we simply update
		//the graph already created.
		if((firstTime && !gm->newGraph(graph)) || (!firstTime && !gm->updateGraph(graphID,graph)) )
#endif
		{
			logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "The graph description is not valid!");
			return 0;
		}
#ifdef UNIFY_NFFG
		firstTime = false;
#endif
	}catch (...)
	{
		logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "An error occurred during the creation of the graph!");
		return 0;
	}

	return 1;
}

bool RestServer::parseGraphFromFile(string toBeCreated,highlevel::Graph &graph, bool newGraph) //startup. cambiare nome alla funzione
{
	Value value;
	read(toBeCreated, value);
	return parseGraph(value, graph, newGraph);
}

bool RestServer::parsePutBody(struct connection_info_struct &con_info,highlevel::Graph &graph, bool newGraph)
{
	Value value;
	read(con_info.message, value);
	return parseGraph(value, graph, newGraph);
}

bool RestServer::parseGraph(Value value, highlevel::Graph &graph, bool newGraph)
{
	//for each NF, contains the set of ports it requires
	map<string,set<unsigned int> > nfs_ports_found;

	//for each NF, contains the id
	map<string, string> nfs_id;

	//for each endpoint (interface), contains the id
	map<string, string> iface_id;

	//for each endpoint (interface-out), contains the id
	map<string, string> iface_out_id;

	//for each endpoint (gre), contains the id
	map<string, string> gre_id;

	//for each endpoint (vlan), contains the pair vlan id, interface
	map<string, pair<string, string> > vlan_id; //XXX: currently, this information is ignored

	try
	{
		Object obj = value.getObject();
		
		vector<Object> gre_array(256);
		
		Object big_switch, ep_gre;

	  	bool foundFlowGraph = false;
	  	
	  	int ii = 0;
		
		//Identify the flow rules
		for( Object::const_iterator i = obj.begin(); i != obj.end(); ++i )
		{
	 		const string& name  = i->first;
			const Value&  value = i->second;
		
			//Identify the forwarding graph
			if(name == FORWARDING_GRAPH)
			{
		    	foundFlowGraph = true;
		    	
		    	bool foundVNFs = false, foundEP = false, foundGRE = false, foundFlowRules = false;
		    	vector<string> id_gre (256);
		    	
		  		Object forwarding_graph = value.getObject();
		    		
				for(Object::const_iterator fg = forwarding_graph.begin(); fg != forwarding_graph.end(); fg++)
		    	{
					bool e_if = false, e_if_out = false, e_vlan = false;
								
					string id, v_id, node, iface, e_name, node_id, sw_id, interface;

		        	const string& fg_name  = fg->first;
			       	const Value&  fg_value = fg->second;
				
					if(fg_name == _ID)
		         	{
		         		logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",FORWARDING_GRAPH,_ID,fg_value.getString().c_str());
					}
					else if(fg_name == _NAME)
					{
		         		logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",FORWARDING_GRAPH,_NAME,fg_value.getString().c_str());
					
						//set name of the graph
						graph.setName(fg_value.getString());
					}
					else if(fg_name == F_DESCR)
					{
		         		logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",FORWARDING_GRAPH,F_DESCR,fg_value.getString().c_str());

						//XXX: currently, this information is ignored
					}
					//Identify the VNFs
					else if(fg_name == VNFS)
					{
						const Array& vnfs_array = fg_value.getArray();

						//XXX We may have no VNFs in the following cases:
						//*	graph with only physical ports
						//*	update of a graph that only adds new flows
						//However, when there are no VNFs, we provide a warning
				    	if(vnfs_array.size() != 0)
					    	foundVNFs = true;
				    	
				    	//Itearate on the VNFs
				    	for( unsigned int vnf = 0; vnf < vnfs_array.size(); ++vnf )
						{
							//This is a VNF, with an ID and a template
							Object network_function = vnfs_array[vnf].getObject();
#ifdef POLITO_MESSAGE							
							bool foundTemplate = false;
#endif					
							bool foundName = false;
							
							map<string,string> ipv4_addresses; 	//port name, ipv4 address
							map<string,string> ipv4_masks;		//port name, ipv4 address

							string id, name, vnf_template, groups, port_id, port_name, port_mac, port_ip, vnf_tcp_port, host_tcp_port;
							//list of four element port id, port name, mac address and ip address related by the VNF
							list<vector<string> > portS;
							//list of pair element host tcp port and vnf tcp port related by the VNF
							list<pair<string, string> > portC;

							//Parse the network function
							for(Object::const_iterator nf = network_function.begin(); nf != network_function.end(); nf++)
							{
								const string& nf_name  = nf->first;
								const Value&  nf_value = nf->second;
									
								if(nf_name == _NAME)
								{
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VNFS,_NAME,nf_value.getString().c_str());
									foundName = true;
									if(!graph.addNetworkFunction(nf_value.getString()))
									{
										logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "Two VNFs with the same name \"%s\" in \"%s\"",nf_value.getString().c_str(),VNFS);
										return false;
									}	
									
									name = nf_value.getString();
									
									nfs_id[id] = nf_value.getString(); 
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\"",id.c_str(), nfs_id[id].c_str());
								}
								else if(nf_name == VNF_TEMPLATE)
								{
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VNFS,VNF_TEMPLATE,nf_value.getString().c_str());
									vnf_template = nf_value.getString();
	#ifdef POLITO_MESSAGE
									foundTemplate = true;
	#endif
								}
								else if(nf_name == _ID)
								{
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VNFS,_ID,nf_value.getString().c_str());
									
									//store value of VNF id
									id.assign(nf_value.getString().c_str());
								}
								else if(nf_name == VNF_CONTROL)
								{
									const Array& control_array = nf_value.getArray();
								
									//Itearate on the control
									for( unsigned int ctrl = 0; ctrl < control_array.size(); ++ctrl )
									{
										//This is a VNF control, with an host tcp port and a vnf tcp port 
										Object control = control_array[ctrl].getObject();
										
										vector<string> port_descr(4);
										
										//Parse the control
										for(Object::const_iterator c = control.begin(); c != control.end(); c++)
										{
											const string& c_name  = c->first;
											const Value&  c_value = c->second;
											
											if(c_name == HOST_PORT)
											{
												logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VNF_CONTROL,HOST_PORT,c_value.getString().c_str());
												
												host_tcp_port = c_value.getString();
											}
											else if(c_name == VNF_PORT)
											{
												logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VNF_CONTROL,VNF_PORT,c_value.getString().c_str());
												
												vnf_tcp_port = c_value.getString();
											}
										}
										
										//Add NF control ports descriptions
										if(!graph.addNetworkFunctionControlConfiguration(name, make_pair(host_tcp_port, vnf_tcp_port)))
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "Two VNFs with the same name \"%s\" in \"%s\"",nf_value.getString().c_str(),VNFS);
											return false;
										}
										
										portC.push_back(make_pair(host_tcp_port, vnf_tcp_port));
									}
								}
								else if(nf_name == VNF_PORTS)
								{
									const Array& ports_array = nf_value.getArray();
								
									//Itearate on the ports
									for( unsigned int ports = 0; ports < ports_array.size(); ++ports )
									{
										//This is a VNF port, with an ID and a name
										Object port = ports_array[ports].getObject();
										
										vector<string> port_descr(4);
										
										//Parse the port
										for(Object::const_iterator p = port.begin(); p != port.end(); p++)
										{
											const string& p_name  = p->first;
											const Value&  p_value = p->second;
											
											if(p_name == _ID)
											{
												logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VNF_PORTS,_ID,p_value.getString().c_str());
												
												port_id = p_value.getString();
												
												port_descr[0] = port_id;
											}
											else if(p_name == _NAME)
											{
												logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VNF_PORTS,_NAME,p_value.getString().c_str());
												
												port_name = p_value.getString();
												
												port_descr[1] = port_name;
											}
											else if(p_name == PORT_MAC)
											{
												logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VNF_PORTS,PORT_MAC,p_value.getString().c_str());
												
												port_mac = p_value.getString();
												
												port_descr[2] = port_mac;
											}
											else if(p_name == PORT_IP)
											{
												logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VNF_PORTS,PORT_IP,p_value.getString().c_str());
												
												port_ip = p_value.getString();
												
												port_descr[3] = port_ip;
											}
											else
											{
												logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "Invalid key \"%s\" in a VNF of \"%s\"",p_name.c_str(),VNF_PORTS);
												return false;
											}
										}
										
										//Add NF ports descriptions
										if(!graph.addNetworkFunctionPortConfiguration(name, make_pair(port_mac, port_ip)))
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "Two VNFs with the same name \"%s\" in \"%s\"",nf_value.getString().c_str(),VNFS);
											return false;
										}					
										
										portS.push_back(port_descr);	
									}
								}
								else if(nf_name == VNF_GROUPS)
								{
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VNFS,VNF_GROUPS,nf_value.getString().c_str());
									
									groups = nf_value.getString();
								}
								else 
								{
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "Invalid key \"%s\" in a VNF of \"%s\"",nf_name.c_str(),VNFS);
									return false;
								}
							}
							if(
#ifdef POLITO_MESSAGE							
							!foundTemplate ||
#endif							
							!foundName)
							{
								logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\", or key \"%s\", or both not found in an element of \"%s\"",_NAME,VNF_TEMPLATE,VNFS);
								return false;
							}
							
							highlevel::VNFs vnfs(id, name, groups, vnf_template, portS, portC);

							graph.addVNF(vnfs);

							portS.clear();
							portC.clear();
						}					
				    	}
					//Identify the end-points
					else if(fg_name == END_POINTS)
				    {
				    	const Array& end_points_array = fg_value.getArray();
				    	
						foundEP = true;

						logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"",END_POINTS);

						int i = 0;

				    	//Iterate on the end-points
				    	for( unsigned int ep = 0; ep < end_points_array.size(); ++ep )
						{
							//This is a endpoints, with a name, a type, and an interface
							Object end_points = end_points_array[ep].getObject();
							
							for(Object::const_iterator aep = end_points.begin(); aep != end_points.end(); aep++)
							{
								const string& ep_name  = aep->first;
								const Value&  ep_value = aep->second;
									
								if(ep_name == _ID)
								{	
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",END_POINTS,_ID,ep_value.getString().c_str());
									
									if(!foundGRE)
										id = ep_value.getString();
									else
										id_gre[i] = ep_value.getString();
								}
								else if(ep_name == _NAME)
								{
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",END_POINTS,_NAME,ep_value.getString().c_str());
									
									e_name = ep_value.getString();
								} 
								else if(ep_name == EP_TYPE)
								{
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",END_POINTS,EP_TYPE,ep_value.getString().c_str());
							
									string type = ep_value.getString();
								}
								else if(ep_name == EP_REM)
								{
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",END_POINTS,EP_REM,ep_value.getString().c_str());

									//XXX: currently, this information is ignored
								} 
								else if(ep_name == EP_PR)
								{
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",END_POINTS,EP_PR,ep_value.getString().c_str());

									//XXX: currently, this information is ignored
								}
								//identify interface end-points 
								else if(ep_name == IFACE)
								{
									Object ep_iface = ep_value.getObject();
						
									e_if = true;
						
									for(Object::const_iterator epi = ep_iface.begin(); epi != ep_iface.end(); epi++)
									{
										const string& epi_name  = epi->first;
										const Value&  epi_value = epi->second;
										
										if(epi_name == NODE_ID)
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",IFACE,NODE_ID,epi_value.getString().c_str());
											
											node_id = epi_value.getString();	
										}
										else if(epi_name == SW_ID)
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",IFACE,SW_ID,epi_value.getString().c_str());
											
											sw_id = epi_value.getString();	
										}
										else if(epi_name == IFACE)
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",IFACE,IFACE,epi_value.getString().c_str());

											interface = epi_value.getString();
										
											iface_id[id] = epi_value.getString();
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\"",id.c_str(), iface_id[id].c_str());
										}
									}
								}
								//identify interface-out end-points 
								else if(ep_name == EP_IFACE_OUT)
								{
									Object ep_iface = ep_value.getObject();
							
									e_if_out = true;
							
									for(Object::const_iterator epi = ep_iface.begin(); epi != ep_iface.end(); epi++)
									{
										const string& epi_name  = epi->first;
										const Value&  epi_value = epi->second;
										
										if(epi_name == NODE_ID)
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",EP_IFACE_OUT,NODE_ID,epi_value.getString().c_str());
										
											node_id = epi_value.getString();
										}
										else if(epi_name == SW_ID)
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",EP_IFACE_OUT,SW_ID,epi_value.getString().c_str());
										
											sw_id = epi_value.getString();	
										}
										else if(epi_name == IFACE)
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",EP_IFACE_OUT,IFACE,epi_value.getString().c_str());
										
											interface = epi_value.getString();
										
											iface_out_id[id] = epi_value.getString();
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\"",id.c_str(), iface_out_id[id].c_str());
										}
									}
								}
								//identify vlan end-points 
								else if(ep_name == VLAN)
								{
									Object ep_vlan = ep_value.getObject();
							
									e_vlan = true;
							
									for(Object::const_iterator epi = ep_vlan.begin(); epi != ep_vlan.end(); epi++)
									{
										const string& epi_name  = epi->first;
										const Value&  epi_value = epi->second;
										
										if(epi_name == V_ID)
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VLAN,VLAN_ID,epi_value.getString().c_str());
										
											v_id = epi_value.getString();
										}
										else if(epi_name == IFACE)
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VLAN,IFACE,epi_value.getString().c_str());

											interface = epi_value.getString();
										}
										else if(epi_name == SW_ID)
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VLAN,SW_ID,epi_value.getString().c_str());

											sw_id = epi_value.getString();
										}
										else if(epi_name == NODE_ID)
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",VLAN,NODE_ID,epi_value.getString().c_str());

											node_id = epi_value.getString();
										}
									}
									
									vlan_id[id] = make_pair(v_id, interface);
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\":\"%s\"",id.c_str(),vlan_id[id].first.c_str(),vlan_id[id].second.c_str());									
								}
								else if(ep_name == EP_GRE)
								{
									ep_gre = ep_value.getObject();
									
									gre_array[i] = ep_gre;
						
									foundGRE = true;
									
									i++;
								}
								else
									logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,END_POINTS,ep_value.getString().c_str());
							}
							//add interface end-points
							if(e_if)
							{
								highlevel::EndPointInterface ep_if(id, e_name, node_id, sw_id, interface);

								graph.addEndPointInterface(ep_if);
								
								e_if = false;
							}
							//add interface-out end-points
							else if(e_if_out)
							{
								highlevel::EndPointInterfaceOut ep_if_out(id, e_name, node_id, sw_id, interface);

								graph.addEndPointInterfaceOut(ep_if_out);
								
								e_if_out = false;
							}
							//add vlan end-points
							else if(e_vlan)
							{
								highlevel::EndPointVlan ep_vlan(id, e_name, v_id, node_id, sw_id, interface);

								graph.addEndPointVlan(ep_vlan);
								
								e_vlan = false;
							}
						}
						
						ii = i;
					}
					//Identify the big-switch
					else if(fg_name == BIG_SWITCH)
					{
						big_switch = fg_value.getObject();
					}
					else
					{
						logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Invalid key \"%s\" in \"%s\"",fg_name.c_str(),FORWARDING_GRAPH);
						return false;
					}
					if(foundEP)
					{
						//Iterate on the gre-tunnel
						if(foundGRE)
						{
							int j = 1;
						
							//Iterate on the gre object
							for( int gre_obj = 0; gre_obj < ii; ++gre_obj )
							{
								vector<string> gre_param (5);
						
								string local_ip, remote_ip, interface, ttl, gre_key;
								bool safe = false;
						
								int i = 0;
				
								for(Object::const_iterator epi = gre_array[gre_obj].begin(); epi != gre_array[gre_obj].end(); epi++)
								{
									const string& epi_name  = epi->first;
									const Value&  epi_value = epi->second;
		
									if(epi_name == LOCAL_IP)
									{
										logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",EP_GRE,LOCAL_IP,epi_value.getString().c_str());

										local_ip = epi_value.getString();

										gre_param[i] = epi_value.getString();
										
										i++;
									}
									else if(epi_name == REMOTE_IP)
									{
										logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",EP_GRE,REMOTE_IP,epi_value.getString().c_str());

										remote_ip = epi_value.getString();
										gre_param[i] = epi_value.getString();
									
										i++;
									}
									else if(epi_name == IFACE)
									{
										logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",EP_GRE,IFACE,epi_value.getString().c_str());
										
										interface = epi_value.getString();
										
										gre_param[3] = interface;
										
										gre_id[id_gre[j]] = epi_value.getString();
										logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\"",id_gre[i].c_str(), gre_id[id_gre[i]].c_str());
									}
									else if(epi_name == TTL)
									{
										logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",EP_GRE,TTL,epi_value.getString().c_str());
								
										ttl = epi_value.getString();
									}
									else if(epi_name == GRE_KEY)
									{
										logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",EP_GRE,GRE_KEY,epi_value.getString().c_str());
									
										gre_key = epi_value.getString();
									
										gre_param[i] = epi_value.getString();
										
										i++;	
									}
									else if(epi_name == SAFE)
									{
										logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%d\"",EP_GRE,SAFE,epi_value.getBool());
									
										safe = epi_value.getBool(); 
									}
								}
							
								if(safe)
									gre_param[4] = string("true");
								else
									gre_param[4] = string("false");
							
								//Add gre-tunnel end-points
								highlevel::EndPointGre ep_gre(id_gre[j], e_name, local_ip, remote_ip, interface, gre_key, ttl, safe);
								
								graph.addEndPointGre(ep_gre);
							
								graph.addEndPoint(id_gre[j],gre_param);
								
								j++;
							}	
						}
					
						logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"",BIG_SWITCH);
						foundEP = false;

						/*Iterate on the big-switch*/
						for(Object::const_iterator bs = big_switch.begin(); bs != big_switch.end(); bs++)
						{
							const string& bs_name  = bs->first;
							const Value&  bs_value = bs->second;
								
							if (bs_name == FLOW_RULES)
							{			
								const Array& flow_rules_array = bs_value.getArray();

								foundFlowRules = true;
#ifndef UNIFY_NFFG
								//FIXME: put the flowrules optional also in case of "standard| nffg?
								if(flow_rules_array.size() == 0)
								{
									logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\" without rules",FLOW_RULES);
									return false;
								}
#endif
								//Itearate on the flow rules
								for( unsigned int fr = 0; fr < flow_rules_array.size(); ++fr )
								{	
									//This is a rule, with a match, an action, and an ID
									Object flow_rule = flow_rules_array[fr].getObject();
									highlevel::Action *action = NULL;
									list<GenericAction*> genericActions;
									highlevel::Match match;
									string ruleID;
									uint64_t priority = 0;
					
									bool foundAction = false;
									bool foundMatch = false;
									bool foundID = false;
						
									//Parse the rule
									for(Object::const_iterator afr = flow_rule.begin(); afr != flow_rule.end(); afr++)
									{
										const string& fr_name  = afr->first;
										const Value&  fr_value = afr->second;
										if(fr_name == _ID)
										{
											foundID = true;
											ruleID = fr_value.getString();
										}
										else if(fr_name == F_DESCR)
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",FLOW_RULES,F_DESCR,fr_value.getString().c_str());

											//XXX: currently, this information is ignored	
										}
										else if(fr_name == PRIORITY)
										{
											logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%d\"",FLOW_RULES,PRIORITY,fr_value.getInt());
										
											priority = fr_value.getInt();
										}
										else if(fr_name == MATCH)
										{
											foundMatch = true;
											if(!MatchParser::parseMatch(fr_value.getObject(),match,nfs_ports_found,nfs_id,iface_id,iface_out_id,vlan_id,graph))
											{
												return false;
											}
										}
										else if(fr_name == ACTIONS)
										{
											const Array& actions_array = fr_value.getArray();
												
											for( unsigned int ac = 0; ac < actions_array.size(); ++ac )
											{
												foundAction = true;
												Object theAction = actions_array[ac].getObject();

												bool foundOne = false;

												for(Object::const_iterator a = theAction.begin(); a != theAction.end(); a++)
												{
													const string& a_name  = a->first;
													const Value&  a_value = a->second;
	
													//output_to_port
													if(a_name == OUTPUT)
													{
														string port_in_name = a_value.getString();
														string realName;
														const char *port_in_name_tmp = port_in_name.c_str();
														char vnf_name_tmp[BUFFER_SIZE];

														//Check the name of port
														char delimiter[] = ":";
													 	char * pnt;

														int p_type = 0;

														char tmp[BUFFER_SIZE];
														strcpy(tmp,(char *)port_in_name_tmp);
														pnt=strtok(tmp, delimiter);
														int i = 0;
															
														while( pnt!= NULL )
														{
															switch(i)
															{
																case 0:
																	//VNFss port type
																	if(strcmp(pnt,VNF) == 0)
																	{
																		p_type = 0;
																	}
																	//end-points port type
																	else if (strcmp(pnt,ENDPOINT) == 0)
																	{
																		p_type = 1;
																	}
																	break;
																case 1:
																	if(p_type == 0)
																	{
																		strcpy(vnf_name_tmp,nfs_id[pnt].c_str());
																		strcat(vnf_name_tmp, ":");
																	}
																	break;
																case 3:
																	if(p_type == 0)
																	{
																		strcat(vnf_name_tmp,pnt);
																	}
															}
		
															pnt = strtok( NULL, delimiter );
															i++;
														}
														//VNFs port type 
														if(p_type == 0)
														{
															if(foundOne)
															{
																logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Only one between keys \"%s\", \"%s\" and \"%s\" are allowed in \"%s\"",PORT_IN,VNF,ENDPOINT,ACTIONS);
																return false;
															}
															foundOne = true;

															//convert char *vnf_name_tmp to string vnf_name
															string vnf_name(vnf_name_tmp, strlen(vnf_name_tmp));
										
															logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,VNF,vnf_name.c_str());
										
															string name = MatchParser::nfName(vnf_name);
															char *tmp_vnf_name = new char[BUFFER_SIZE];
															strcpy(tmp_vnf_name, (char *)vnf_name.c_str());
															unsigned int port = MatchParser::nfPort(string(tmp_vnf_name));
															bool is_port = MatchParser::nfIsPort(string(tmp_vnf_name));
															
															if(name == "" || !is_port)
															{
																logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Network function \"%s\" is not valid. It must be in the form \"name:port\"",vnf_name.c_str());
																return false;	
															}
															
															/*nf port starts from 0*/
															port++;

															action = new highlevel::ActionNetworkFunction(name, string(port_in_name_tmp), port);
										
															set<unsigned int> ports_found;
															if(nfs_ports_found.count(name) != 0)
																ports_found = nfs_ports_found[name];
															ports_found.insert(port);
															nfs_ports_found[name] = ports_found;
														}
														//end-points port type
														else if(p_type == 1) 
														{
															if(foundOne)
															{
																logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Only one between keys \"%s\", \"%s\" and \"%s\" are allowed in \"%s\"",PORT_IN,VNF,ENDPOINT,ACTIONS);
																return false;
															}
															foundOne = true;
										
															bool iface_found = false, vlan_found = false;
						
															char *s_a_value = new char[BUFFER_SIZE];
															strcpy(s_a_value, (char *)a_value.getString().c_str());
															string eP = MatchParser::epName(a_value.getString());
															if(eP != "")
															{
																map<string,string>::iterator it = iface_id.find(eP);
																map<string,string>::iterator it1 = iface_out_id.find(eP);
																map<string,pair<string,string> >::iterator it2 = vlan_id.find(eP);
																if(it != iface_id.end())
																{
																	//physical port		
																	realName.assign(iface_id[eP]);
																	iface_found = true;		
																}
																else if(it1 != iface_out_id.end())
																{
																	//physical port		
																	realName.assign(iface_out_id[eP]);	
																	iface_found = true;	
																}
																else if(it2 != vlan_id.end())
																{
																	//vlan		
																	vlan_found = true;	
																}
															}
															//physical endpoint
															if(iface_found)
															{
#ifdef UNIFY_NFFG
																//In this case, the virtualized port name must be translated into the real one.
																try
																{
		realName = Virtualizer::getRealName(port_in_name);											
#endif
																	action = new highlevel::ActionPort(realName, string(s_a_value));
																	
																	graph.addPort(realName);
#ifdef UNIFY_NFFG
																}catch(exception e)
																{
																	logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Error while translating the virtualized port '%s': %s",port_in_name.c_str(),e.what());
																	return false;
																}
#endif
															}
															//vlan endpoint
															else if(vlan_found)
															{
																vlan_action_t actionType;
																unsigned int vlanID = 0;
														
																actionType = ACTION_ENDPOINT_VLAN;
														
																sscanf(vlan_id[eP].first.c_str(),"%u",&vlanID);
											
																action = new highlevel::ActionPort(vlan_id[eP].second, string(s_a_value));
																graph.addPort(vlan_id[eP].second);
											
																GenericAction *ga = new VlanAction(actionType,string(s_a_value),vlanID);
																genericActions.push_back(ga);
															}
															//gre-tunnel endpoint
															else
															{
																unsigned int endPoint = MatchParser::epPort(string(s_a_value));
																if(endPoint == 0)
																{
																	logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Graph end point \"%s\" is not valid. It must be in the form \"graphID:endpoint\"",value.getString().c_str());
																	return false;	
																}
																action = new highlevel::ActionEndPoint(endPoint, string(s_a_value));
															}
														}
													}
													else if(a_name == SET_VLAN_ID)
													{
														logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,SET_VLAN_ID,a_value.getString().c_str());

														//XXX: currently, this information is ignored	
													}
													else if(a_name == SET_VLAN_PRIORITY)
													{
														logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,SET_VLAN_PRIORITY,a_value.getString().c_str());

														//XXX: currently, this information is ignored	
													}
													else if(a_name == VLAN_PUSH)
													{
														//A vlan push action is required
											
														bool foundVlanID = false;
											
														vlan_action_t actionType;
														unsigned int vlanID = 0;
														
														actionType = ACTION_VLAN_PUSH;
														
														string strVlanID = a_value.getString();
														sscanf(strVlanID.c_str(),"%u",&vlanID);
											
														if(actionType == ACTION_VLAN_PUSH && !foundVlanID)
														{
															logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\" not found in \"%s\"",VLAN_ID,VLAN_PUSH);
															return false;
														}
														//Finally, we are sure that the command is correct!
											
														GenericAction *ga = new VlanAction(actionType,string(""),vlanID);
														genericActions.push_back(ga);
											
													}//end if(a_name == VLAN_PUSH)
													else if(a_name == VLAN_POP)
													{
														//A vlan pop action is required
														bool foundVlanID = false;
											
														vlan_action_t actionType;
														unsigned int vlanID = 0;
														
														actionType = ACTION_VLAN_POP;
														
														string strVlanID = a_value.getString();
														if(strVlanID.compare("") != 0)
															foundVlanID = true;
														sscanf(strVlanID.c_str(),"%u",&vlanID);
											
														if(actionType == ACTION_VLAN_POP && foundVlanID)
														{
															logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\" found in \"%s\"",VLAN_ID,VLAN_POP);
															return false;
														}
														
														//Finally, we are sure that the command is correct!
														GenericAction *ga = new VlanAction(actionType,string(""),vlanID);
														genericActions.push_back(ga);
											
													}//end if(a_name == VLAN_POP)
													else if(a_name == SET_ETH_SRC_ADDR)
													{
														logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "\"%s\" \"%s\" not available",ACTIONS,SET_ETH_SRC_ADDR);

														logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,SET_ETH_SRC_ADDR,a_value.getString().c_str());

														//XXX: currently, this information is ignored	
													}
													else if(a_name == SET_ETH_DST_ADDR)
													{
														logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "\"%s\" \"%s\" not available",ACTIONS,SET_ETH_DST_ADDR);

														logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,SET_ETH_DST_ADDR,a_value.getString().c_str());

														//XXX: currently, this information is ignored	
													}
													else if(a_name == SET_IP_SRC_ADDR)
													{
														logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "\"%s\" \"%s\" not available",ACTIONS,SET_IP_SRC_ADDR);

														logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,SET_IP_SRC_ADDR,a_value.getString().c_str());

														//XXX: currently, this information is ignored	
													}
													else if(a_name == SET_IP_DST_ADDR)
													{
														logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "\"%s\" \"%s\" not available",ACTIONS,SET_IP_DST_ADDR);

														logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,SET_IP_DST_ADDR,a_value.getString().c_str());

														//XXX: currently, this information is ignored	
													}
													else if(a_name == SET_IP_TOS)
													{
														logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "\"%s\" \"%s\" not available",ACTIONS,SET_IP_TOS);

														logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,SET_IP_TOS,a_value.getString().c_str());

														//XXX: currently, this information is ignored	
													}
													else if(a_name == SET_L4_SRC_PORT)
													{
														logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "\"%s\" \"%s\" not available",ACTIONS,SET_L4_SRC_PORT);

														logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,SET_L4_SRC_PORT,a_value.getString().c_str());

														//XXX: currently, this information is ignored	
													}
													else if(a_name == SET_L4_DST_PORT)
													{
														logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "\"%s\" \"%s\" not available",ACTIONS,SET_L4_DST_PORT);

														logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,SET_L4_DST_PORT,a_value.getString().c_str());

														//XXX: currently, this information is ignored	
													}
													else if(a_name == OUT_TO_QUEUE)
													{
														logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "\"%s\" \"%s\" not available",ACTIONS,OUT_TO_QUEUE);

														logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,OUT_TO_QUEUE,a_value.getString().c_str());

														//XXX: currently, this information is ignored	
													}
													else if(a_name == DROP)
													{
														logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "\"%s\" \"%s\" not available",ACTIONS,DROP);

														logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,DROP,a_value.getString().c_str());

														//XXX: currently, this information is ignored	
													}
													else if(a_name == OUTPUT_TO_CTRL)
													{
														logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "\"%s\" \"%s\" not available",ACTIONS,OUTPUT_TO_CTRL);

														logger(ORCH_DEBUG, MODULE_NAME, __FILE__, __LINE__, "\"%s\"->\"%s\": \"%s\"",ACTIONS,OUTPUT_TO_CTRL,a_value.getString().c_str());

														//XXX: currently, this information is ignored	
													}
													else
													{
														logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Invalid key \"%s\" in \"%s\"",a_name.c_str(),ACTIONS);
														return false;
													}
												}
	
												if(!foundOne)
												{
													logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Neither Key \"%s\", nor key \"%s\" found in \"%s\"",PORT_IN,_ID,ACTIONS);
													return false;
												}
												for(list<GenericAction*>::iterator ga = genericActions.begin(); ga != genericActions.end(); ga++)
												{
													action->addGenericAction(*ga);
												}
											}
										}//end if(fr_name == ACTION)
										else
										{
											logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Invalid key \"%s\" in a rule of \"%s\"",name.c_str(),FLOW_RULES);
											return false;
										}
									}
						
									if(!foundAction || !foundMatch || !foundID)
									{
										logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\", or key \"%s\", or key \"%s\", or all of them not found in an elmenet of \"%s\"",_ID,MATCH,ACTIONS,FLOW_RULES);
										return false;
									}
						
									highlevel::Rule rule(match,action,ruleID,priority);
							
									if(!graph.addRule(rule))
									{
										logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "The graph has at least two rules with the same ID: %s",ruleID.c_str());
										return false;
									}
					
								}//for( unsigned int fr = 0; fr < flow_rules_array.size(); ++fr )
								
								bool same_priority = false;
							list<highlevel::Rule> rules = graph.getRules();
							for(list<highlevel::Rule>::iterator r = rules.begin(); r != rules.end(); r++)
							{
								uint64_t priority = (*r).getPriority();
								for(list<highlevel::Rule>::iterator r1 = r; r1!=rules.end(); r1++)
								{
									if((*r1).getPriority() == priority)
										same_priority = true;
								}
							}
						
							if(same_priority)
								logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "One or more flow rule with the same priority, switch can delete one of this rules");
								}// end  if (fg_name == FLOW_RULES)
							}
			    		}
					}
			    	if(!foundFlowRules)
				{
					logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\" not found in \"%s\"",FLOW_RULES,FORWARDING_GRAPH);
					return false;
				}
				if(!foundVNFs)
					logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\" not found in \"%s\"",VNFS,FORWARDING_GRAPH);
			}
			else
			{
				logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Invalid key: %s",name.c_str());
				return false;
			}
		}
		if(!foundFlowGraph)
		{
			logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "Key \"%s\" not found",FORWARDING_GRAPH);
			return false;
		}
	}catch(exception& e)
	{
		logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "The content does not respect the JSON syntax: ",e.what());
		return false;
	}

#ifndef UNIFY_NFFG
	//XXX The number of ports is provided by the name resolver, and should not depend on the flows inserted. In fact,
	//it should be possible to start VNFs without setting flows related to such a function!
    	for(map<string,set<unsigned int> >::iterator it = nfs_ports_found.begin(); it != nfs_ports_found.end(); it++)
	{
		set<unsigned int> ports = it->second;
		assert(ports.size() != 0);
		
		for(set<unsigned int>::iterator p = ports.begin(); p != ports.end(); p++)
		{
			if(!graph.updateNetworkFunction(it->first,*p))
			{
				if(newGraph)
					return false;
				else
				{
					//The message does not describe the current NF into the section "VNFs". However, this NF could be
					//already part of the graph, and in this case the match/action using it is valid. On the contrary,
					//if the NF is no longer part of the graph, there is an error, and the graph cannot be updated.
					if(gm->graphContainsNF(graph.getID(),it->first))
					{
						graph.addNetworkFunction(it->first);
						graph.updateNetworkFunction(it->first,*p);
					}
					else
						return false;
				}
			}
		}
		
		logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "NF \"%s\" requires ports:",it->first.c_str());
		for(set<unsigned int>::iterator p = ports.begin(); p != ports.end(); p++)
			logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "\t%d",*p);
	}
#endif	
	
	return true;
}

int RestServer::doGet(struct MHD_Connection *connection, const char *url)
{
	struct MHD_Response *response;
	int ret;
	
	bool request = 0; //false->graph - true->interfaces
	
	//Check the URL
	char delimiter[] = "/";
 	char * pnt;

	char graphID[BUFFER_SIZE];
	char tmp[BUFFER_SIZE];
	strcpy(tmp,url);
	pnt=strtok(tmp, delimiter);
	int i = 0;
	while( pnt!= NULL )
	{
		switch(i)
		{
			case 0:
				if(strcmp(pnt,BASE_URL_GRAPH) == 0)
					request = false;
				else if(strcmp(pnt,BASE_URL_IFACES) == 0)
					request = true;
				else
				{
get_malformed_url:
					logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Resource \"%s\" does not exist", url);
					response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
					ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
					MHD_destroy_response (response);
					return ret;
				}
				break;
			case 1:
				strcpy(graphID,pnt);
		}
		
		pnt = strtok( NULL, delimiter );
		i++;
	}
	if( (!request && i != 2) || (request == 1 && i != 1) )
	{
		//the URL is malformed
		goto get_malformed_url;
	}
	
	if(MHD_lookup_connection_value (connection,MHD_HEADER_KIND, "Host") == NULL)
	{
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "\"Host\" header not present in the request");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
		MHD_destroy_response (response);
		return ret;
	}
	
	//if client authentication is required
	if(dbmanager != NULL)
	{
		const char *token = MHD_lookup_connection_value (connection,MHD_HEADER_KIND, "X-Auth-Token");
	
		if(!checkAuthentication(connection, token, dbmanager))
		{
			//User unauthenticated!
			response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
			int ret = MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
			MHD_destroy_response (response);
			return ret;
		}
	}

	if(!request)
		//request for a graph description
		return doGetGraph(connection,graphID);
	else
		//request for interfaces description
		return doGetInterfaces(connection);	
}

int RestServer::doGetGraph(struct MHD_Connection *connection,char *graphID)
{
	struct MHD_Response *response;
	int ret;
	
	logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Required resource: %s",graphID);
	
	if(!gm->graphExists(graphID))
	{	
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Method GET is not supported for this resource");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header (response, "Allow", PUT);
		ret = MHD_queue_response (connection, MHD_HTTP_METHOD_NOT_ALLOWED, response);
		MHD_destroy_response (response);
		return ret;
	}
	
	try
	{
		Object json = gm->toJSON(graphID);
		stringstream ssj;
 		write_formatted(json, ssj );
 		string sssj = ssj.str();		
 		char *aux = (char*)malloc(sizeof(char) * (sssj.length()+1));
 		strcpy(aux,sssj.c_str());
		response = MHD_create_response_from_buffer (strlen(aux),(void*) aux, MHD_RESPMEM_PERSISTENT);		
		MHD_add_response_header (response, "Content-Type",JSON_C_TYPE);
		MHD_add_response_header (response, "Cache-Control",NO_CACHE);
		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
		MHD_destroy_response (response);
		return ret;
	}catch(...)
	{
		logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "An error occurred while retrieving the graph description!");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		ret = MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		MHD_destroy_response (response);
		return ret;
	}
}

int RestServer::doGetInterfaces(struct MHD_Connection *connection)
{
	struct MHD_Response *response;
	int ret;
	
	try
	{
		Object json = gm->toJSONPhysicalInterfaces();
		stringstream ssj;
 		write_formatted(json, ssj );
 		string sssj = ssj.str();
 		char *aux = (char*)malloc(sizeof(char) * (sssj.length()+1));
 		strcpy(aux,sssj.c_str());
		response = MHD_create_response_from_buffer (strlen(aux),(void*) aux, MHD_RESPMEM_PERSISTENT);		
		MHD_add_response_header (response, "Content-Type",JSON_C_TYPE);
		MHD_add_response_header (response, "Cache-Control",NO_CACHE);
		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
		MHD_destroy_response (response);
		return ret;
	}catch(...)
	{
		logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "An error occurred while retrieving the description of the physical interfaces!");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		ret = MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		MHD_destroy_response (response);
		return ret;
	}
}

int RestServer::doDelete(struct MHD_Connection *connection, const char *url, void **con_cls)
{
	struct MHD_Response *response;
	int ret;
	
	//Check the URL
	char delimiter[] = "/";
 	char * pnt;

	char graphID[BUFFER_SIZE];
	char flowID[BUFFER_SIZE];
	bool specificFlow = false;
	
	char tmp[BUFFER_SIZE];
	strcpy(tmp,url);
	pnt=strtok(tmp, delimiter);
	int i = 0;
	while( pnt!= NULL )
	{
		switch(i)
		{
			case 0:
				if(strcmp(pnt,BASE_URL_GRAPH) != 0)
				{
delete_malformed_url:
					logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Resource \"%s\" does not exist", url);
					response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
					ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
					MHD_destroy_response (response);
					return ret;
				}
				break;
			case 1:
				strcpy(graphID,pnt);
				break;
			case 2:
				strcpy(flowID,pnt);
				specificFlow = true;
		}
		
		pnt = strtok( NULL, delimiter );
		i++;
	}
	if((i != 2) && (i != 3))
	{
		//the URL is malformed
		goto delete_malformed_url;
	}
	
	if(MHD_lookup_connection_value (connection,MHD_HEADER_KIND, "Host") == NULL)
	{
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "\"Host\" header not present in the request");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
		MHD_destroy_response (response);
		return ret;
	}
	
	struct connection_info_struct *con_info = (struct connection_info_struct *)(*con_cls);
	assert(con_info != NULL);
	if(con_info->length != 0)
	{
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "DELETE with body is not allowed");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
		MHD_destroy_response (response);
		return ret;
	}
	
	//if client authentication is required
	if(dbmanager != NULL){
		const char *token = MHD_lookup_connection_value (connection,MHD_HEADER_KIND, "X-Auth-Token");
	
		if(!checkAuthentication(connection, token, dbmanager))
		{
			//User unauthenticated!
			response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
			int ret = MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
			MHD_destroy_response (response);
			return ret;
		}
	}

	logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Deleting resource: %s/%s",graphID,(specificFlow)?flowID:"");

	if(!gm->graphExists(graphID) || (specificFlow && !gm->flowExists(graphID,flowID)))
	{
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "Method DELETE is not supported for this resource");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header (response, "Allow", PUT);
		ret = MHD_queue_response (connection, MHD_HTTP_METHOD_NOT_ALLOWED, response);
		MHD_destroy_response (response);
		return ret;
	}
	
	try
	{	
		if(!specificFlow)
		{
			//The entire graph must be deleted
			if(!gm->deleteGraph(graphID))
			{
				response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
				int ret = MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
				MHD_destroy_response (response);
				return ret;
			}
			else
				logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "The graph has been properly deleted!");
				logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "");
		}
		else
		{
			//A specific flow must be deleted
			if(!gm->deleteFlow(graphID,flowID))
			{
				response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
				int ret = MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
				MHD_destroy_response (response);
				return ret;
			}
			else
				logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "The flow has been properly deleted!");
		}
	
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);		
		ret = MHD_queue_response (connection, MHD_HTTP_NO_CONTENT, response);
		MHD_destroy_response (response);
		return ret;
	}catch(...)
	{
		logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "An error occurred during the destruction of the graph!");
		response = MHD_create_response_from_buffer (0,(void*) "", MHD_RESPMEM_PERSISTENT);
		ret = MHD_queue_response (connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		MHD_destroy_response (response);
		return ret;
	}		
}

bool RestServer::checkAuthentication(struct MHD_Connection *connection,const char *token,SQLiteManager *dbmanager)
{

	if(token == NULL)
	{
		logger(ORCH_INFO, MODULE_NAME, __FILE__, __LINE__, "\"Token\" header not present in the request");
		return false;
	} 
	else
	{
		dbmanager->selectToken((char *)token);
		if(strcmp(dbmanager->getToken(), token) == 0){
			//User authenticated!
			logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__, "User authenticated");
			return true;
		}
		else
		{
			//User unauthenticated!
			logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__, "User unauthenticated");
			return false;
		}
	}
}

