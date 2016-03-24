#include "SQLiteManager.h"
#include "SQLiteManager_constants.h"

sqlite3 *SQLiteManager::db = NULL;
char *SQLiteManager::db_name = NULL;

SQLiteManager::SQLiteManager(char *db_name) {
	this->db_name = db_name;

	if (connect(db_name)) {
		logger(ORCH_ERROR, MODULE_NAME, __FILE__, __LINE__,
				"Can't open database: %s.", sqlite3_errmsg(this->db));
		throw SQLiteManagerException();
	} else
		logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__,
				"Opened database successfully.");
}

SQLiteManager::~SQLiteManager() {
	disconnect();
}


sqlite3* SQLiteManager::getDb() {
	return this->db;
}

int SQLiteManager::connect(char *db_name) {
	int rc = 0;

	rc = sqlite3_open(db_name, &(this->db));

	return rc;
}

void SQLiteManager::disconnect() {
	sqlite3_close(this->db);
}

bool SQLiteManager::createTables() {
	int rc = 0;
	char *zErrMsg = 0, *sql = NULL;

	sql = "CREATE TABLE USERS("								\
			"USER		TEXT	PRIMARY KEY	NOT NULL, "		\
			"PWD		TEXT				NOT NULL, "		\
			"MEMBERSHIP	TEXT				NOT NULL); "	\

		"CREATE TABLE LOGIN(" 							\
			"TOKEN		TEXT	PRIMARY KEY	NOT NULL, " \
			"USER		TEXT	UNIQUE		NOT NULL, " \
			"TIMESTAMP	TEXT				NOT NULL); "	\

		"CREATE TABLE GENERIC_RESOURCES("				\
			"GENERIC_RESOURCE	PRIMARY KEY	NOT NULL);"	\

		"CREATE TABLE USER_CREATION_PERMISSIONS("		\
			"USER				TEXT	NOT NULL, "		\
			"GENERIC_RESOURCE	TEXT	NOT NULL, "		\
			"PERMISSION			TEXT	NOT NULL, "		\
			"PRIMARY KEY (USER, GENERIC_RESOURCE)); "	\

		"CREATE TABLE DEFAULT_USAGE_PERMISSIONS("				\
			"GENERIC_RESOURCE	TEXT	PRIMARY KEY	NOT NULL, "	\
			"OWNER_PERMISSION	TEXT				NOT NULL, "	\
			"GROUP_PERMISSION	TEXT				NOT NULL, "	\
			"ALL_PERMISSION		TEXT				NOT NULL, "	\
			"ADMIN_PERMISSION	TEXT				NOT NULL); " \

		"CREATE TABLE CURRENT_RESOURCES_PERMISSIONS("			\
			"GENERIC_RESOURCE	TEXT				NOT NULL, "	\
			"RESOURCE			TEXT				NOT NULL, "	\
			"OWNER				TEXT				NOT NULL, "	\
			"OWNER_PERMISSION	TEXT				NOT NULL, "	\
			"GROUP_PERMISSION	TEXT				NOT NULL, "	\
			"ALL_PERMISSION		TEXT				NOT NULL, "	\
			"ADMIN_PERMISSION	TEXT				NOT NULL, " \
			"PRIMARY KEY (GENERIC_RESOURCE, RESOURCE));";

	rc = sqlite3_exec(this->db, sql, NULL, NULL, &zErrMsg);

	if (rc != SQLITE_OK) {
		logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "SQL error: %s.",
				zErrMsg);
		return false;
	} else
		logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__,
				"Table created successfully.");

	return true;
}

bool SQLiteManager::resourceExists(const char *generic_resource) {
	sqlite3_stmt *stmt;
	int rc = 0, res = 0, idx = 0, count = 0;
	const char *sql = "select count(*) from GENERIC_RESOURCES where GENERIC_RESOURCE = @generic_resource;";

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@generic_resource");
		sqlite3_bind_text(stmt, idx, generic_resource, strlen(generic_resource), 0);

		res = sqlite3_step(stmt);

		if (res == SQLITE_ROW)
			count = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);

	return (count > 0);
}

bool SQLiteManager::resourceExists(const char *generic_resource, const char *resource) {
	assert(generic_resource != NULL && resource != NULL);

	sqlite3_stmt *stmt;
	int rc = 0, res = 0, idx = 0, count = 0;
	const char *sql = "select count(*) "	\
						"from CURRENT_RESOURCES_PERMISSIONS "	\
						"where GENERIC_RESOURCE = @generic_resource and RESOURCE = @resource;";

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@generic_resource");
		sqlite3_bind_text(stmt, idx, generic_resource, strlen(generic_resource), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@resource");
		sqlite3_bind_text(stmt, idx, resource, strlen(resource), 0);

		res = sqlite3_step(stmt);

		if (res == SQLITE_ROW)
			count = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);

	return (count > 0);
}

bool SQLiteManager::cleanTables() {
	int rc = 0;
	char *zErrMsg = 0, *sql = "delete from LOGIN; "	\
								"delete from CURRENT_RESOURCES_PERMISSIONS;";

	rc = sqlite3_exec(this->db, sql, NULL, NULL, &zErrMsg);

	if (rc != SQLITE_OK) {
		logger(ORCH_WARNING, MODULE_NAME, __FILE__, __LINE__, "SQL error: %s.",
				zErrMsg);
		return false;
	} else
		logger(ORCH_DEBUG_INFO, MODULE_NAME, __FILE__, __LINE__,
				"Tables (LOGIN, RESOURCES, PERMISSIONS) has been cleaned up.");

	return true;
}

user_info_t *SQLiteManager::getUserByToken(const char *token) {

	int rc = 0, res = 0, idx = 0;
	char *sql = "select USER, MEMBERSHIP, PWD " \
				"from USERS " \
				"where USER in (select USER from LOGIN where TOKEN = @token);";

	sqlite3_stmt *stmt;
	user_info_t *usr = NULL;

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@token");
		sqlite3_bind_text(stmt, idx, token, strlen(token), 0);

		res = sqlite3_step(stmt);

		if (res == SQLITE_ROW) {
			usr = (user_info_t *) malloc(sizeof(user_info_t));

			usr->user = (char *) sqlite3_column_text(stmt, 0);
			usr->group = (char *) sqlite3_column_text(stmt, 1);
			usr->pwd = (char *) sqlite3_column_text(stmt, 2);
			usr->token = (char *) token;
		}
	}

	return usr;
}

char *SQLiteManager::getGroup(const char *user) {

	int rc = 0, res = 0, idx = 0;
	char *group = NULL, *sql = "select MEMBERSHIP " \
								"from USERS " \
								"where USER = @user;";

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@user");
		sqlite3_bind_text(stmt, idx, user, strlen(user), 0);

		res = sqlite3_step(stmt);

		if (res == SQLITE_ROW)
			group = (char *) sqlite3_column_text(stmt, 0);
	}

	return group;
}

bool SQLiteManager::isGenericResource(const char *generic_resource) {
	int rc = 0, res = 0, idx = 0, count = 0;
	char *sql = "select * from GENERIC_RESOURCES where GENERIC_RESOURCE = @generic_resource;";

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@generic_resource");
		sqlite3_bind_text(stmt, idx, generic_resource, strlen(generic_resource), 0);

		res = sqlite3_step(stmt);

		if (res == SQLITE_ROW)
			count = sqlite3_column_count(stmt);
	}

	sqlite3_finalize(stmt);

	return (count > 0);
}

int SQLiteManager::insertResource(char *generic_resource, char *resource, char *owner) {
	int rc = 0, res = 0, idx = 0;
	char *owner_p = NULL, *group_p = NULL, *all_p = NULL, *admin_p = NULL, *sql = NULL;

	sqlite3_stmt *stmt;

	sql = "select OWNER_PERMISSION, GROUP_PERMISSION, ALL_PERMISSION, ADMIN_PERMISSION " \
			"from DEFAULT_USAGE_PERMISSIONS " \
			"where GENERIC_RESOURCE = @generic_resource";

	if ((rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0)) == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@generic_resource");
		sqlite3_bind_text(stmt, idx, generic_resource, strlen(generic_resource), 0);

		res = sqlite3_step(stmt);

		if (res == SQLITE_ROW) {
			owner_p = (char *) sqlite3_column_text(stmt, 0);
			group_p = (char *) sqlite3_column_text(stmt, 1);
			all_p = (char *) sqlite3_column_text(stmt, 2);
			admin_p = (char *) sqlite3_column_text(stmt, 3);
		}

		// Default permissions should be stored in the database
		assert(owner_p != NULL && group_p != NULL && all_p != NULL && admin_p != NULL);

		sql = "insert into CURRENT_RESOURCES_PERMISSIONS(" \
				"GENERIC_RESOURCE, RESOURCE, OWNER, " \
				"OWNER_PERMISSION, GROUP_PERMISSION, ALL_PERMISSION, ADMIN_PERMISSION) " \
				"values (@generic_resource, @resource, @owner, @owner_p, @group_p, @all_p, @admin_p);";

		if((rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0)) == SQLITE_OK) {
			idx = sqlite3_bind_parameter_index(stmt, "@generic_resource");
			sqlite3_bind_text(stmt, idx, generic_resource, strlen(generic_resource), 0);

			idx = sqlite3_bind_parameter_index(stmt, "@resource");
			sqlite3_bind_text(stmt, idx, resource, strlen(resource), 0);

			idx = sqlite3_bind_parameter_index(stmt, "@owner");
			sqlite3_bind_text(stmt, idx, owner, strlen(owner), 0);

			idx = sqlite3_bind_parameter_index(stmt, "@owner_p");
			sqlite3_bind_text(stmt, idx, owner_p, strlen(owner_p), 0);

			idx = sqlite3_bind_parameter_index(stmt, "@group_p");
			sqlite3_bind_text(stmt, idx, owner_p, strlen(group_p), 0);

			idx = sqlite3_bind_parameter_index(stmt, "@all_p");
			sqlite3_bind_text(stmt, idx, all_p, strlen(all_p), 0);

			idx = sqlite3_bind_parameter_index(stmt, "@admin_p");
			sqlite3_bind_text(stmt, idx, admin_p, strlen(admin_p), 0);

			res = sqlite3_step(stmt);
		}
	}

	sqlite3_finalize(stmt);

	return res;
}

int SQLiteManager::insertResource(char *generic_resource) {
	int rc = 0, res = 0, idx = 0;
	char *sql =
			"insert into GENERIC_RESOURCES(GENERIC_RESOURCE) values (@generic_resource);";

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@generic_resource");
		sqlite3_bind_text(stmt, idx, generic_resource, strlen(generic_resource), 0);

		res = sqlite3_step(stmt);
	}

	sqlite3_finalize(stmt);

	return res;
}

/**
 * Insert login information into the local database and cache
 */
int SQLiteManager::insertLogin(char *user, char *token, char *timestamp) {
	int rc = 0, res = 0, idx = 0;
	char *sql =
			"insert into LOGIN(TOKEN, USER, TIMESTAMP) values (@token, @user, @timestamp);";

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@token");
		sqlite3_bind_text(stmt, idx, token, strlen(token), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@user");
		sqlite3_bind_text(stmt, idx, user, strlen(user), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@timestamp");
		sqlite3_bind_text(stmt, idx, timestamp, strlen(timestamp), 0);

		res = sqlite3_step(stmt);
	}

	sqlite3_finalize(stmt);

	return res;
}

int SQLiteManager::insertUser(char *user, char *pwd, char *group) {
	int rc = 0, res = 0, idx = 0;
	char *sql =
			"insert into USERS(USER, PWD, MEMBERSHIP) values (@user, @pwd, @group);";

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@user");
		sqlite3_bind_text(stmt, idx, user, strlen(user), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@pwd");
		sqlite3_bind_text(stmt, idx, pwd, strlen(pwd), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@group");
		sqlite3_bind_text(stmt, idx, group, strlen(group), 0);

		res = sqlite3_step(stmt);

		cache.addUser(user, pwd, group);

		User *usr = cache.getUser(user);
		usr->setDirty(false);

		usr = NULL;
	}

	sqlite3_finalize(stmt);

	return res;
}

int SQLiteManager::deleteUser(char *user) {
	int rc = 0, res = 0, idx = 0;
	char *sql = "delete from USERS where USER = @user;";

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@user");
		sqlite3_bind_text(stmt, idx, user, strlen(user), 0);

		res = sqlite3_step(stmt);
	}

	sqlite3_finalize(stmt);

	return res;
}


bool SQLiteManager::isLogged(char *user) {
	int rc = 0, res = 0, idx = 0, count = 0;
	char *sql = "select count(*) from LOGIN where USER = @user;";

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@user");
		sqlite3_bind_text(stmt, idx, user, strlen(user), 0);

		res = sqlite3_step(stmt);

		if (res == SQLITE_ROW)
			count = sqlite3_column_int(stmt, 0);
	}

	sqlite3_finalize(stmt);

	return (count > 0);
}

bool SQLiteManager::userExists(char *user, char *hash_pwd) {
	int rc = 0, res = 0, idx = 0, count = 0;
	char *sql = "select count(*) from USERS where USER = @user and PWD = @hash_pwd;";

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@user");
		sqlite3_bind_text(stmt, idx, user, strlen(user), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@hash_pwd");
		sqlite3_bind_text(stmt, idx, hash_pwd, strlen(hash_pwd), 0);

		res = sqlite3_step(stmt);

		if (res == SQLITE_ROW)
			count = sqlite3_column_int(stmt, 0);
	}

	return (count > 0);
}

int SQLiteManager::deleteResource(char *generic_resource, char *resource) {
	int rc = 0, res = 0, idx = 0;
	char *sql = "delete from CURRENT_RESOURCES_PERMISSIONS where GENERIC_RESOURCE = @generic_resource and RESOURCE = @resource;";

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@generic_resource");
		sqlite3_bind_text(stmt, idx, generic_resource, strlen(generic_resource), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@resource");
		sqlite3_bind_text(stmt, idx, resource, strlen(resource), 0);

		res = sqlite3_step(stmt);
	}

	sqlite3_finalize(stmt);

	return res;
}

int SQLiteManager::insertUserCreationPermission(char *user, char *generic_resource, char *permission) {
	int rc = 0, res = 0, idx = 0;
	char *sql =
			"insert into USER_CREATION_PERMISSIONS"	\
			"(USER, GENERIC_RESOURCE, PERMISSION) "	\
			"values(@user, @generic_resource, @permission);";

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@user");
		sqlite3_bind_text(stmt, idx, user, strlen(user), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@generic_resource");
		sqlite3_bind_text(stmt, idx, generic_resource, strlen(generic_resource), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@permission");
		sqlite3_bind_text(stmt, idx, permission, 1, 0);

		res = sqlite3_step(stmt);
	}

	sqlite3_finalize(stmt);

	return res;
}

int SQLiteManager::insertDefaultUsagePermissions(char *generic_resource, char *owner_p, char *group_p,
		char *all_p, char *admin_p) {
	int rc = 0, res = 0, idx = 0;
	char *sql =
			"insert into DEFAULT_USAGE_PERMISSIONS"	\
			"(GENERIC_RESOURCE, OWNER_PERMISSION, "	\
			"GROUP_PERMISSION, ALL_PERMISSION, ADMIN_PERMISSION) "	\
			"values(@generic_resource, @owner_p, @group_p, @all_p, @admin_p);";

	sqlite3_stmt *stmt;

	rc = sqlite3_prepare_v2(this->db, sql, -1, &stmt, 0);

	if (rc == SQLITE_OK) {
		idx = sqlite3_bind_parameter_index(stmt, "@generic_resource");
		sqlite3_bind_text(stmt, idx, generic_resource, strlen(generic_resource), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@owner_p");
		sqlite3_bind_text(stmt, idx, owner_p, strlen(owner_p), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@group_p");
		sqlite3_bind_text(stmt, idx, group_p, strlen(group_p), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@all_p");
		sqlite3_bind_text(stmt, idx, all_p, strlen(all_p), 0);

		idx = sqlite3_bind_parameter_index(stmt, "@admin_p");
		sqlite3_bind_text(stmt, idx, admin_p, strlen(admin_p), 0);

		res = sqlite3_step(stmt);
	}

	sqlite3_finalize(stmt);

	return res;
}


