CC=gcc
INCLUDES=`pkg-config --cflags sqlite3`
CFLAGS=-g -c -Wall -O0
LDFLAGS=`pkg-config --libs sqlite3`

SOURCES_MODULES = src/modules/conf.c
SOURCES_MODULES+= src/modules/bdd.c
SOURCES_MODULES+= src/modules/fwl.c
# comment this for linux
SOURCES_MODULES+= src/firewall/pf.c
# uncomment this for linux
#SOURCES_MODULES+= src/firewall/ipt.c
SOURCES_MODULES+= src/modules/log.c
SOURCES_MODULES+= src/modules/users.c
SOURCES_MODULES+= src/modules/sock.c
SOURCES_MODULES+= src/modules/secure_auth.c

SOURCES_SQUID = src/squid/main.c
SOURCES_SQUID+= src/squid/parseline.c
SOURCES_SQUID+= src/squid/rewrite_program.c
OBJECTS_SQUID = $(SOURCES_SQUID:.c=.o) $(SOURCES_MODULES:.c=.o)
EXECUTABLE_SQUID = sauthpf-squid

SOURCES_CLEANER = src/cleaner/main.c
OBJECTS_CLEANER = $(SOURCES_CLEANER:.c=.o) $(SOURCES_MODULES:.c=.o)
EXECUTABLE_CLEANER = sauthpf-cleaner

SOURCES_DAEMON = src/daemon/main.c
OBJECTS_DAEMON = $(SOURCES_DAEMON:.c=.o) $(SOURCES_MODULES:.c=.o)
EXECUTABLE_DAEMON = sauthpf-daemon

SOURCES_CLIENT = src/client/main.c
OBJECTS_CLIENT = $(SOURCES_CLIENT:.c=.o) $(SOURCES_MODULES:.c=.o)
EXECUTABLE_CLIENT = sauthpf-client

CONFIG_PHP = php-sauthpf-config
LIB_PHP = php-sauthpf

EXECUTABLES_SAUTHPF = $(EXECUTABLE_SQUID)
EXECUTABLES_SAUTHPF+= $(EXECUTABLE_CLEANER)
EXECUTABLES_SAUTHPF+= $(EXECUTABLE_DAEMON)
EXECUTABLES_SAUTHPF+= $(EXECUTABLE_CLIENT)
EXECUTABLES_SAUTHPF+= $(LIB_PHP)

DEBUG = 0
#DEBUG = 1

INSTALL_DATA_PATH =		/usr/local/share/
INSTALL_BIN_PATH =		/usr/local/bin/
INSTALL_SBIN_PATH =		/usr/local/sbin/
INSTALL_PHP_PATH =		/usr/local/lib/php-${PHP_VERSION}/modules/
INSTALL_PHP_CONFIG_PATH =	/etc/php-${PHP_VERSION}.sample/
APACHE_CHROOT =			/var/www/
MODULE_PHP =			sauthpf.so
CONFIG_PHP =			sauthpf.ini

DEFAULT_BDD_PATH =		/var/db/sauthpf/sessions.sqlite
DEFAULT_CONF_PATH =		/etc/
DEFAULT_CONF_FILENAME =		sauthpf.conf

DEFAULT_CONF_FILE =		\"$(DEFAULT_CONF_PATH)$(DEFAULT_CONF_FILENAME)\"
CONF_DEFAULT_BDD_PATH =		\"$(DEFAULT_BDD_PATH)\"
CONF_DEFAULT_SOCKET_PATH =	\"/var/run/sauthpf.sock\"
CONF_DEFAULT_PID_PATH =		\"/var/run/sauthpf.pid\"
CONF_DEFAULT_USER =		\"_sauthpf\"
CONF_DEFAULT_GROUP =		\"_sauthpf\"
CONF_DEFAULT_SESSIONS_TTL =	3600
CONF_DEFAULT_SECURE_AUTH =	true

DEFINES += -DDEFAULT_CONF_FILE=$(DEFAULT_CONF_FILE)
DEFINES += -DCONF_DEFAULT_BDD_PATH=$(CONF_DEFAULT_BDD_PATH)
DEFINES += -DCONF_DEFAULT_SOCKET_PATH=$(CONF_DEFAULT_SOCKET_PATH)
DEFINES += -DCONF_DEFAULT_PID_PATH=$(CONF_DEFAULT_PID_PATH)
DEFINES += -DCONF_DEFAULT_USER=$(CONF_DEFAULT_USER)
DEFINES += -DCONF_DEFAULT_GROUP=$(CONF_DEFAULT_GROUP)
DEFINES += -DCONF_DEFAULT_SESSIONS_TTL=$(CONF_DEFAULT_SESSIONS_TTL)
DEFINES += -DCONF_DEFAULT_SECURE_AUTH=$(CONF_DEFAULT_SECURE_AUTH)
DEFINES += -DDEBUG=$(DEBUG)
# comment this for linux
DEFINES += -DHAVE_PF
# uncomment this for linux
#DEFINES += -DHAVE_IPTABLE

all: $(EXECUTABLES_SAUTHPF)
	@echo 'Compilation pass : '
	@echo 'now run make install'

$(EXECUTABLE_CLEANER): $(OBJECTS_CLEANER)
	$(CC) $(LDFLAGS) $(OBJECTS_CLEANER) -o $@

$(EXECUTABLE_SQUID): $(OBJECTS_SQUID)
	$(CC) $(LDFLAGS) $(OBJECTS_SQUID) -o $@

$(EXECUTABLE_DAEMON): $(OBJECTS_DAEMON)
	$(CC) $(LDFLAGS) $(OBJECTS_DAEMON) -o $@

$(EXECUTABLE_CLIENT): $(OBJECTS_CLIENT)
	$(CC) $(LDFLAGS) $(OBJECTS_CLIENT) -o $@

$(CONFIG_PHP):
	cp -r src/modules src/php/
	cd src/php/ && DEFINES="$(DEFINES)" phpize-${PHP_VERSION} && \
	    ./configure --with-php-config=php-config-$(PHP_VERSION) \
	    --enable-sauthpf && cd ../.. && touch $(CONFIG_PHP)

$(LIB_PHP):$(CONFIG_PHP)
	cd src/php/ && make && cd ../.. && touch $(LIB_PHP)

.c.o:
	$(CC) $(DEFINES) $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -f $(CONFIG_PHP)
	rm -f $(EXECUTABLES_SAUTHPF)
	rm -f src/*/*.o
	rm -f data$(DEFAULT_BDD_PATH)
	cd src/php && phpize-${PHP_VERSION} --clean && cd ../..
	rm -rf src/php/modules

install:
	install -d $(INSTALL_PHP_PATH)
	install src/php/modules/$(MODULE_PHP) $(INSTALL_PHP_PATH)

	install $(EXECUTABLE_SQUID) $(INSTALL_BIN_PATH)
	install $(EXECUTABLE_DAEMON) $(INSTALL_SBIN_PATH)
	install $(EXECUTABLE_CLEANER) $(INSTALL_SBIN_PATH)
	install $(EXECUTABLE_CLIENT) $(INSTALL_SBIN_PATH)

	install -d $(INSTALL_DATA_PATH)sauthpf/php
	install -d $(INSTALL_DATA_PATH)sauthpf/www
	install data/create_session.sh $(INSTALL_DATA_PATH)sauthpf/
	install data/sauthpf.conf $(INSTALL_DATA_PATH)sauthpf/
	install data/php/$(CONFIG_PHP) $(INSTALL_DATA_PATH)sauthpf/php
	install data/php/$(CONFIG_PHP) $(INSTALL_PHP_CONFIG_PATH)

	install -d $(APACHE_CHROOT)/sauthpf/
	cp -r data/www/* $(APACHE_CHROOT)/sauthpf/


uninstall:
	rm -f $(INSTALL_BIN_PATH)$(EXECUTABLE_SQUID)
	rm -f $(INSTALL_SBIN_PATH)$(EXECUTABLE_DAEMON)
	rm -f $(INSTALL_SBIN_PATH)$(EXECUTABLE_CLEANER)
	rm -f $(INSTALL_SBIN_PATH)$(EXECUTABLE_CLIENT)
	rm -rf $(INSTALL_DATA_PATH)sauthpf
	rm -rf $(APACHE_CHROOT)/sauthpf
	rm -f $(INSTALL_PHP_PATH)$(MODULE_PHP)
	rm -f $(INSTALL_PHP_CONFIG_PATH)$(CONFIG_PHP)
