PROG = test
OBJS = test.o

ROOT_DIR= $(shell pwd)

PKG_CONFIG = pkg-config
PKG_CONFIG_PATH += $(OSSL_DIR)
PKGS = openssl
CFLAGS += $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --cflags $(PKGS))
LDLIBS += $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs-only-L --static $(PKGS))
LDLIBS += -l:libcrypto.a

CFLAGS += -Wall -Werror

OSSL_DIR = openssl-3.0.12
OSSL_CFG_PARAMS = \
	--prefix=$(ROOT_DIR)/$(OSSL_DIR)/build \
	-no-shared \
	-static \
	fips \
	no-capieng \
	no-heartbeats \
	no-idea \
	no-md2 \
	no-mdc2 \
	no-rc5 \
	no-seed \
	no-siphash \
	no-sm2 \
	no-sm3 \
	no-sm4 \
	no-srp \
	no-ssl \
	no-zlib \
	threads \

all: .ossldone $(PROG)

.ossldone:
	cd $(OSSL_DIR) && \
	./Configure $(OSSL_CFG_PARAMS) && \
	make -j8 && \
	make -j8 install_sw && \
	touch $(ROOT_DIR)/.ossldone

clean:
	rm -f $(OBJS) $(PROG)

cleanall:
	rm -f .ossldone;
	cd $(OSSL_DIR) && \
	make clean
	rm -f *.so.3
	rm -rf $(OSSL_DIR)/build

.PHONY: clean cleanall
