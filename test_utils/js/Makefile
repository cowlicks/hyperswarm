# git submodule directories
HYPERDHT_DIR := hyperdht
SODIUM_NATIVE_DIR := sodium-native
UDX_NATIVE_DIR := udx-native
DHT_RPC_DIR := rpc

# I update these in development so we want to rebuild if they change
HDHT_SOURCES = $(shell test -d $(HYPERDHT_DIR) && find $(HYPERDHT_DIR) -type f -name "*.js")

node_modules: package.json $(HYPERDHT_DIR) $(HDHT_SOURCES) $(SODIUM_NATIVE_DIR)/prebuilds $(UDX_NATIVE_DIR)/prebuilds
	npm install

$(SODIUM_NATIVE_DIR)/prebuilds: $(SODIUM_NATIVE_DIR)
	$(MAKE) -C sodium-native prebuilds

$(UDX_NATIVE_DIR)/prebuilds: $(UDX_NATIVE_DIR)
	$(MAKE) -C udx-native prebuilds

# pull in the submodule if it doesn't exist
$(HYPERDHT_DIR) $(SODIUM_NATIVE_DIR) $(UDX_NATIVE_DIR) $(DHT_RPC_DIR):
	git submodule update --init --recursive

clean:
	rm -rf package-lock.json node_modules yarn.lock
	$(MAKE) -C sodium-native clean || true # fails if sodium native git submodule not pulled in

.PHONY: clean
