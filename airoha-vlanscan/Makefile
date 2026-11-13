# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=airoha-vlanscan
PKG_VERSION:=0.2.0
PKG_RELEASE:=3
PKG_URL:=https://github.com/pbs05/openwrt-pon-userspace/tree/main/airoha-vlanscan

PKG_LICENSE:=GPL-2.0-only
PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/airoha-vlanscan
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=PON
  TITLE:=Airoha PON VLAN id scanner
  DEPENDS:=$(RUST_ARCH_DEPENDS)
endef

define Package/airoha-vlanscan/description
 Discovers which 802.1Q VLAN ids carry traffic on the PON uplink. Passive
 listening mode never transmits anything; the optional probe mode sends
 discovery frames only (ARP request, PPPoE PADI, DHCP DISCOVER) as
 802.1Q-tagged frames on the parent link, with a configurable source MAC,
 and never binds a lease or a session. With no explicit candidate list the
 probe only covers VLANs already configured on the PON parent; 'common' and
 'all' presets are opt-in because ISP VLAN ids differ by region. No
 interfaces are created or modified and UCI configuration is never touched.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/Cargo.toml ./src/Cargo.lock $(PKG_BUILD_DIR)/
	$(CP) ./src/src $(PKG_BUILD_DIR)/
endef

define Package/airoha-vlanscan/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/vlanscan $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) ./files/vlanscan-ctl $(1)/usr/libexec/vlanscan-ctl
endef

$(eval $(call RustBinPackage,airoha-vlanscan))
$(eval $(call BuildPackage,airoha-vlanscan))
