# SPDX-License-Identifier: Apache-2.0

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI VLAN scan jobs for the PON uplink
LUCI_URL:=https://github.com/pbs05/openwrt-pon-userspace/tree/main/luci-app-vlanscan
LUCI_DEPENDS:=+luci-base +airoha-vlanscan
LUCI_PKGARCH:=all

PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage: feed scanner marker; luci.mk generates the package rules.
