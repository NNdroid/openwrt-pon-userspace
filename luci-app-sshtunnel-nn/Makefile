# SPDX-License-Identifier: Apache-2.0

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for SSH Tunnels (sshtunnel package)
LUCI_URL:=https://github.com/NNdroid/openwrt-pon-userspace
LUCI_DEPENDS:=+luci-base +sshtunnel-nn
LUCI_PKGARCH:=all

PKG_NAME:=luci-app-sshtunnel-nn
PKG_VERSION:=1.1.1
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=Sergey Ponomarev <stokito@gmail.com>

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
