%{!?disable_offload:%define disable_offload 0}
%{!?disable_toecore:%define disable_toecore 0}
%{!?disable_bonding:%define disable_bonding 0}
%{!?release:%define release 0}
%{!?kversion:%define kversion %(uname -r)}

## Summary offload string define.
%if %{disable_offload}
%define offload ""
%else
%define offload "Offload "
%endif
Summary: Chelsio Terminator 4 %{offload}driver for Linux
Name:    %{name}
Version: %{version}
Release: %{release}
License: GPL
Group:   System Environment/Kernel
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>
Provides: %{name}
Provides: %{name}-%{version}
requires: cxgb4toe > 1.1.0.10, chelsio-series4-firmware > 1.1.0.10

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}-root
#BuildRequires: kernel-devel
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc
ExclusiveOS: linux

%define drvbase /lib/modules/%{kversion}/updates
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%description
The Chelsio Terminator 4 Ethernet Adapter Bonding driver for Linux kernel (%{kversion}).

%prep
%{__mkdir} -p %{name}-%{version}/drivers/net/bonding/
%{__cp} -a %{srcdir}/bonding/bonding.ko %{name}-%{version}/drivers/net/bonding/
echo "%{drvbase}/drivers/net/bonding/bonding.ko" > %{rpmfiles}

%build
## Nothing to do here.

%pre

%post
## Workaround for auto-loading infiniband drivers.
file=/etc/modprobe.d/libcxgb4.conf
lines=`grep -n "^install cxgb4 " $file 2>/dev/null | sed 's/:.*//g' | sort -gr`
string="# Disabled by Chelsio Makefile on `date`"
for i in $lines; do
  sed -i "$i"'s/^install cxgb4\s/#install cxgb4 /' $file
  let i-=1
  sed -i "$i"'a'"$string" $file
done
## Generate new module dependencies.
depmod
exit 0

%postun
## Workaround for auto-loading infiniband drivers.
file=/etc/modprobe.d/libcxgb4.conf
string="# Disabled by Chelsio Makefile"
lines=`grep -n "^$string" $file 2>/dev/null | sed 's/:.*//g' | sort -gr`
for i in $lines; do
  sed -i "$i"'d' $file
  sed -i "$i"'s/^#//' $file
done
## Update module dependencies.
depmod
exit 0

%install
cd %{_topdir}/BUILD/%{name}-%{version}
%{__install} -D -v drivers/net/bonding/bonding.ko %{buildroot}/%{drvbase}/drivers/net/bonding/bonding.ko

%debug_package

%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt

%defattr(744,root,root)

%clean
%{__rm} -rf %{buildroot}

%changelog
