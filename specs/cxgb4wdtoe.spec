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
Provides: %{name}-%{version}
#Conflicts: %{conflict_name}
requires: chelsio-series4-firmware > 1.1.0.10

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}-root
#BuildRequires: kernel-devel
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc
ExclusiveOS: linux

%if %{disable_offload}
%define conflict_name %{name}toe
%else
%define conflict_name %(echo %{name} | %{__sed} 's/toe//')
%endif

%define drvbase /lib/modules/%{kversion}/updates
%define fwdir /lib/firmware/cxgb4
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%description
The Chelsio Terminator 4 Ethernet Adapter driver for Linux kernel (%{kversion}).

%prep
## offload drivers
if ((!%{disable_offload})); then
  %{__mkdir} -p %{name}-%{version}/cxgb4/
  %{__cp} -a %{srcdir}/cxgb4/cxgb4.ko %{name}-%{version}/cxgb4/
  echo "%{drvbase}/drivers/net/cxgb4.ko" > %{rpmfiles}
  %{__mkdir} -p %{name}-%{version}/t4_tom/
  %{__cp} -a %{srcdir}/t4_tom/t4_tom.ko %{name}-%{version}/t4_tom/
  echo "%{drvbase}/drivers/net/offload/t4_tom/t4_tom.ko" >> %{rpmfiles}
  if ((!%{disable_toecore})); then
    %{__mkdir} -p %{name}-%{version}/toecore/
    %{__cp} -a %{srcdir}/toecore/toecore.ko %{name}-%{version}/toecore/
    echo "%{drvbase}/drivers/net/offload/toecore.ko" >> %{rpmfiles}
  fi
fi
#if ( "%{kversion}" == "2.6.34" ); then
#   %{__mkdir} -p %{name}-%{version}/ipv6/
#   %{__cp} -a %{srcdir}/ipv6/ipv6.ko %{name}-%{version}/ipv6/.
#   echo "%{drvbase}/net/ipv6/ipv6.ko" >> %{rpmfiles}
#fi

%build
## Nothing to do here.

%pre

%post
## Workaround for auto-loading infiniband drivers.
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
if ((! %{disable_offload})); then
  %{__install} -D -v cxgb4/cxgb4.ko %{buildroot}/%{drvbase}/drivers/net/cxgb4.ko
  %{__install} -D -v t4_tom/t4_tom.ko %{buildroot}/%{drvbase}/drivers/net/offload/t4_tom/t4_tom.ko
  if ((! %{disable_toecore})); then
    %{__install} -D -v toecore/toecore.ko %{buildroot}/%{drvbase}/drivers/net/offload/toecore.ko
  fi
fi
#if ( "%{kversion}" == "2.6.34" ) ; then
#   %{__install} -D -v ipv6/ipv6.ko %{buildroot}/%{drvbase}/net/ipv6/ipv6.ko
#fi

%debug_package

%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt
%defattr(744,root,root)

%clean
%{__rm} -rf %{buildroot}

%changelog
