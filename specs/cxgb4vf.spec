%{!?release:%define release 0}
%{!?kversion:%define kversion %(uname -r)}

Summary: Chelsio Terminator 4 virtual network driver for Linux
Name:    cxgb4vf
Version: %{version}
Release: %{release}
License: GPL
Group:   System Environment/Kernel
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>
Provides: cxgb4vf-%{version}

BuildRoot: %{_tmppath}/cxgb4vf-%{version}-%{release}-%{kversion}-root
#BuildRequires: kernel-devel
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc
ExclusiveOS: linux

%define drvbase /lib/modules/%{kversion}/updates
%define fwdir /lib/firmware
%define rpmfiles %{_topdir}/BUILD/cxgb4vf-%{version}/rpmfiles.txt

%description
The Chelsio Terminator 4 Ethernet Adapter driver for Linux kernel (%{kversion}).

%prep
%{__mkdir} -p cxgb4vf-%{version}/cxgb4vf
%{__cp} -a %{srcdir}/cxgb4vf/cxgb4vf.ko cxgb4vf-%{version}/cxgb4vf/
echo "%{drvbase}/drivers/net/cxgb4vf/cxgb4vf.ko" > %{rpmfiles}

%build

%pre

%post
file=/etc/modprobe.d/libcxgb4.conf
lines=`grep -n "^install cxgb4 " $file 2>/dev/null | sed 's/:.*//g' | sort -gr`
string="# Disabled by Chelsio Makefile on `date`"
for i in $lines; do
  sed -i "$i"'s/^install cxgb4\s/#install cxgb4 /' $file
  let i-=1
  sed -i "$i"'a'"$string" $file
done
depmod
exit 0

%postun
file=/etc/modprobe.d/libcxgb4.conf
string="# Disabled by Chelsio Makefile"
lines=`grep -n "^$string" $file 2>/dev/null | sed 's/:.*//g' | sort -gr`
for i in $lines; do
  sed -i "$i"'d' $file
  sed -i "$i"'s/^#//' $file
done
depmod
exit 0

%install
cd %{_topdir}/BUILD/cxgb4vf-%{version}
%{__install} -D -v cxgb4vf/cxgb4vf.ko %{buildroot}/%{drvbase}/drivers/net/cxgb4vf/cxgb4vf.ko

%debug_package

%files -f %{_builddir}/cxgb4vf-%{version}/rpmfiles.txt
%defattr(744,root,root)

%clean
%{__rm} -rf %{buildroot}

%changelog
