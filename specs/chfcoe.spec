%define kver %{expand:%%(echo ${KVER:-$(uname -r)})}
%{!?arch:%define arch %(uname -p)}

Summary: Chelsio Terminator FCoE Partial Offload Driver for Linux
Name: %{name}
Version: %{version}
Release: %{release}
License: GPL
Group:   System Environment/Kernel
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>
Provides: chfcoe-%{version}
requires: scst-%{kver}, scst-%{kver}-devel, cxgb4 > 1.1.0.10, chelsio-series4-firmware > 1.1.0.10

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc
ExclusiveOS: linux

%define debug_package %{nil}

%define drvbase /lib/modules/%{kversion}/extra
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%description
The Chelsio Terminator FCoE Partial Offload Driver for Linux kernel (%{kversion}).

%prep
%{__mkdir} -p %{name}-%{version}/chfcoe/
%{__cp} -a %{srcdir}/chfcoe/linux/chfcoe.ko %{name}-%{version}/chfcoe/
echo "%{drvbase}/chfcoe.ko" > %{rpmfiles}

%{__mkdir} -p %{name}-%{version}/etc/modprobe.d/
%{__cp} -a %{srcdir}/chfcoe/config/chfcoe.conf %{name}-%{version}/etc/modprobe.d/
echo "/etc/modprobe.d/chfcoe.conf" >> %{rpmfiles}

%{__mkdir} -p %{name}-%{version}/etc/chelsio-fcoe/
%{__cp} -a %{srcdir}/chfcoe/config/chfcoe_scst.conf %{name}-%{version}/etc/chelsio-fcoe
echo "/etc/chelsio-fcoe/chfcoe_scst.conf" >> %{rpmfiles}

#if [ ! -f /sbin/chinfotool ] ; then
#    %{__mkdir} -p %{name}-%{version}/sbin
#    if [ %{arch} == 'x86_64' ] ; then
#        %{__cp} -a %{srcdir}/chfcoe/tools/chinfotool64 %{name}-%{version}/sbin/chinfotool
#    else
#        %{__cp} -a %{srcdir}/chfcoe/tools/chinfotool32 %{name}-%{version}/sbin/chinfotool
#    fi
#    echo "/sbin/chinfotool" >> %{rpmfiles}
#fi

%{__mkdir} -p %{name}-%{version}/sbin
%{__cp} -a %{srcdir}/chfcoe/tools/chfcoe_perftune.sh %{name}-%{version}/sbin/chfcoe_perftune.sh
echo "/sbin/chfcoe_perftune.sh" >> %{rpmfiles}

%{__mkdir} -p %{name}-%{version}/etc/init.d
%{__cp} -a %{srcdir}/chfcoe/tools/chfcoe %{name}-%{version}/etc/init.d
echo "/etc/init.d/chfcoe" >> %{rpmfiles}

%build

%install
cd %{_topdir}/BUILD/%{name}-%{version}
%{__install} -D -v chfcoe/chfcoe.ko %{buildroot}/%{drvbase}/chfcoe.ko
%{__install} -D -v -m 644 etc/modprobe.d/chfcoe.conf %{buildroot}/etc/modprobe.d/chfcoe.conf
%{__install} -D -v -m 644 etc/chelsio-fcoe/chfcoe_scst.conf %{buildroot}/etc/chelsio-fcoe/chfcoe_scst.conf
#if [ ! -f /sbin/chinfotool ] ; then
#    %{__install} -D -v -m 755 sbin/chinfotool %{buildroot}/sbin/chinfotool
#fi
%{__install} -D -v -m 755 sbin/chfcoe_perftune.sh %{buildroot}/sbin/chfcoe_perftune.sh
%{__install} -D -v -m 755 etc/init.d/chfcoe %{buildroot}/etc/init.d/chfcoe

%post
chkconfig --add chfcoe
chkconfig chfcoe off
depmod

%postun
depmod 

%pre

%clean
rm -rf $RPM_BUILD_ROOT

%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt
%defattr(-,root,root,-)

%doc

%changelog
* Wed Apr 09 2014 Allwin Prabhu <rallwin@chelsio.com> - 
- Initial build.

