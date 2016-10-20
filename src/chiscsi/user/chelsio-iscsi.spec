
Summary: Chelsio iSCSI kernel modules & administration utilities
Name: chelsio-iscsi
Version: 5.0.106
Release: 0.2%{?dist}
Source0: chiscsi.5.0-0106.tar.gz

Group: System Environment
License: GPL
URL: http://www.chelsio.com
Buildroot: %{_tmppath}/%{name}-root
Prereq: /sbin/chkconfig
ExclusiveArch: i686 x86_64
Vendor: Chelsio Communications, Inc.
Packager: Anish Bhatt <anish@chelsio.com>

%{!?kernel:     %define kernel %(uname -r)}

%description
Chelsio iSCSI kernel module, target & initiator administration utility and iSNS server

%prep
%setup -q -n chiscsi.5.0-0106

%build
make 
cd ..

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/sbin
mkdir -p $RPM_BUILD_ROOT/etc/bash_completion.d
mkdir -p $RPM_BUILD_ROOT/etc/chelsio-iscsi
mkdir -p $RPM_BUILD_ROOT/etc/chelsio-iscsi/discovery
mkdir -p $RPM_BUILD_ROOT/etc/chelsio-iscsi/prdb
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{kernel}/kernel/drivers/iscsi
mkdir -p ${RPM_BUILD_ROOT}%{_mandir}/man8
mkdir -p $RPM_BUILD_ROOT/etc/init.d
mkdir -p $RPM_BUILD_ROOT/etc/sysconfig

install -m 755 user/iscsictl user/chisns user/ibft/chibft example/boot/chiscsi_boot $RPM_BUILD_ROOT/sbin
install -m 644 example/initd/chiscsi $RPM_BUILD_ROOT/etc/sysconfig
install -m 644 user/bash/iscsictl user/bash/chisns $RPM_BUILD_ROOT/etc/bash_completion.d
install -m 644 docs/iscsictl.8.gz $RPM_BUILD_ROOT/%{_mandir}/man8
install -m 755 example/initd/chelsio-target.redhat $RPM_BUILD_ROOT/etc/init.d/chelsio-target
install -vD -m 755 example/initd/chelsio-initiator.redhat /etc/init.d/chelsio-initiator
install -m 644 example/chiscsi.conf $RPM_BUILD_ROOT/etc/chelsio-iscsi

make install-mod INSTPATH=$RPM_BUILD_ROOT/lib/modules/%{kernel}/kernel/drivers/iscsi

%clean
rm -rf $RPM_BUILD_ROOT

%pre
rm -rf /lib/modules/%{kernel}/kernel/drivers/iscsi
rm -f /sbin/iscsictl
rm -f /sbin/chisns
rm -f /etc/bash_completion.d/iscsictl
rm -f /etc/bash_completion.d/chisns

%post
/sbin/depmod -a
/sbin/chkconfig --add chelsio-target
/sbin/chkconfig --add chelsio-initiator

%postun
/sbin/depmod -a


%preun
if [ "$1" = "0" ]; then
    /sbin/chkconfig --del chelsio-target
    /sbin/chkconfig --del chelsio-initiator
fi

%files
%defattr(-,root,root)
%doc README
/lib/modules/%{kernel}/kernel/drivers/iscsi
/etc/chelsio-iscsi
/etc/init.d
/etc/bash_completion.d
%attr(0600,root,root) %config(noreplace) /etc/sysconfig
%attr(0600,root,root) %config(noreplace) /etc/chelsio-iscsi/chiscsi.conf
/sbin/*
%{_mandir}/*/*

%changelog
* Wed Jun 30 2010 Anish Bhatt <anish@chelsio.com>
- Add man page to rpm

* Mon Jun 28 2010 Anish Bhatt <anish@chelsio.com>
- initial packaging

