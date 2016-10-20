%{!?release:%define release 0}
%{!?kversion:%define kversion %(uname -r)}

Summary: Chelsio Terminator 4 virtual network driver for Linux
Name:    cxgb4i
Version: %{version}
Release: %{release}
License: GPL
Group:   System Environment/Kernel
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>
Provides: cxgb4i-%{version}
requires: cxgb4 > 1.1.0.10 ,chelsio-series4-firmware > 1.1.0.10

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}
#BuildRequires: kernel-devel
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc
ExclusiveOS: linux

%define drvbase /lib/modules/%{kversion}/updates/kernel
%define fwdir /lib/firmware
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt
%define sbin /sbin
%define etc /etc
%define usr /usr
%define mandir %{usr}/share/man/man8

%description
The Chelsio Terminator 4 Ethernet Adapter driver for Linux kernel (%{kversion}).

%prep
%{__mkdir} -p cxgb4i-%{version}/scsi/cxgbi
%{__cp} -a %{srcdir}/libcxgbi/libcxgbi.ko %{name}-%{version}/scsi/cxgbi
echo "%{drvbase}/drivers/scsi/cxgbi/libcxgbi.ko" > %{rpmfiles}
%{__cp} -a %{srcdir}/cxgb4i/cxgb4i.ko %{name}-%{version}/scsi/cxgbi
echo "%{drvbase}/drivers/scsi/cxgbi/cxgb4i.ko" > %{rpmfiles}

#oiscsi-utils
%{__mkdir} -p %{name}-%{version}%{sbin}
%{__mkdir} -p %{name}-%{version}%{mandir}
%{__mkdir} -p %{name}-%{version}%{etc}/iscsi/ifaces

%{__cp} -a %{osrcdir}%{usr}/iscsid %{name}-%{version}%{sbin}/iscsid2
echo "%{sbin}/iscsid2" >> %{rpmfiles}
%{__cp} -a %{osrcdir}%{usr}/iscsiadm %{name}-%{version}%{sbin}/iscsiadm2
echo "%{sbin}/iscsiadm2" >> %{rpmfiles}

%{__cp} -a %{osrcdir}/utils/iscsi_discovery %{name}-%{version}%{sbin}/iscsi_discovery2
echo "%{sbin}/iscsi_discovery2" >> %{rpmfiles}
%{__cp} -a %{osrcdir}/utils/iscsi-iname %{name}-%{version}%{sbin}/iscsi-iname2
echo "%{sbin}/iscsi-iname2" >> %{rpmfiles}
%{__cp} -a %{osrcdir}%{etc}/iface.example %{name}-%{version}%{etc}/iscsi/ifaces/
echo "%{etc}/iscsi/ifaces/chelsio_iface.example" >>  %{rpmfiles}

%{__cp} -a %{osrcdir}%{etc}/iscsid.conf %{name}-%{version}%{etc}/iscsi
echo "%{etc}/iscsi/iscsid.conf.2" >> %{rpmfiles}

#oiscsi
if ( echo "%{kversion}" | %{__grep} -i "2.6.18-164" ) || ( echo "%{kversion}" | %{__grep} -i "2.6.18-194" ) || ( echo "%{kversion}" | %{__grep} -i  "2.6.18-238" ) \
         || ( echo "%{kversion}" | %{__grep} -i   "2.6.18-128" ) || ( echo "%{kversion}" | %{__grep} -i  "2.6.18-274" ) ||\
	 ( echo "%{kversion}" | %{__grep} -i  "2.6.27.19" ) || ( echo "%{kversion}" | %{__grep} -i  "2.6.32.12" ); then
	%{__mkdir} -p %{name}-%{version}/scsi
	%{__cp} -a %{osrcdir}/kernel/scsi_transport_iscsi.ko %{name}-%{version}/scsi/
	echo "%{drvbase}/drivers/scsi/scsi_transport_iscsi.ko" >> %{rpmfiles}
	echo "%{drvbase}/drivers/scsi/scsi_transport_iscsi1.ko" >> %{rpmfiles}
	%{__cp} -a %{osrcdir}/kernel/libiscsi.ko %{name}-%{version}/scsi/
	echo "%{drvbase}/drivers/scsi/libiscsi.ko" >> %{rpmfiles}
	echo "%{drvbase}/drivers/scsi/libiscsi1.ko" >> %{rpmfiles}
	%{__cp} -a %{osrcdir}/kernel/libiscsi_tcp.ko %{name}-%{version}/scsi/
	echo "%{drvbase}/drivers/scsi/libiscsi_tcp.ko" >> %{rpmfiles}
	%{__cp} -a %{osrcdir}/kernel/iscsi_tcp.ko %{name}-%{version}/scsi/
	echo "%{drvbase}/drivers/scsi/iscsi_tcp.ko" >> %{rpmfiles}
	echo "%{drvbase}/drivers/scsi/iscsi_tcp1.ko" >> %{rpmfiles}
fi
%build

%pre
if [ -f /sbin/iscsiadm ]
then
        mv /sbin/iscsiadm /sbin/iscsiadm1
fi
if [ -f /sbin/iscsid ]
then
        mv /sbin/iscsid /sbin/iscsid1
fi
if [ -f /sbin/iscsi-iname ]
then
        mv /sbin/iscsi-iname /sbin/iscsi-iname1
fi
if [ -f /etc/iscsi/iscsid.conf ]
then
        mv /etc/iscsi/iscsid.conf /etc/iscsi/iscsid.conf.1
fi
if [ ! -e /sbin/iscsi_discovery ]
then
	rm -rf /sbin/iscsi_discovery
fi
if [ -f /sbin/iscsi_discovery ]
then
	mv /sbin/iscsi_discovery /sbin/iscsi_discovery1
	rm -rf /sbin/iscsi_discovery
fi

%post
if [ -f /sbin/iscsiadm2 ]
then
        ln -s /sbin/iscsiadm2 /sbin/iscsiadm
fi;

if [ -f /sbin/iscsid2 ]
then
        ln -s /sbin/iscsid2 /sbin/iscsid
fi

if [ -f /sbin/iscsi-iname2 ]
then
        ln -s /sbin/iscsi-iname2 /sbin/iscsi-iname
fi

if [ -f /etc/iscsi/iscsid.conf.2 ]
then
        ln -s /etc/iscsi/iscsid.conf.2 /etc/iscsi/iscsid.conf
fi

if [ -f /sbin/iscsi_discovery2 ]
then 
	ln -s /sbin/iscsi_discovery2 /sbin/iscsi_discovery
fi

if [ ! -f /etc/iscsi/initiatorname.iscsi ];
then
    echo "InitiatorName=`/sbin/iscsi-iname`" > /etc/iscsi/initiatorname.iscsi ;
fi
file=/etc/modprobe.d/libcxgb4.conf
lines=`grep -n "^install cxgb4 " $file 2>/dev/null | sed 's/:.*//g' | sort -gr`
string="# Disabled by Chelsio Makefile on `date`"
for i in $lines; do
  sed -i "$i"'s/^install cxgb4\s/#install cxgb4 /' $file
  let i-=1
  sed -i "$i"'a'"$string" $file
done
depmod 2>/dev/null
exit 0

%postun
if [ -f /sbin/iscsiadm1 ]
then
        mv /sbin/iscsiadm1 /sbin/iscsiadm
else
        rm -rf /sbin/iscsiadm
fi
if [ -f /sbin/iscsid1 ]
then
        mv /sbin/iscsid1 /sbin/iscsid
else
        rm -rf /sbin/iscsid
fi
if [ -f /sbin/iscsi-iname1 ]
then
        mv /sbin/iscsi-iname1 /sbin/iscsi-iname
else
        rm -rf /sbin/iscsi-iname
fi
if [ -f /etc/iscsi/iscsid.conf.1 ]
then
        mv /etc/iscsi/iscsid.conf.1 /etc/iscsi/iscsid.conf
fi
if [ -f /sbin/iscsi_discovery1 ]
then
	mv /sbin/iscsi_discovery1 /sbin/iscsi_discovery
fi
file=/etc/modprobe.d/libcxgb4.conf
string="# Disabled by Chelsio Makefile"
lines=`grep -n "^$string" $file 2>/dev/null | sed 's/:.*//g' | sort -gr`
for i in $lines; do
  sed -i "$i"'d' $file
  sed -i "$i"'s/^#//' $file
done
depmod 2>/dev/null
exit 0

%preun
if [ -f /etc/iscsi/iscsid.conf ]
then
        rm -rf /etc/iscsi/iscsid.conf
        cp -f /etc/iscsi/iscsid.conf.2 /etc/iscsi/iscsid.conf.rpmsave
fi

%install

cd %{_topdir}/BUILD/%{name}-%{version}
%{__install} -D -v scsi/cxgbi/libcxgbi.ko %{buildroot}%{drvbase}/drivers/scsi/cxgbi/libcxgbi.ko
%{__install} -D -v scsi/cxgbi/cxgb4i.ko %{buildroot}%{drvbase}/drivers/scsi/cxgbi/cxgb4i.ko
#oiscsi-utils
cd %{_topdir}/BUILD/%{name}-%{version}%{sbin}
%{__install} -D -v iscsid2 %{buildroot}%{sbin}/iscsid2
%{__install} -D -v iscsiadm2 %{buildroot}%{sbin}/iscsiadm2
%{__install} -D -v iscsi_discovery2 %{buildroot}%{sbin}/iscsi_discovery2
%{__install} -D -v iscsi-iname2 %{buildroot}%{sbin}/iscsi-iname2

cd %{_topdir}/BUILD/%{name}-%{version}%{etc}/iscsi
%{__install} -D -v iscsid.conf %{buildroot}%{etc}/iscsi/iscsid.conf.2

cd %{_topdir}/BUILD/%{name}-%{version}%{etc}/iscsi/ifaces
%{__install} -D -v iface.example %{buildroot}%{etc}/iscsi/ifaces/chelsio_iface.example
#oiscsi-kernel
cd %{_topdir}/BUILD/%{name}-%{version}
if ( echo "%{kversion}" | %{__grep} -i "2.6.18-164" ) || ( echo "%{kversion}" | %{__grep} -i "2.6.18-194" ) || ( echo "%{kversion}" | %{__grep} -i  "2.6.18-238" ) \
         || ( echo "%{kversion}" | %{__grep} -i   "2.6.18-128" ) || ( echo "%{kversion}" | %{__grep} -i  "2.6.18-274" ) ||\
	 (echo "%{kversion}" | %{__grep} -i  "2.6.27.19" ) || ( echo "%{kversion}" | %{__grep} -i  "2.6.32.12" ); then
	cd %{_topdir}/BUILD/%{name}-%{version}/scsi
	%{__install} -D -v scsi_transport_iscsi.ko %{buildroot}%{drvbase}/drivers/scsi/scsi_transport_iscsi.ko
	%{__install} -D -v scsi_transport_iscsi.ko %{buildroot}%{drvbase}/drivers/scsi/scsi_transport_iscsi1.ko
	%{__install} -D -v libiscsi.ko %{buildroot}%{drvbase}/drivers/scsi/libiscsi.ko
	%{__install} -D -v libiscsi.ko %{buildroot}%{drvbase}/drivers/scsi/libiscsi1.ko
	%{__install} -D -v libiscsi_tcp.ko %{buildroot}%{drvbase}/drivers/scsi/libiscsi_tcp.ko
	%{__install} -D -v iscsi_tcp.ko %{buildroot}%{drvbase}/drivers/scsi/iscsi_tcp.ko
	%{__install} -D -v iscsi_tcp.ko %{buildroot}%{drvbase}/drivers/scsi/iscsi_tcp1.ko
fi

%debug_package

%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt
%{drvbase}/drivers/scsi/cxgbi/libcxgbi.ko
#%{drvbase}/drivers/scsi/cxgbi/cxgb4i.ko
%defattr(744,root,root)

%clean
%{__rm} -rf %{buildroot}

%changelog
