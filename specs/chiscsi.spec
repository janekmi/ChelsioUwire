%{!?release:%define release 0}
%{!?kversion:%define kversion %(uname -r)}
%{!?arch:%define arch %(uname -p)}

## Summary offload string define.
Summary: Chelsio Terminator 4 iscsi-target driver for Linux
Name:    %{name}
Version: %{version}
Release: %{release}
License: GPL
Group:   System Environment/Kernel
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>
Provides: %{name}-%{version}
requires: cxgb4toe > 1.1.0.10, chelsio-series4-firmware > 1.1.0.10

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}-root
#BuildRequires: kernel-devel
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc
ExclusiveOS: linux

%define drvbase /lib/modules/%{kversion}/updates/kernel
%define mandir /usr/share/man/man8
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%define debug_package %{nil}

%description
The Chelsio Terminator 4 iscsi-target driver and utils for Linux kernel (%{kversion}).

%prep
## chiscsi driver
%{__mkdir} -p %{name}-%{version}/chiscsi/
%{__cp} -a %{srcdir}/base/chiscsi_base.ko %{name}-%{version}/chiscsi/
%{__cp} -a %{srcdir}/t4/chiscsi_t4.ko %{name}-%{version}/chiscsi/
echo "%{drvbase}/drivers/scsi/chiscsi/chiscsi_t4.ko" > %{rpmfiles}
echo "%{drvbase}/drivers/scsi/chiscsi/chiscsi_base.ko" >> %{rpmfiles}

if [  -f  %{srcdir}/t3/chiscsi_t3.ko ]; then
	%{__cp} -a %{srcdir}/t3/chiscsi_t3.ko %{name}-%{version}/chiscsi/
	echo "%{drvbase}/drivers/scsi/chiscsi/chiscsi_t3.ko" >> %{rpmfiles}
fi

#chiscsi utils
%{__mkdir} -p %{name}-%{version}/sbin
%{__mkdir} -p %{name}-%{version}/etc/bash_completion.d
%{__mkdir} -p %{name}-%{version}/etc/chelsio-iscsi
%{__mkdir} -p %{name}-%{version}/etc/init.d
%{__mkdir} -p %{name}-%{version}/etc/sysconfig
%{__mkdir} -p %{name}-%{version}%{mandir}

#iscsictl
%{__cp} -a %{srcdir}/user/iscsictl %{name}-%{version}/sbin/
echo "/sbin/iscsictl" >> %{rpmfiles}
%{__cp} -a %{srcdir}/user/chisns %{name}-%{version}/sbin/
echo "/sbin/chisns" >> %{rpmfiles}
%{__cp} -a %{srcdir}/user/bash/iscsictl %{name}-%{version}/etc/bash_completion.d/
echo "/etc/bash_completion.d/iscsictl" >> %{rpmfiles}
%{__cp} -a %{srcdir}/user/bash/chisns %{name}-%{version}/etc/bash_completion.d/
echo "/etc/bash_completion.d/chisns" >> %{rpmfiles}
%{__cp} -a %{srcdir}/tools/chiscsi_set_affinity.sh %{name}-%{version}/sbin/
echo "/sbin/chiscsi_set_affinity.sh" >> %{rpmfiles}

#docs
%{__cp} -a %{srcdir}/docs/iscsictl.8.gz %{name}-%{version}%{mandir}
echo "%{mandir}/iscsictl.8.gz" >> %{rpmfiles}

# chiscsi service
%{__cp} -a %{srcdir}/example/chiscsi.conf %{name}-%{version}/etc/chelsio-iscsi
echo "/etc/chelsio-iscsi/chiscsi.conf" >> %{rpmfiles}
%{__cp} -a %{srcdir}/example/chiscsi.conf %{name}-%{version}/etc/sysconfig
echo "/etc/sysconfig/chiscsi.conf" >> %{rpmfiles}

%{__cp} -a %{srcdir}/example/initd/chiscsi %{name}-%{version}/etc/sysconfig
echo "/etc/sysconfig/chiscsi" >> %{rpmfiles}

if [  -f /etc/redhat-release ] ; then
        %{__cp} -a %{srcdir}/example/initd/chelsio-target.redhat %{name}-%{version}/etc/init.d/chelsio-target
        echo "/etc/init.d/chelsio-target" >> %{rpmfiles}
elif [ -f /etc/SuSE-release ] ; then
        %{__cp} -a %{srcdir}/example/initd/chelsio-target.suse %{name}-%{version}/etc/init.d/chelsio-target
        echo "/etc/init.d/chelsio-target" >> %{rpmfiles}
fi;

#if [ -f %{srcdir}/user/chinfotool64 ] || [ -f %{srcdir}/user/chinfotool32 ] ; then \
#if [ %{arch} == 'x86_64' ] ; then
#        %{__cp} -a %{srcdir}/user/chinfotool64 %{name}-%{version}/sbin/
#        echo "/sbin/chinfotool64" >> %{rpmfiles}
#       echo "/sbin/chinfotool" >> %{rpmfiles}
#else
#        %{__cp} -a %{srcdir}/user/chinfotool32 %{name}-%{version}/sbin/
#        echo "/sbin/chinfotool32" >> %{rpmfiles}
#       echo "/sbin/chinfotool" >> %{rpmfiles}
#fi;
#echo "/sbin/chinfotool" >> %{rpmfiles}
#fi;

%build
## Nothing to do here.

%pre
if [ ! -f /etc/chelsio-iscsi ] ; then
        %{__mkdir} -p /etc/chelsio-iscsi
fi ;

%post
rm -f /etc/chelsio-iscsi/iscsictl.pid
%{__mkdir} -p /etc/chelsio-iscsi/discovery
%{__mkdir} -p /etc/chelsio-iscsi/prdb
%{__mkdir} -p /etc/chelsio-iscsi/log
chkconfig --add chelsio-target

#if [ -f /sbin/chinfotool64 ] || [ -f /sbin/chinfotool32 ] ; then \
#if [ %{arch} == 'x86_64' ]
#then
#        %{__mv} /sbin/chinfotool64 /sbin/chinfotool
#else
#        %{__mv} /sbin/chinfotool32 /sbin/chinfotool
#fi;
#fi ;
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

%preun
%{__rm} -f /sbin/chinfotool
if [ -f /etc/chelsio-iscsi/chiscsi.conf ] ; then
        %{__cp} -f /etc/chelsio-iscsi/chiscsi.conf /etc/chelsio-iscsi/chiscsi.conf.rpmsave
        echo "chiscsi.conf saved to chiscsi.conf.rpmsave"
fi

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
%{__install} -D -v chiscsi/chiscsi_base.ko %{buildroot}%{drvbase}/drivers/scsi/chiscsi/chiscsi_base.ko
%{__install} -D -v chiscsi/chiscsi_t4.ko %{buildroot}%{drvbase}/drivers/scsi/chiscsi/chiscsi_t4.ko
if [ -f  chiscsi/chiscsi_t3.ko ]; then
	%{__install} -D -v chiscsi/chiscsi_t3.ko %{buildroot}%{drvbase}/drivers/scsi/chiscsi/chiscsi_t3.ko
fi
#chiscsi utils 
%{__install} -D -v -m 755 sbin/iscsictl  %{buildroot}/sbin/iscsictl
%{__install} -D -v -m 755 sbin/chisns  %{buildroot}/sbin/chisns
%{__install} -D -v -m 755 sbin/chiscsi_set_affinity.sh %{buildroot}/sbin/chiscsi_set_affinity.sh

#if [ -f sbin/chinfotool64 ] || [ -f sbin/chinfotool32 ] ; then \
#if [ %{arch} == 'x86_64' ]
#then
#        %{__install} -D -v -m 755 sbin/chinfotool64 %{buildroot}/sbin/chinfotool64
#else
#        %{__install} -D -v -m 755 sbin/chinfotool32 %{buildroot}/sbin/chinfotool32
#fi;
#fi;

cd %{_topdir}/BUILD/%{name}-%{version}/etc/bash_completion.d
%{__install} -D -v -m 644 iscsictl  %{buildroot}/etc/bash_completion.d/iscsictl
%{__install} -D -v -m 644 chisns  %{buildroot}/etc/bash_completion.d/chisns

cd %{_topdir}/BUILD/%{name}-%{version}%{mandir}
%{__install} -D -v -m 644 iscsictl.8.gz %{buildroot}%{mandir}/iscsictl.8.gz

cd %{_topdir}/BUILD/%{name}-%{version}/etc/chelsio-iscsi
%{__install} -D -v -m 644 chiscsi.conf %{buildroot}/etc/chelsio-iscsi/chiscsi.conf

cd %{_topdir}/BUILD/%{name}-%{version}/etc/sysconfig
%{__install} -D -v -m 644 chiscsi.conf %{buildroot}/etc/sysconfig/chiscsi.conf
%{__install} -D -v -m 644 chiscsi %{buildroot}/etc/sysconfig/chiscsi

cd %{_topdir}/BUILD/%{name}-%{version}/etc/init.d
%{__install} -D -v -m 755 chelsio-target %{buildroot}/etc/init.d/chelsio-target

%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt
%defattr(744,root,root)

%clean
%{__rm} -rf %{buildroot}

%changelog
