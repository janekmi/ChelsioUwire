%{!?PERL:%define PERL %(which perl)}
Summary: Chelsio Terminator 4 Storage Adapter driver for Linux
Name: csiostor-target
Version: %{version}
Release: %{release}
License: GPL
Group:   System Environment/Kernel
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc
ExclusiveOS: linux
Provides: csiostor-target-%{version} perl(SCST::SCST) >= 0.9.0
requires: chelsio-series4-firmware > 1.1.0.10
Conflicts: csiostor

%define drvbase /lib/modules/%{kversion}/updates/kernel
%define drvbaseSt /lib/modules/%{kversion}/extra
%define lib lib/udev
%define librules lib/udev/rules.d
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt
%define incfiles /usr/local/include
%define SITEARCHEXP %(%{PERL} '-V:installsitearch' |awk -F"='" '{print $2}'|awk -F"';" '{print $1}')
%define INSTALLSITEARCH %(%{PERL} '-V:installsitearch' |awk -F"='" '{print $2}'|awk -F"';" '{print $1}')
%define INSTALLSITELIB  %(%{PERL} '-V:installsitelib' |awk -F"='" '{print $2}'|awk -F"';" '{print $1}')
%define INSTALLSITEBIN  %(%{PERL} '-V:installsitebin' |awk -F"='" '{print $2}'|awk -F"';" '{print $1}')
%define INSTALLSITESCRIPT %(%{PERL} '-V:installsitescript' |awk -F"='" '{print $2}'|awk -F"';" '{print $1}')
%define INSTALLSITEMAN1  %(%{PERL} '-V:installsiteman1dir' |awk -F"='" '{print $2}'|awk -F"';" '{print $1}')
%define INSTALLSITEMAN3 %(%{PERL} '-V:installsiteman3dir' |awk -F"='" '{print $2}'|awk -F"';" '{print $1}')
%define INSTALLARCHLIB  %(%{PERL} '-V:installarchlib' |awk -F"='" '{print $2}'|awk -F"';" '{print $1}')
%define rpm_ver %(rpm -qf /etc/issue)
%define rpm_ver_rel %(rpm -q --queryformat "[%{VERSION}]" %{rpm_ver})

%description
The Chelsio Terminator 4 Storage Adapter driver for Linux kernel (%{kversion}).


%clean
rm -rf $RPM_BUILD_ROOT

%prep

%{__mkdir} -p %{name}-%{version}/csiostor/
%{__mkdir} -p %{name}-%{version}/csioscst/
%{__cp} -a %{srcdir}/csiostor/csiostor.ko %{name}-%{version}/csiostor/
echo "%{drvbase}/drivers/scsi/csiostor/csiostor.ko" > %{rpmfiles}
%{__cp} -a %{srcdir}/csioscst/csioscst.ko %{name}-%{version}/csioscst/
echo "%{drvbase}/drivers/scsi/csioscst/csioscst.ko" >> %{rpmfiles}

#SCST Kernel Modules
%{__mkdir} -p %{name}-%{version}/scst/kernel
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/src/scst.ko %{name}-%{version}/scst/kernel
echo "%{drvbaseSt}/scst.ko" >> %{rpmfiles}
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/src/dev_handlers/scst_cdrom.ko %{name}-%{version}/scst/kernel
echo "%{drvbaseSt}/dev_handlers/scst_cdrom.ko" >> %{rpmfiles}
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/src/dev_handlers/scst_changer.ko %{name}-%{version}/scst/kernel
echo "%{drvbaseSt}/dev_handlers/scst_changer.ko" >> %{rpmfiles}
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/src/dev_handlers/scst_disk.ko %{name}-%{version}/scst/kernel
echo "%{drvbaseSt}/dev_handlers/scst_disk.ko" >> %{rpmfiles}
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/src/dev_handlers/scst_modisk.ko %{name}-%{version}/scst/kernel
echo "%{drvbaseSt}/dev_handlers/scst_modisk.ko" >> %{rpmfiles}
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/src/dev_handlers/scst_processor.ko %{name}-%{version}/scst/kernel
echo "%{drvbaseSt}/dev_handlers/scst_processor.ko" >> %{rpmfiles}
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/src/dev_handlers/scst_raid.ko %{name}-%{version}/scst/kernel
echo "%{drvbaseSt}/dev_handlers/scst_raid.ko" >> %{rpmfiles} 
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/src/dev_handlers/scst_tape.ko %{name}-%{version}/scst/kernel
echo "%{drvbaseSt}/dev_handlers/scst_tape.ko" >> %{rpmfiles} 
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/src/dev_handlers/scst_user.ko %{name}-%{version}/scst/kernel
echo "%{drvbaseSt}/dev_handlers/scst_user.ko" >> %{rpmfiles} 
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/src/dev_handlers/scst_vdisk.ko %{name}-%{version}/scst/kernel
echo "%{drvbaseSt}/dev_handlers/scst_vdisk.ko" >> %{rpmfiles} 

#SCST Include files
%{__mkdir} -p %{name}-%{version}/scst/include
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/include/scst.h  %{name}-%{version}/scst/include
echo "%{incfiles}/scst/scst.h" >> %{rpmfiles}
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/include/scst_sgv.h  %{name}-%{version}/scst/include
echo "%{incfiles}/scst/scst_sgv.h" >> %{rpmfiles}
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/include/scst_debug.h  %{name}-%{version}/scst/include
echo "%{incfiles}/scst/scst_debug.h" >> %{rpmfiles}
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/include/scst_user.h  %{name}-%{version}/scst/include
echo "%{incfiles}/scst/scst_user.h" >> %{rpmfiles}
%{__cp} -a %{srcdirSt}/scst-2.0.0.1/include/scst_const.h %{name}-%{version}/scst/include
echo "%{incfiles}/scst/scst_const.h " >> %{rpmfiles}

#SCST User App (scstadmin)
%{__mkdir} -p %{name}-%{version}/scst/user
%{__cp} -a %{srcdirSt}/scstadmin-2.0.0/scstadmin/scstadmin %{name}-%{version}/scst/user
echo "/usr/local/sbin/scstadmin" >> %{rpmfiles}
%{__mkdir} -p %{name}-%{version}/scst/user/init.d
%{__cp} -a %{srcdirSt}/scstadmin-2.0.0/init.d/scst %{name}-%{version}/scst/user/init.d
echo "/etc/init.d/scst" >> %{rpmfiles}
%{__cp} -a %{srcdirSt}/scstadmin-2.0.0/init.d/qla2x00t %{name}-%{version}/scst/user/init.d
echo "/etc/init.d/qla2x00t" >> %{rpmfiles}
%{__mkdir} -p %{name}-%{version}/scst/user/blib/
%{__cp} -a -r  %{srcdirSt}/scstadmin-2.0.0/scstadmin/scst-0.9.00/blib/* %{name}-%{version}/scst/user/blib/
if [ %{rpm_ver_rel} == "11.1" ]; then 
    echo "/usr/lib/perl5/site_perl/5.10.0/SCST/SCST.pm" >> %{rpmfiles}
    echo "/usr/lib/perl5/site_perl/5.10.0/x86_64-linux-thread-multi/auto/SCST-SCST/.packlist" >> %{rpmfiles}
    echo "/usr/share/man/man3/SCST::SCST.3pm.gz" >> %{rpmfiles}
else 
    echo "/usr/local/share/perl5/SCST/SCST.pm" >> %{rpmfiles}
    echo "/usr/local/share/man/man3/SCST::SCST.3pm" >> %{rpmfiles}
    echo "/usr/local/lib64/perl5/auto/SCST-SCST/.packlist" >> %{rpmfiles}
fi 
%build


%install
cd %{_topdir}/BUILD/%{name}-%{version}/scst/user
%{PERL} -MExtUtils::Install -e 'install({@ARGV}, '\''0'\'', 0, '\''0'\'');' -- read %{buildroot}%{SITEARCHEXP}/auto/SCST-SCST/.packlist \
        write %{buildroot}%{INSTALLSITEARCH}/auto/SCST-SCST/.packlist \
        blib/lib %{buildroot}%{INSTALLSITELIB}\
        blib/arch %{buildroot}%{INSTALLSITEARCH} \
        blib/bin %{buildroot}%{INSTALLSITEBIN} \
        blib/script %{buildroot}%{INSTALLSITESCRIPT} \
        blib/man1  %{buildroot}%{INSTALLSITEMAN1} \
        blib/man3 %{buildroot}%{INSTALLSITEMAN3}  > /dev/null

#Chelsio Fcoe Target Kernel Modules
cd %{_topdir}/BUILD/%{name}-%{version}
%{__install} -D -v csiostor/csiostor.ko %{buildroot}/%{drvbase}/drivers/scsi/csiostor/csiostor.ko
%{__install} -D -v csioscst/csioscst.ko %{buildroot}/%{drvbase}/drivers/scsi/csioscst/csioscst.ko

#SCST kernel modules
cd %{_topdir}/BUILD/%{name}-%{version}/scst/kernel
%{__install} -D -v scst.ko  %{buildroot}/%{drvbaseSt}/scst.ko
%{__install} -D -v scst_cdrom.ko  %{buildroot}/%{drvbaseSt}/dev_handlers/scst_cdrom.ko
%{__install} -D -v scst_changer.ko  %{buildroot}/%{drvbaseSt}/dev_handlers/scst_changer.ko
%{__install} -D -v scst_disk.ko  %{buildroot}/%{drvbaseSt}/dev_handlers/scst_disk.ko
%{__install} -D -v scst_modisk.ko  %{buildroot}/%{drvbaseSt}/dev_handlers/scst_modisk.ko
%{__install} -D -v scst_processor.ko  %{buildroot}/%{drvbaseSt}/dev_handlers/scst_processor.ko
%{__install} -D -v scst_raid.ko  %{buildroot}/%{drvbaseSt}/dev_handlers/scst_raid.ko
%{__install} -D -v scst_tape.ko  %{buildroot}/%{drvbaseSt}/dev_handlers/scst_tape.ko
%{__install} -D -v scst_user.ko  %{buildroot}/%{drvbaseSt}/dev_handlers/scst_user.ko
%{__install} -D -v scst_vdisk.ko  %{buildroot}/%{drvbaseSt}/dev_handlers/scst_vdisk.ko
                                                      
#SCST include files 
cd %{_topdir}/BUILD/%{name}-%{version}/scst/include
for incfile in scst_const.h scst_debug.h scst.h scst_sgv.h scst_user.h ; do 
    %{__install} -m 644 -D -v $incfile %{buildroot}/%{incfiles}/scst/$incfile
done

#SCST User Utils
cd %{_topdir}/BUILD/%{name}-%{version}/scst/user
%{__install} -D -v scstadmin  %{buildroot}/usr/local/sbin/scstadmin
%{__install} -m 755 -D -v init.d/scst %{buildroot}/etc/init.d/scst
%{__install} -m 755 -D -v init.d/qla2x00t %{buildroot}/etc/init.d/qla2x00t


%post
/usr/lib/lsb/install_initd scst
/usr/lib/lsb/install_initd qla2x00t
depmod

%postun
depmod 



%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt
%defattr(-,root,root,-)

%doc

%changelog
* Fri Aug 26 2011 root <root@plethora.asicdesigners.com> - 
- Initial build.

