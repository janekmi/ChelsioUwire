Summary: Chelsio Terminator 4 Storage Adapter driver for Linux
Name: %{name}
Version: %{version}
Release: %{release}
License: GPL
Group:   System Environment/Kernel
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>
Provides: csiostor-%{version}
requires: chelsio-series4-firmware > 1.1.0.10

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc
ExclusiveOS: linux

%define drvbase /lib/modules/%{kversion}/updates
%define lib lib/udev
%define librules lib/udev/rules.d
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%description
The Chelsio Terminator 4 Storage Adapter driver for Linux kernel (%{kversion}).

%prep
%{__mkdir} -p %{name}-%{version}/csiostor/
%{__cp} -a %{srcdir}/csiostor/csiostor.ko %{name}-%{version}/csiostor/
echo "%{drvbase}/drivers/scsi/csiostor/csiostor.ko" > %{rpmfiles}

%{__mkdir} -p %{name}-%{version}/%{librules}
%{__cp} -a %{srcdir}/csiostor/udev/path_chelsio_id  %{name}-%{version}/%{lib}/
echo "/%{lib}/path_chelsio_id" >> %{rpmfiles}

%{__cp} -a %{srcdir}/csiostor/udev/30-chelsio-storage.rules  %{name}-%{version}/%{librules}/
echo "/%{librules}/30-chelsio-storage.rules" >> %{rpmfiles}

%{__mkdir} -p %{name}-%{version}/etc/modprobe.d/
%{__cp} -a %{srcdir}/csiostor/csiostor.conf %{name}-%{version}/etc/modprobe.d/
echo "/etc/modprobe.d/csiostor.conf" >> %{rpmfiles}


%build

%install
cd %{_topdir}/BUILD/%{name}-%{version}
%{__install} -D -v csiostor/csiostor.ko %{buildroot}/%{drvbase}/drivers/scsi/csiostor/csiostor.ko
%{__install} -D -v lib/udev/path_chelsio_id %{buildroot}/%{lib}/path_chelsio_id
%{__install} -D -v -m 644 lib/udev/rules.d/30-chelsio-storage.rules %{buildroot}/%{librules}/30-chelsio-storage.rules
%{__install} -D -v -m 644 etc/modprobe.d/csiostor.conf %{buildroot}/etc/modprobe.d/csiostor.conf

%post
depmod

%postun
depmod 

%pre
%{__mkdir} -p %{libriles}

%clean
rm -rf $RPM_BUILD_ROOT

%debug_package

%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt
%defattr(-,root,root,-)

%doc

%changelog
* Fri Aug 26 2011 root <root@plethora.asicdesigners.com> - 
- Initial build.

