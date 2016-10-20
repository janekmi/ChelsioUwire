Summary: Chelsio T4 WD TOE Debug Library
Name: %{name}
Version: %{version}
Release: %{release}
License: Freeware
Group: System Environment/Libraries
URL: www.chelsio.com
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
%define debug_package %{nil}
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%define lib /usr/lib64
%define etc /etc

%description
libwdtoe debug provides a device-specific userspace debug library for Chelsio T4
driver for use with the WD-TOE drivers.

%prep

%{__mkdir} -p %{name}-%{version}%{lib}
%{__mkdir} -p %{name}-%{version}%{etc}

%{__cp} -a %{srcdir}/libwdtoe_dbg/examples/wdtoe.conf %{name}-%{version}%{etc}
echo "%{etc}/wdtoe.conf" > %{rpmfiles}

find %{srcdir}/libwdtoe_dbg/ -name libwdtoe_debug\* -type f -exec cp {} %{name}-%{version}%{lib} \;;
find %{name}-%{version}%{lib} -name *.lai -type f -exec rm {} \;
for file in $(/bin/ls  %{_topdir}/BUILD/%{name}-%{version}%{lib} 2>/dev/null); do
	echo "%{lib}/$(basename $file)" >> %{rpmfiles}
done

%preun
if [ -f  %{lib}/libwdtoe_debug.so ]; then 
    unlink %{lib}/libwdtoe_debug.so;
fi
if [ -f %{lib}/libwdtoe_debug.so.1 ]; then
    unlink %{lib}/libwdtoe_debug.so.1;
fi

%post
ln -f -s %{lib}/libwdtoe_debug.so.1.0.0 %{lib}/libwdtoe_debug.so
ln -f -s %{lib}/libwdtoe_debug.so.1.0.0 %{lib}/libwdtoe_debug.so.1

%install
cd %{_topdir}/BUILD/%{name}-%{version}%{etc}
%{__install} -D -v -m 755 wdtoe.conf %{buildroot}%{etc}/wdtoe.conf

cd %{_topdir}/BUILD/%{name}-%{version}%{lib}
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}%{lib} 2>/dev/null); do
	%{__install} -D -v $file %{buildroot}%{lib}/$(basename $file)
done

/sbin/ldconfig

%clean
rm -rf %{RPM_BUILD_ROOT}

%files
/etc/wdtoe.conf
/usr/lib64/libwdtoe_debug.so.1.0.0
/usr/lib64/libwdtoe_debug.la

%changelog
* Sun Jun 12 2011 root <root@speedy1.blr.asicdesigners.com> - 
- Initial build.

