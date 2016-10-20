Summary: Chelsio T4 Open Fabrics Userspace Library
Name: %{name}
Version: %{version}
Release: %{release}
License: Freeware
Group: System Environment/Libraries
URL: www.chelsio.com
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
requires: chiwarp > 1.1.0.10 ,libcxgb4 > 1.1.0.10
%define debug_package %{nil}
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%define lib /usr/lib64

%description
libcxgb4_udp provides a device-specific userspace library for Chelsio T4
driver for use with the libibverbs library.

%prep

%{__mkdir} -p %{name}-%{version}%{lib}

find %{srcdir}/libcxgb4_udp_debug/ -name libcxgb4_udp_debug\* -type f -exec cp {} %{name}-%{version}%{lib} \;;
find %{name}-%{version}%{lib} -name *.lai -type f -exec rm {} \;
for file in $(/bin/ls  %{_topdir}/BUILD/%{name}-%{version}%{lib} 2>/dev/null); do
	echo "%{lib}/$(basename $file)" >> %{rpmfiles}
done

%preun
if [ -f %{lib}/libcxgb4_udp_debug.so ]; then
    unlink %{lib}/libcxgb4_udp_debug.so;
fi
if [ -f %{lib}/libcxgb4_udp_debug.so.1 ]; then
    unlink %{lib}/libcxgb4_udp_debug.so.1;
fi

%post
ln -f -s %{lib}/libcxgb4_udp_debug.so.1.0.0 %{lib}/libcxgb4_udp_debug.so
ln -f -s %{lib}/libcxgb4_udp_debug.so.1.0.0 %{lib}/libcxgb4_udp_debug.so.1

%install
cd %{_topdir}/BUILD/%{name}-%{version}%{lib}
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}%{lib} 2>/dev/null); do
	%{__install} -D -v $file %{buildroot}%{lib}/$(basename $file)
done

/sbin/ldconfig

%clean
rm -rf %{RPM_BUILD_ROOT}

%files
/usr/lib64/libcxgb4_udp_debug.so.1.0.0
/usr/lib64/libcxgb4_udp_debug.a
/usr/lib64/libcxgb4_udp_debug.la

%changelog
* Sun Jun 12 2011 root <root@speedy1.blr.asicdesigners.com> - 
- Initial build.

