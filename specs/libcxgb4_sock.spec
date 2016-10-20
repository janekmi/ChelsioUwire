Summary: Chelsio T4 Open Fabrics Userspace Library
Name: %{name}
Version: %{version}
Release: %{release}
License: Freeware
Group: System Environment/Libraries
URL: www.chelsio.com
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
requires: chiwarp > 1.1.0.10 ,libcxgb4 > 1.1.0.10
%define debug_package %{nil}
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%define lib /usr/lib64
%define bin /usr/bin

%description
libcxgb4_sock provides a device-specific userspace library for Chelsio T4
driver for use with the libibverbs library.

%prep
%{__mkdir} -p %{name}-%{version}%{lib}
%{__mkdir} -p %{name}-%{version}%{bin}

#%{__cp} -a %{srcdir}/libcxgb4_sock/examples/udp_echo %{name}-%{version}%{bin}
#echo "%{bin}/udp_echo" > %{rpmfiles}
find %{srcdir}/libcxgb4_sock/ -name libcxgb4_sock\* -type f -exec cp {} %{name}-%{version}%{lib} \;
find %{name}-%{version}%{lib} -name *.lai -type f -exec rm {} \;
find %{name}-%{version}%{lib} -name *.spec* -type f -exec rm {} \;
find %{name}-%{version}%{lib} -name libcxgb4_sock.h -type f -exec rm {} \;
for file in $(/bin/ls  %{_topdir}/BUILD/%{name}-%{version}%{lib} 2>/dev/null); do
	echo "%{lib}/$(basename $file)" >> %{rpmfiles}
done

%preun
if [ -f %{lib}/libcxgb4_sock.so ]; then
    unlink %{lib}/libcxgb4_sock.so;
fi
if [ -f %{lib}/libcxgb4_sock.so.1 ]; then
    unlink %{lib}/libcxgb4_sock.so.1
fi

%post
ln -f -s %{lib}/libcxgb4_sock.so.1.0.0 %{lib}/libcxgb4_sock.so
ln -f -s %{lib}/libcxgb4_sock.so.1.0.0 %{lib}/libcxgb4_sock.so.1

%install
cd %{_topdir}/BUILD/%{name}-%{version}%{bin}
#%{__install} -D -v -m 755 udp_echo %{buildroot}%{bin}/udp_echo

cd %{_topdir}/BUILD/%{name}-%{version}%{lib}
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}%{lib} 2>/dev/null); do
	%{__install} -D -v $file %{buildroot}%{lib}/$(basename $file)
done
/sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
#/usr/bin/udp_echo
/usr/lib64/libcxgb4_sock.so.1.0.0
/usr/lib64/libcxgb4_sock.la

%changelog
* Sun Jun 12 2011 root <root@speedy1.blr.asicdesigners.com> - 
- Initial build.

