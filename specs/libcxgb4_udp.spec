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
%define bin /usr/bin
%define inc /usr/include/chelsio
%define mandir /usr/share/man/man3
%define mandirs /usr/share/man/man7

%description
libcxgb4_udp provides a device-specific userspace library for Chelsio T4
driver for use with the libibverbs library.

%prep

%{__mkdir} -p %{name}-%{version}%{lib}
%{__mkdir} -p %{name}-%{version}%{bin}
%{__mkdir} -p %{name}-%{version}%{inc}
%{__mkdir} -p %{name}-%{version}%{mandir}
%{__mkdir} -p %{name}-%{version}%{mandirs}

%{__cp} -a %{srcdir}/libcxgb4_udp/examples/.libs/udp_test %{name}-%{version}%{bin}
echo "%{bin}/udp_test" > %{rpmfiles}

%{__cp} -a %{srcdir}/libcxgb4_udp/include/chelsio/* %{name}-%{version}%{inc}
for file in $(/bin/ls  %{_topdir}/BUILD/%{name}-%{version}%{inc} 2>/dev/null); do
	echo "%{inc}/$(basename $file)" >> %{rpmfiles}
done

#%{__cp} -a %{srcdir}/libcxgb4_udp/man/*.3 %{name}-%{version}%{mandir}
#for file in $(/bin/ls  %{_topdir}/BUILD/%{name}-%{version}%{mandir} 2>/dev/null); do
#	echo "%{mandir}/$(basename $file)" >> %{rpmfiles}
#done

#%{__cp} -a %{srcdir}/libcxgb4_udp/man/*.7 %{name}-%{version}%{mandirs}
#for file in $(/bin/ls  %{_topdir}/BUILD/%{name}-%{version}%{mandir} 2>/dev/null); do
#	echo "%{mandirs}/$(basename $file)" >> %{rpmfiles}
#done

find %{srcdir}/libcxgb4_udp/ -name libcxgb4_udp\* -type f -exec cp {} %{name}-%{version}%{lib} \;;
find %{name}-%{version}%{lib} -name *.lai -type f -exec rm {} \;
find %{name}-%{version}%{lib} -name *.spec* -type f -exec rm {} \;
find %{name}-%{version}%{lib} -name libcxgb4_udp.map -type f -exec rm {} \;
for file in $(/bin/ls  %{_topdir}/BUILD/%{name}-%{version}%{lib} 2>/dev/null); do
	echo "%{lib}/$(basename $file)" >> %{rpmfiles}
done

%preun
if [ -f  %{lib}/libcxgb4_udp.so ]; then 
    unlink %{lib}/libcxgb4_udp.so;
fi
if [ -f %{lib}/libcxgb4_udp.so.1 ]; then
    unlink %{lib}/libcxgb4_udp.so.1;
fi

%post
ln -f -s %{lib}/libcxgb4_udp.so.1.0.0 %{lib}/libcxgb4_udp.so
ln -f -s %{lib}/libcxgb4_udp.so.1.0.0 %{lib}/libcxgb4_udp.so.1

%install
cd %{_topdir}/BUILD/%{name}-%{version}%{bin}
%{__install} -D -v -m 755 udp_test %{buildroot}%{bin}/udp_test

cd %{_topdir}/BUILD/%{name}-%{version}%{lib}
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}%{lib} 2>/dev/null); do
	%{__install} -D -v $file %{buildroot}%{lib}/$(basename $file)
done

cd %{_topdir}/BUILD/%{name}-%{version}%{mandir}
for file in $(/bin/ls  %{_topdir}/BUILD/%{name}-%{version}%{mandir} 2>/dev/null); do
	%{__install} -D -v $file %{buildroot}%{mandir}/$(basename $file)
done

cd %{_topdir}/BUILD/%{name}-%{version}%{mandirs}
for file in $(/bin/ls  %{_topdir}/BUILD/%{name}-%{version}%{mandirs} 2>/dev/null); do
	%{__install} -D -v $file %{buildroot}%{mandirs}/$(basename $file)
done

cd %{_topdir}/BUILD/%{name}-%{version}%{inc}
for file in $(/bin/ls  %{_topdir}/BUILD/%{name}-%{version}%{inc} 2>/dev/null); do
	%{__install} -D -v $file %{buildroot}%{inc}/$(basename $file)
done

/sbin/ldconfig

%clean
rm -rf %{RPM_BUILD_ROOT}

%files
/usr/bin/udp_test
/usr/include/chelsio/cxgb4_udp.h
#/usr/include/chelsio/get_clock.h
/usr/include/chelsio/queue.h
/usr/lib64/libcxgb4_udp.so.1.0.0
/usr/lib64/libcxgb4_udp.a
/usr/lib64/libcxgb4_udp.la
#/usr/share/man/man3/udp_alloc_dev.3.gz
#/usr/share/man/man3/udp_attach_mcast.3.gz
#/usr/share/man/man3/udp_create_qp.3.gz
#/usr/share/man/man3/udp_dealloc_dev.3.gz
#/usr/share/man/man3/udp_destroy_qp.3.gz
#/usr/share/man/man3/udp_detach_mcast.3.gz
#/usr/share/man/man3/udp_poll_cq.3.gz
#/usr/share/man/man3/udp_poll_frag.3.gz
#/usr/share/man/man3/udp_post_recv.3.gz
#/usr/share/man/man3/udp_post_send.3.gz
#/usr/share/man/man3/udp_start_dev.3.gz
#/usr/share/man/man3/udp_stop_dev.3.gz
#/usr/share/man/man7/cxgb4_udp.7.gz

%changelog
* Sun Jun 12 2011 root <root@speedy1.blr.asicdesigners.com> - 
- Initial build.

