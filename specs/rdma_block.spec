%{!?release:%define release 0}
%{!?kversion:%define kversion %(uname -r)}
%{!?arch:%define arch %(uname -p)}

## Summary offload string define.
Summary: Chelsio Terminator RDMA block device driver for Linux
Name:    %{name}
Version: %{version}
Release: %{release}
License: GPL
Group:   System Environment/Kernel
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>
Provides: %{name}-%{version}
requires: chiwarp > 1.1.0.10, chelsio-series4-firmware > 1.1.0.10

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}-root
#BuildRequires: kernel-devel
ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc
ExclusiveOS: linux

%define drvbase /lib/modules/%{kversion}/extra
%define mandir /usr/share/man/man8
%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt

%define debug_package %{nil}

%description
The Chelsio Terminator RDMA block device driver for Linux kernel (%{kversion}).

%prep
%{__mkdir} -p %{name}-%{version}/rdma-block-device/
%{__cp} -a %{srcdir}/rbdt.ko %{name}-%{version}/rdma-block-device/
%{__cp} -a %{srcdir}/rbdi.ko %{name}-%{version}/rdma-block-device/
echo "%{drvbase}/rbdt.ko" > %{rpmfiles}
echo "%{drvbase}/rbdi.ko" >> %{rpmfiles}

#utils
%{__mkdir} -p %{name}-%{version}/sbin
%{__cp} -a %{srcdir}/rbdctl/rbdctl %{name}-%{version}/sbin/
echo "/sbin/rbdctl" >> %{rpmfiles}

%build
## Nothing to do here.

%pre
## Nothing to do here.

%post
depmod
exit 0

%preun
## Nothing to do here.

%postun
depmod
exit 0

%install
cd %{_topdir}/BUILD/%{name}-%{version}
%{__install} -D -v rdma-block-device/rbdt.ko %{buildroot}%{drvbase}/rbdt.ko
%{__install} -D -v rdma-block-device/rbdi.ko %{buildroot}%{drvbase}/rbdi.ko
#utils 
%{__install} -D -v -m 755 sbin/rbdctl  %{buildroot}/sbin/rbdctl

%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt
%defattr(744,root,root)

%clean
%{__rm} -rf %{buildroot}

%changelog
