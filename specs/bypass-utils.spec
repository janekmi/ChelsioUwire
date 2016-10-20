Summary: Chelsio Terminator 4 %{offload} Tracing tool for Linux
Name:    %{name}
Version: %{version}
Release: %{release}
License: GPL
Group:   System Environment/Tools
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}-root

ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc
ExclusiveOS: linux
Provides: %{name}-%{version}

%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt
%define bin /sbin
%define mandir /usr/share/man/man8
%define srvdir /etc/init.d

%description
The Chelsio Terminator 4 Ethernet Adapter driver for Linux kernel (%{kversion}).

%preun
if [ -f /sbin/redirect ] ; then 
    unlink /sbin/redirect;
fi;
if [ -f /sbin/bypass ] ; then 
   unlink /sbin/bypass;
fi;

%post
ln -f /sbin/ba_client /sbin/redirect
ln -f /sbin/ba_client /sbin/bypass

%postun

%prep
%{__mkdir} -p %{name}-%{version}%{bin}
%{__cp} -a %{srcdir}/ba_server/build/t4/ba_server  %{name}-%{version}/sbin/
echo "%{bin}/ba_server" > %{rpmfiles}
%{__cp} -a %{srcdir}/ba_server/build/t4/ba_client  %{name}-%{version}/sbin/
echo "%{bin}/ba_client" >> %{rpmfiles}
%{__mkdir} -p %{name}-%{version}%{srvdir}
%{__cp} -a %{srcdir}/ba_server/build/ba-rc  %{name}-%{version}%{srvdir}
echo "%{srvdir}/ba-rc" >> %{rpmfiles}


%build

%install
cd %{_topdir}/BUILD/%{name}-%{version}%{bin}
%{__install} -D -m 755 ba_server %{buildroot}%{bin}/ba_server
%{__install} -D -m 755 ba_client %{buildroot}%{bin}/ba_client
cd %{_topdir}/BUILD/%{name}-%{version}%{srvdir}
%{__install} -D -m 744 ba-rc %{buildroot}%{srvdir}/bad

%files
%defattr(744,root,root)
/sbin/ba_server
/sbin/ba_client
/etc/init.d/bad

%clean
%{__rm} -rf %{buildroot}

%changelog
