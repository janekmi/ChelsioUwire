Summary: Chelsio Terminator %{offload} Filtering and Tracing tool for Linux
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
requires: chiwarp > 1.1.0.10 ,libcxgb4 > 1.1.0.10

%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt
%define bin /sbin
%define opt /opt/chelsio-utils
%define mandir /usr/share/man/man8
%define rpm_ver %(rpm -qf /etc/issue)
%define rpm_ver_rel %(rpm -q --queryformat "[%{NAME}]-[%{VERSION}]-[%{RELEASE}]" %{rpm_ver})

%description
The Chelsio Terminator Ethernet Adapter Filtering and Tracing tool for Linux kernel (%{kversion}).

%pre

%post

%postun

%prep
%{__mkdir} -p %{name}-%{version}%{bin}
%{__cp} -a %{srcdir}/t4_sniffer/tcpdump-4.1.1/wd_tcpdump_trace %{name}-%{version}/sbin/
echo "%{bin}/wd_tcpdump_trace" > %{rpmfiles}
%{__cp} -a %{srcdir}/t4_sniffer/tcpdump-4.1.1/wd_tcpdump %{name}-%{version}/sbin/
echo "%{bin}/wd_tcpdump" > %{rpmfiles}
%{__cp} -a %{srcdir}/t4_sniffer/sniffer_rdma_filter/sniffer  %{name}-%{version}/sbin/wd_sniffer
echo "%{bin}/wd_sniffer" > %{rpmfiles}

%build

%install
cd %{_topdir}/BUILD/%{name}-%{version}%{bin}
%{__install} -D -v -m 755 wd_tcpdump_trace %{buildroot}%{bin}/wd_tcpdump_trace
%{__install} -D -v -m 755 wd_tcpdump %{buildroot}%{bin}/wd_tcpdump
%{__install} -D -v -m 755 wd_sniffer %{buildroot}%{bin}/wd_sniffer

%files
%defattr(744,root,root)
/sbin/wd_tcpdump_trace
/sbin/wd_tcpdump
/sbin/wd_sniffer

%clean
%{__rm} -rf %{buildroot}

%changelog
