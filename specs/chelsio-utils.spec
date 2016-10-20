%{!?kversion:%define kversion %(uname -r)}
%{!?arch:%define arch %(uname -p)}

Summary: Chelsio Terminator 4 %{offload}driver for Linux
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
%define opt /opt/chelsio-utils
%define mandir /usr/share/man/man8

%description
The Chelsio Terminator 4 Ethernet Adapter driver for Linux kernel (%{kversion}).

%pre

%post

%postun

%prep
%{__mkdir} -p %{name}-%{version}%{bin}
%{__mkdir} -p %{name}-%{version}%{mandir}

%{__cp} -a %{srcdir}/cxgbtool/cxgbtool %{name}-%{version}/sbin/
echo "%{bin}/cxgbtool" > %{rpmfiles}

%{__cp} -a %{srcdir}/cxgbtool/cxgbtool.8 %{name}-%{version}%{mandir}
echo "%{mandir}/cxgbtool.8.gz" >> %{rpmfiles}

if [ -f %{srcdir}/cop/cop ] ; then 
    %{__cp} -a %{srcdir}/cop/cop %{name}-%{version}/sbin/
    echo "%{bin}/cop" >> %{rpmfiles}
    %{__cp} -a %{srcdir}/cop/cop.8 %{name}-%{version}%{mandir}
    echo "%{mandir}/cop.8.gz" >> %{rpmfiles}
fi;

%{__cp} -a %{srcdir}/cudbg/app/cudbg_app %{name}-%{version}/sbin/
echo "%{bin}/cudbg_app" >> %{rpmfiles}

%{__cp} -a %{srcdir}/t4_perftune.sh %{name}-%{version}/sbin/
echo "%{bin}/t4_perftune.sh" >> %{rpmfiles}

%{__cp} -a %{srcdir}/t4_latencytune.sh %{name}-%{version}/sbin/
echo "%{bin}/t4_latencytune.sh" >> %{rpmfiles}

if [ %{arch} == 'x86_64' ] ; then
  %{__cp} -a %{srcdir}/wdload %{name}-%{version}/sbin/
  echo "%{bin}/wdload" >> %{rpmfiles}

  %{__cp} -a %{srcdir}/wdunload %{name}-%{version}/sbin/
  echo "%{bin}/wdunload" >> %{rpmfiles}
fi;

%{__cp} -a %{srcdir}/chstatus %{name}-%{version}/sbin/
echo "%{bin}/chstatus" >> %{rpmfiles}

%{__cp} -a %{srcdir}/chsetup %{name}-%{version}/sbin/
echo "%{bin}/chsetup" >> %{rpmfiles}

%{__cp} -a %{srcdir}/chdebug %{name}-%{version}/sbin/
echo "%{bin}/chdebug" >> %{rpmfiles}

%{__cp} -a %{srcdir}/uname_r %{name}-%{version}/sbin/
echo "%{bin}/uname_r" >> %{rpmfiles}

%{__cp} -a %{srcdir}/t4-forward.sh %{name}-%{version}/sbin/
echo "%{bin}/t4-forward.sh" >> %{rpmfiles}

if [ -f %{srcdir}/benchmarks/netperf/src/netperf ]; then
%{__cp} -a %{srcdir}/benchmarks/netperf/src/netperf %{name}-%{version}/sbin/
echo "%{bin}/netperf" >> %{rpmfiles}
fi;

if [ -f %{srcdir}/benchmarks/netperf/src/netserver ]; then
%{__cp} -a %{srcdir}/benchmarks/netperf/src/netserver %{name}-%{version}/sbin/
echo "%{bin}/netserver" >> %{rpmfiles}
fi;

if [ -f %{srcdir}/benchmarks/sockperf/src/sockperf ] ; then
%{__cp} -a %{srcdir}/benchmarks/sockperf/src/sockperf %{name}-%{version}/sbin/
echo "%{bin}/sockperf" >> %{rpmfiles}
fi;

if [ -f %{srcdir}/benchmarks/sockperf-lite/src/sockperf ] ; then
%{__cp} -a %{srcdir}/benchmarks/sockperf-lite/src/sockperf %{name}-%{version}/sbin/sockperf-lite
echo "%{bin}/sockperf-lite" >> %{rpmfiles}
fi;

if [ -f %{srcdir}/benchmarks/hpcbench/tcp/tcpserver ] ; then
%{__cp} -a %{srcdir}/benchmarks/hpcbench/tcp/tcpserver %{name}-%{version}/sbin/
echo "%{bin}/tcpserver" >> %{rpmfiles}
fi;

if [ -f %{srcdir}/benchmarks/hpcbench/tcp/tcptest ] ; then
%{__cp} -a %{srcdir}/benchmarks/hpcbench/tcp/tcptest %{name}-%{version}/sbin/
echo "%{bin}/tcptest" >> %{rpmfiles}
fi;

if [ %{arch} == 'x86_64' ] ; then
 if [ -f %{srcdir}/benchmarks/hpcbench/udp/udptest ] ; then
  %{__cp} -a %{srcdir}/benchmarks/hpcbench/udp/udptest %{name}-%{version}/sbin/
  echo "%{bin}/udptest" >> %{rpmfiles}
 fi;

 if [ -f %{srcdir}/benchmarks/hpcbench/udp/udpserver ] ; then
  %{__cp} -a %{srcdir}/benchmarks/hpcbench/udp/udpserver %{name}-%{version}/sbin/
  echo "%{bin}/udpserver" >> %{rpmfiles}
 fi;
fi ;

if [ -f %{srcdir}/benchmarks/iperf/src/iperf ]; then
%{__cp} -a %{srcdir}/benchmarks/iperf/src/iperf %{name}-%{version}/sbin/
echo "%{bin}/iperf" >> %{rpmfiles}
fi;

if [ -f %{srcdir}/benchmarks/netpipe/NPtcp ]; then
%{__cp} -a %{srcdir}/benchmarks/netpipe/NPtcp %{name}-%{version}/sbin/
echo "%{bin}/NPtcp" >> %{rpmfiles}
fi;

if [ -f %{srcdir}/chelsio_adapter_config_v4/bin/chelsio_adapter_config ]; then
    %{__cp} -a %{srcdir}/chelsio_adapter_config_v4/bin/chelsio_adapter_config %{name}-%{version}/sbin/
    echo "%{bin}/chelsio_adapter_config" >> %{rpmfiles}
fi;
if [ -f %{srcdir}/chelsio_adapter_config_v4/bin/t5seeprom ]; then
    %{__cp} -a %{srcdir}/chelsio_adapter_config_v4/bin/t5seeprom %{name}-%{version}/sbin/
    echo "%{bin}/t5seeprom" >> %{rpmfiles}
fi; 

%build

%install
cd %{_topdir}/BUILD/%{name}-%{version}%{bin}
%{__install} -D -v -m 755 cxgbtool %{buildroot}%{bin}/cxgbtool
%{__install} -D -v -m 755 cudbg_app %{buildroot}%{bin}/cudbg_app
if [ -f cop ]; then
    %{__install} -D -v -m 755 cop %{buildroot}%{bin}/cop
    cd %{_topdir}/BUILD/%{name}-%{version}%{mandir}
    %{__install} -D -v -m 644 cop.8 %{buildroot}%{mandir}/cop.8
fi;

cd %{_topdir}/BUILD/%{name}-%{version}%{mandir}
%{__install} -D -v -m 644 cxgbtool.8 %{buildroot}%{mandir}/cxgbtool.8

cd %{_topdir}/BUILD/%{name}-%{version}%{bin}
%{__install} -D -v -m 755 t4_perftune.sh %{buildroot}%{bin}/t4_perftune.sh
%{__install} -D -v -m 755 t4_latencytune.sh %{buildroot}%{bin}/t4_latencytune.sh

if [ -f wdload ] ; then
 %{__install} -D -v -m 755 wdload %{buildroot}%{bin}/wdload
fi;

if [ -f wdunload ] ; then
%{__install} -D -v -m 755 wdunload %{buildroot}%{bin}/wdunload
fi ;

%{__install} -D -v -m 755 chstatus %{buildroot}%{bin}/chstatus
%{__install} -D -v -m 755 chsetup %{buildroot}%{bin}/chsetup
%{__install} -D -v -m 755 chdebug %{buildroot}%{bin}/chdebug
%{__install} -D -v -m 755 t4-forward.sh %{buildroot}%{bin}/t4-forward.sh
%{__install} -D -v -m 755 uname_r %{buildroot}%{bin}/uname_r
if [ -f netperf ] ; then 
    %{__install} -D -v -m 755 netperf %{buildroot}%{bin}/netperf
fi;
if [ -f netserver ]; then
    %{__install} -D -v -m 755 netserver %{buildroot}%{bin}/netserver
fi;
if [ -f sockperf ]; then
    %{__install} -D -v -m 755 sockperf %{buildroot}%{bin}/sockperf
fi;
if [ -f sockperf-lite ]; then
    %{__install} -D -v -m 755 sockperf-lite %{buildroot}%{bin}/sockperf-lite
fi;
if [ -f udpserver ]; then
    %{__install} -D -v -m 755 udpserver %{buildroot}%{bin}/udpserver
fi;
if  [ -f udptest ]; then
    %{__install} -D -v -m 755 udptest %{buildroot}%{bin}/udptest
fi;
if [ -f tcpserver ]; then
    %{__install} -D -v -m 755 tcpserver %{buildroot}%{bin}/tcpserver
fi;
if [ -f tcptest ]; then
    %{__install} -D -v -m 755 tcptest %{buildroot}%{bin}/tcptest
fi;
if [ -f iperf ] ; then 
    %{__install} -D -v -m 755 iperf %{buildroot}%{bin}/iperf
fi;
if [ -f NPtcp ] ; then
    %{__install} -D -v -m 755 NPtcp %{buildroot}%{bin}/NPtcp
fi;

for dbins in chelsio_adapter_config t5seeprom ; do
    if [ -f ${dbins} ]; then
        %{__install} -D -v -m 755 ${dbins} %{buildroot}%{bin}/${dbins}
    fi;
done;

%files -f %{_builddir}/%{name}-%{version}/rpmfiles.txt

%clean
%{__rm} -rf %{buildroot}

%changelog
