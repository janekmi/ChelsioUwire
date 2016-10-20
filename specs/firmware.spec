Summary: Chelsio Terminator 4 %{offload}driver for Linux
Name:    %{name}
Version: %{version}
Release: %{release}
License: GPL
Group:   System Environment/kernel
URL:     http://www.chelsio.com
Vendor:  Chelsio Communications, Inc.
Packager:Chelsio Communications, Inc. <http://www.chelsio.com>

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%{kversion}-root

ExclusiveArch: %{ix86} x86_64 ia64 ppc ppc64 ppc64le powerpc
ExclusiveOS: linux
Provides: %{name}-%{version}

%define rpmfiles %{_topdir}/BUILD/%{name}-%{version}/rpmfiles.txt
%define fwdir /lib/firmware/cxgb4
%define toolsdir %{srcdir}/../../tools
%description
The Chelsio Terminator 5 / Terminator 4 Ethernet Adapter firmware for Linux kernel (%{kversion}).

%pre
if [ ! -d %{fwdir} ]; then
  %{__rm} -rf %{fwdir};
  mkdir -p %{fwdir};
fi;
if [ -f %{fwdir}/t4fw.bin ] && [ ! -h %{fwdir}/t4fw.bin ]; then  
    %{__mv} -f %{fwdir}/t4fw.bin %{fwdir}/t4fw.bin_bak ; 
fi ;
if [ -h %{fwdir}/t4fw.bin ]; then 
    /bin/rm -f %{fwdir}/t4fw.bin ;
fi ;
if [ -f %{fwdir}/t5fw.bin ] && [ ! -h %{fwdir}/t5fw.bin ]; then
    %{__mv} -f %{fwdir}/t5fw.bin %{fwdir}/t5fw.bin_bak ;
fi ;
if [ -h %{fwdir}/t5fw.bin ]; then
    /bin/rm -f %{fwdir}/t5fw.bin ;
fi ;

for file in $(/bin/ls %{fwdir}/*.bin 2>/dev/null); do
    /bin/rm -f %{fwdir}/$(basename $file)
done 

for file in $(/bin/ls %{fwdir}/*.cld 2>/dev/null); do
    /bin/rm -f %{fwdir}/$(basename $file)
done

for file in $(/bin/ls %{fwdir}/*.txt 2>/dev/null); do
    /bin/rm -f %{fwdir}/$(basename $file)
done 

%post
for file in $(/bin/ls %{fwdir}/*.bin 2>/dev/null); do
    cfirm=`echo $file | awk -F "-" '{print $1}' | head -1 | awk '{print $1}' 2>/dev/null`
    if [ $cfirm == "/lib/firmware/cxgb4/t4fw" ] ; then
        /bin/ln -s %{fwdir}/$(basename $file) %{fwdir}/t4fw.bin 
    fi ;
    if [ $cfirm == "/lib/firmware/cxgb4/t5fw" ] ; then
        /bin/ln -s %{fwdir}/$(basename $file) %{fwdir}/t5fw.bin
    fi 
done 

%preun
if [ "$1" = "0" ] ; then
    if [ -h %{fwdir}/t4fw.bin ] ; then 
        %{__rm} -f %{fwdir}/t4fw.bin 2>/dev/null;
    fi
    if [ -h %{fwdir}/t5fw.bin ] ; then
         %{__rm} -f %{fwdir}/t5fw.bin 2>/dev/null;
    fi 
    if [ -f %{fwdir}/t4fw.bin_bak ]; then 
         %{__mv} %{fwdir}/t4fw.bin_bak %{fwdir}/t4fw.bin ;
    fi
    if [ -f %{fwdir}/t5fw.bin_bak ]; then
         %{__mv} %{fwdir}/t5fw.bin_bak %{fwdir}/t5fw.bin ;
    fi
fi

%prep
%{__mkdir} -p %{name}-%{version}/%{fwdir}
%{__cp} -a %{srcdir}/firmware/*.bin %{name}-%{version}%{fwdir}
%{__cp} -a %{conffile} %{name}-%{version}%{fwdir}
%{__cp} -a %{srcdir}/firmware/*.cld %{name}-%{version}%{fwdir}
%{__cp} -a %{toolsdir}/chelsio_adapter_config_v4/vpds/*.bin %{name}-%{version}%{fwdir}

for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}%{fwdir}/*.bin 2>/dev/null); do
  echo "%{fwdir}/$(basename $file)" >> %{rpmfiles}
done
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}%{fwdir}/*.cld 2>/dev/null); do
  echo "%{fwdir}/$(basename $file)" >> %{rpmfiles}
done
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}%{fwdir}/*.txt 2>/dev/null); do
  echo "%{fwdir}/$(basename $file)" >> %{rpmfiles}
done


%build

%install
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}%{fwdir}/*.bin 2>/dev/null); do
  %{__install} -D -v -m 644 $file %{buildroot}/%{fwdir}/$(basename $file)
done
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}%{fwdir}/*.txt 2>/dev/null); do
  %{__install} -D -v -m 644 $file %{buildroot}/%{fwdir}/$(basename $file)
done
for file in $(/bin/ls %{_topdir}/BUILD/%{name}-%{version}%{fwdir}/*.cld 2>/dev/null); do
  %{__install} -D -v -m 644 $file %{buildroot}/%{fwdir}/$(basename $file)
done

%files -f %{rpmfiles}

%clean
%{__rm} -rf %{buildroot}

%changelog
