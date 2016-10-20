#!/usr/bin/python
import os,commands,sys,re
inbox=False
ofed=False
BLUE = '\033[1;34m'
GREEN = '\033[0;32m'
WARNING = '\033[93m'
FAIL = '\033[91m'
RESET = '\033[0m'
sts,kernel_ver = commands.getstatusoutput('uname -r')

def fixIscsiLink():
	if os.path.isfile('/sbin/iscsiadm1'):
        	os.system('mv /sbin/iscsiadm1 /sbin/iscsiadm')
	if os.path.isfile('/sbin/iscsid1'):
        	os.system('mv /sbin/iscsid1 /sbin/iscsid')
	if os.path.isfile('/sbin/iscsi-iname1'):
        	os.system('mv /sbin/iscsi-iname1 /sbin/iscsi-iname')
	if os.path.isfile('/etc/iscsi/iscsid.conf.1'):
        	os.system('mv /etc/iscsi/iscsid.conf.1 /etc/iscsi/iscsid.conf')
	if os.path.islink('/lib/modules/%s/updates/kernel/drivers/scsi/scsi_transport_iscsi2.ko'%(kernel_ver)):
		os.system('rm -f /lib/modules/%s/updates/kernel/drivers/scsi/scsi_transport_iscsi2.ko'%(kernel_ver))
	if os.path.islink('/lib/modules/%s/updates/kernel/drivers/scsi/libiscsi2.ko'%(kernel_ver)):
		os.system('rm -f /lib/modules/%s/updates/kernel/drivers/scsi/libiscsi2.ko'%(kernel_ver))

def shell(cmd):
        sts, out = commands.getstatusoutput(cmd)
        return (sts,out.strip())

def uninstall():
	global inbox
	global ofed
	dist_rpm = None
	dist = None
	os.system('rm -f uninstall.log &> /dev/null')
	fd = os.open ('uninstall.log',os.O_CREAT|os.O_WRONLY,0644)
	os.write(fd,"-----------------------------------------")
	os.write(fd," \nChelsio Unified Wire 2.12.0.3 Installer")
	os.write(fd,"\n-----------------------------------------\n\n")
	os.close(fd)
	print "Uninstalling RPM packages from the system, uninstallation logs can be found in %s/uninstall.log file"%(os.getcwd())
	if os.path.isfile('/etc/issue'):
                dist_rpm = shell('rpm -qf /etc/issue | head -1')[1]
                dist_rpm = shell('rpm -q --queryformat "[%{NAME}]-[%{VERSION}]-[%{RELEASE}]" ' + dist_rpm)[1]
        else:
                dist_rpm = "unsupported"
        if re.search('sles-release-11.2',dist_rpm) != None:
                dist = 'sles11'
        elif re.search('sles-release-11.1',dist_rpm) != None:
                dist = 'sles11'
        elif re.search('sles-release-11',dist_rpm) != None:
                dist = 'sles11'
        else :
		dist = 'rhel'
	ofed_packages = ["compat-rdma", "compat-rdma-devel","kernel-ib", "kernel-ib-devel", "ofed", "ofed-kmp-default", "ib-bonding", 
			 "ib-bonding-debuginfo", "libmlx5-devel", "libmlx5-debuginfo", "libmlx5", 
			 "libocrdma-devel", "libocrdma-debuginfo", "libocrdma", "librdmacm1",
        	         "libmlx4", "libmlx4-devel", "libmlx4-debuginfo",
        	         "libibverbs", "libibverbs1", "libibverbs-runtime", "libibverbs-devel", "libibverbs-devel-static",
                	 "libibverbs-utils", "libibverbs-debuginfo",
	                 "libmthca", "libmthca-devel-static", "libmthca-debuginfo",
                	 "libcxgb3", "libcxgb3-devel", "libcxgb3-debuginfo",
	                 "libnes", "libnes-devel-static", "libnes-debuginfo",
        	         "libipathverbs", "libipathverbs-devel", "libipathverbs-debuginfo",
                	 "libibcm", "libibcm-devel", "libibcm-debuginfo",
	                 "libibumad", "libibumad-devel", "libibumad-static", "libibumad-debuginfo",
        	         "libibmad", "libibmad-devel", "libibmad-static", "libibmad-debuginfo",
                	 "ibsim", "ibsim-debuginfo", "ibacm-devel", "ibacm-debuginfo","ibacm",
	                 "librdmacm", "librdmacm-utils", "librdmacm-devel", "librdmacm-debuginfo",
        	         "libsdp", "libsdp-devel", "libsdp-debuginfo",
               		 "opensm-libs", "opensm","opensm-devel", "opensm-debuginfo", "opensm-static",
	                 "dapl", "dapl-static", "dapl-devel", "dapl-devel-static", "dapl-utils", "dapl-debuginfo",
			 "compat-dapl", "compat-dapl-static","compat-dapl-devel", "compat-dapl-devel-static", "compat-dapl-utils",
			 "compat-dapl-debuginfo", "compat-dapl-static",
	                 "perftest", "mstflint","perftest-debuginfo","mstflint-debuginfo",
                	 "sdpnetstat", "sdpnetstat-debuginfo", "srptools", "srptools-debuginfo", "rds-tools", "rds-devel",
        	         "ibutils", "ibutils-devel","ibutils-libs", "ibutils-debuginfo", "infiniband-diags-compat","infiniband-diags", "infiniband-diags-debuginfo",
	                 "qperf", "qperf-debuginfo", "rds-tools-debuginfo",
        	         "ofed-docs", "ofed-doc", "ofed-scripts", "tgt-generic", "tgt","scsi-target-utils",
                	 "infinipath-psm", "infinipath-psm-devel","infinipath-psm-debuginfo", "mpi-selector",
	                 "mvapich_gcc", "mvapich2_gcc", "openmpi_gcc",
        	         "mpitests_mvapich_gcc", "mpitests_mvapich2_gcc", "mpitests_openmpi_gcc" ]

	old_ofed_packages = [ "mpich_mlx", "ibtsal", "openib", "mpi_ncsa", "thca", "ib-osm",
			     "osm", "diags", "ibadm", "ib-diags", "ibgdiag", "ibdiag", "ib-management",
			     "ib-verbs", "ib-ipoib", "ib-cm", "ib-sdp", "ib-dapl", "udapl", "udapl-devel", 
			     "libdat", "libibat", "ib-kdapl", "ib-srp", "ib-srp_target", "oiscsi-iser-support", 
			     "ibvexdmtools", "qlvnictools", "ipoibtools", "libibcommon1","rdma-ofa-agent",
			     "libibumad3", "libibumad5", "ofa", "libamso", "libamso-devel", "dapl2", "dapl2-devel", "lam" ]
	
	ofed_packages_32_bit = [ "opensm-32bit", "ibutils-32bit", "libibumad1-32bit", "libamso-rdmav2-32bit", 
				 "libcxgb3-rdmav2-32bit",  "libmlx4-rdmav2-32bit", "libmthca-rdmav2-32bit" ]

	inbox_mpi_packages = [ "mvapich", "mvapich2-psm", "mvapich-psm", "mvapich2", "mvapich2-common", "openmpi",
			       "mpitests-mvapich2", "mpitests-mvapich", "mpitests-openmpi","openmpi-libs",
			       "openmpi-devel", "lam-libs", "compat-openmpi-psm", "compat-openmpi", 
			       "compat-opensm-libs" ]

	sles_ofed_libs_package = [ "libamso-rdmav2", "libcxgb3-rdmav2", "libcxgb4-rdmav2", "libmlx4-rdmav2", 
				   "libmthca-rdmav2", "libnes-rdmav2", "libibumad1" ]

	all_ofed_package = ofed_packages + old_ofed_packages + inbox_mpi_packages + sles_ofed_libs_package + ofed_packages_32_bit

	chelsio_package = [ "chelsio-series4-firmware", "cxgb4nic", "cxgb4", "cxgb4toe", "cxgb4vf", "rdma-block-device", "chiwarp",
        	            "bonding", "libcxgb4", "libcxgb4-debuginfo", "libcxgb4-devel",
        	            "chfilter", "chtrace", "sniffer", "libcxgb4_udp", "libcxgb4_sock", "chelsio-utils",
			    "bypass", "chelsio-bypass-utils", "cxgb4toe-ipv4", "libwdtoe","libwdtoe_dbg",
			    "chiscsi", "cxgb4i", "csiostor-initiator", "csiostor-target", "cxgb4ipv6",
			    "cxgb4toe-udpso", "libcxgb4_udp_debug", "libcxgb4_sock_debug", "cxgb4wdtoe", "chfcoe" ]
	debug=0
	to_remove = []
	to_remove_ofed = []
	if ofed:
		for package in all_ofed_package:
			sts,out = shell('rpm -q ' + package)
			if sts == 0:
				to_remove_ofed.append(package)
			elif debug:
				print 'package : %s not installed'%(package)
		for package in chelsio_package:
                	sts,out = shell('rpm -q ' + package)
	                if sts == 0:
        	                to_remove.append(package)
                	elif debug:
	                        print 'package : %s not installed'%(package)
	elif inbox:
		for package in chelsio_package:
                	sts,out = shell('rpm -q ' + package)
	                if sts == 0:
        	                to_remove.append(package)
	                elif debug:
                	        print 'package : %s not installed'%(package)
	scsi_target_utils = [ "scsi-target-utils", "tgt", "tgt-generic" ]
	scst_packages = ["scst-"+kernel_ver,"scst-"+kernel_ver+"-devel","scst-"+kernel_ver+"-debuginfo","scstadmin","scstadmin-debuginfo"]
	for scst_pack in scst_packages :
		sts,out = shell('rpm -q ' + scst_pack)
		if sts == 0:
			to_remove.append(scst_pack)
		elif debug:
                                print 'package : %s not installed'%(package)
	if len(to_remove) > 0:
		for pack in scsi_target_utils :
			if pack in to_remove:
				uninst_cmd = 'rpm --noscripts -e %s'%(pack)
				ret = os.system(uninst_cmd)
				to_remove.remove(pack)
		fd = os.open ('uninstall.log',os.O_APPEND|os.O_WRONLY)
		os.write(fd,"Uninstalling packages %s\n"%(' ,'.join(to_remove)))
		uninst_cmd = 'rpm -e --allmatches ' + ' '.join(to_remove) + '>> uninstall.log 2>&1'
		os.write(fd,"CMD: %s\n\n"%(uninst_cmd)) 
		ret = os.system(uninst_cmd)
		os.close(fd)
		res = ret >> 8;
		sig = ret &127;
		if dist == 'sles11' and (res or sig):
			print FAIL + "Failed to uninstall RPM's" + RESET
			print FAIL + "Edit /etc/sysconfig/services, set DISABLE_STOP_ON_REMOVAL=\"yes\"" +  RESET 
                	print FAIL + "Run the following cmd to uninstall all the rpms : " + RESET
	                print 'rpm -e --allmatches ' + ' '.join(to_remove)
			print FAIL + "Some RPMs may depend on the RPMs above. Please uninstall them manually." + RESET
        	        sys.exit(1)
		elif dist == 'rhel' and res > 0:
			print FAIL + "Failed to uninstall RPM's" + RESET
			print FAIL + "Run the following cmd to uninstall all the rpms : " + RESET
			print 'rpm -e --allmatches ' + ' '.join(to_remove)
			print FAIL + "Some RPMs may depend on the RPMs above. Please uninstall them manually." + RESET
			sys.exit(1)
		for loc in [ "/usr/local/lib64", "/usr/local/lib32", "/usr/lib64", "/usr/lib32" ]:
			cmd = "find %s -name libcxgb4* -exec rm {} \+"%(loc)
			commands.getstatusoutput(cmd)
		cmd = "find /lib/firmware/cxgb4 -name aq1202_fw.cld -exec rm {} \+"
		commands.getstatusoutput(cmd)
		commands.getstatusoutput("ldconfig")
		os.system('rm -f /sbin/uname_r')
	elif debug:	
		print "Nothing found to uninstall. toremove ",to_remove
	else:
		fd = os.open ('uninstall.log',os.O_APPEND|os.O_WRONLY)
		os.write(fd,"Nothing to Uninstall\n")
		os.close(fd)
	if len(to_remove_ofed) > 0:
		fd = os.open ('uninstall.log',os.O_APPEND|os.O_WRONLY)
	        os.write(fd,"Uninstalling OFED packages %s\n"%(' ,'.join(to_remove)))
	        uninst_cmd = 'rpm -e --allmatches --nodeps ' + ' '.join(to_remove_ofed) + '>> uninstall.log 2>&1'
		os.write(fd,"CMD: %s\n\n"%(uninst_cmd))
	        ret = os.system(uninst_cmd)
		os.close(fd)
		res = ret >> 8;
	        sig = ret &127;
		

def Usage():
	print "Usage: %s inbox|ofed"%(sys.argv[0])
	print "          inbox  : for removing all Chelsio drivers."
	print "          ofed   : for removing OFED and Chelsio drivers." 	 
	sys.exit(1)

if __name__ == "__main__":
	if len(sys.argv) != 2:
		Usage()
	if sys.argv[1] == "ofed":
		ofed = True
	elif sys.argv[1] == "inbox":
		inbox = True
	elif sys.argv[1] == "-h" or sys.argv[1] == "--help":
		Usage()
                sys.exit(1)
	elif sys.argv[1] != "ofed" or sys.argv[1] != "inbox":
		print "Unknown argument: %s provided.\n"%(sys.argv[1])
		Usage()
		sys.exit(1)
	if os.path.isfile('/usr/bin/dpkg'):
		sys.exit(0)
	uninstall()
	fixIscsiLink()
	os.system('rm -f /lib/modules/%s/updates/kernel/net/ipv6/ipv6.ko'%(kernel_ver))
	if os.path.isfile('/etc/modprobe.d/chelsio.conf') :
		os.system('rm -f /etc/modprobe.d/chelsio.conf')
	os.system('depmod -a')
	if os.path.isfile('/lib/modules/%s/updates/kernel/net/ipv6/ipv6.ko'%(kernel_ver)):
		os.system('rm -f /lib/modules/%s/updates/kernel/net/ipv6/ipv6.ko'%(kernel_ver))
	if os.path.isfile('/lib/modules/%s/updates/kernel/drivers/scsi/csioscst/csioscst.ko'%(kernel_ver)):
		os.system('rm -f /lib/modules/%s/updates/kernel/drivers/scsi/csioscst/csioscst.ko'%(kernel_ver))
	sys.exit(0)
