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
	else:
        	os.system('rm -rf /sbin/iscsiadm')
	if os.path.isfile('/sbin/iscsid1'):
        	os.system('mv /sbin/iscsid1 /sbin/iscsid')
	else:
        	os.system('rm -rf /sbin/iscsid')
	if os.path.isfile('/sbin/iscsi-iname1'):
        	os.system('mv /sbin/iscsi-iname1 /sbin/iscsi-iname')
	else:
        	os.system('rm -rf /sbin/iscsi-iname')
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
	fd = open ('uninstall.log','w')
	fd.write("-----------------------------------------")
	fd.write(" \nChelsio Unified Wire 2.12.0.3 Installer")
	fd.write("\n-----------------------------------------\n\n")
	fd.close()
	print "Uninstalling DEB packages from the system, uninstallation logs can be found in %s/uninstall.log file"%(os.getcwd())
	ofed_packages = ["compat-rdma", "compat-rdma-devel","kernel-ib", "kernel-ib-devel", "ofed", "ofed-kmp-default", "ib-bonding", 
			 "ib-bonding-debuginfo",
        	         "libibverbs", "libibverbs-devel", "libibverbs-devel-static",
                	 "libibverbs-utils", "libibverbs-debuginfo",
	                 "libmthca", "libmthca-devel-static", "libmthca-debuginfo",
        	         "libmlx4", "libmlx4-devel", "libmlx4-debuginfo",
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

	chelsio_package = [ "chelsio-series4-firmware", "cxgb4nic", "cxgb4", "cxgb4toe", "cxgb4vf", "chiwarp",
                            "bonding", "libcxgb4", "libcxgb4-debuginfo", "libcxgb4-devel", "sniffer",
                            "chfilter", "chtrace", "libcxgb4-udp", "libcxgb4-sock", "chelsio-utils",
                            "bypass", "chelsio-bypass-utils", "cxgb4toe-ipv4", "libwdtoe","libwdtoe-dbg",
                            "chiscsi", "cxgb4i", "csiostor-initiator", "csiostor-target", "cxgb4ipv6",
                            "cxgb4toe-udpso", "libcxgb4-udp-dbg", "libcxgb4-sock-dbg", "cxgb4wdtoe", "chfcoe", "rdma-block-device" ]
	debug=0
	to_remove = []
	if ofed:
		for package in all_ofed_package:
			sts,out = shell(' dpkg -s ' + package)
			if sts == 0:
				to_remove.append(package)
			elif debug:
				print 'package : %s not installed'%(package)
		for package in chelsio_package:
                	sts,out = shell('dpkg -s ' + package)
	                if sts == 0:
        	                to_remove.append(package)
                	elif debug:
	                        print 'package : %s not installed'%(package)
	elif inbox:
		for package in chelsio_package:
                	sts,out = shell('dpkg -s ' + package)
	                if sts == 0:
        	                to_remove.append(package)
	                elif debug:
                	        print 'package : %s not installed'%(package)
	scsi_target_utils = [ "scsi-target-utils", "tgt", "tgt-generic" ]
	scst_packages = ["scst-"+kernel_ver,"scst-"+kernel_ver+"-devel","scst-"+kernel_ver+"-debuginfo","scstadmin","scstadmin-debuginfo"]
	for scst_pack in scst_packages :
		sts,out = shell('dpkg -s ' + scst_pack)
		if sts == 0:
			to_remove.append(scst_pack)
		elif debug:
                                print 'package : %s not installed'%(package)
	if len(to_remove) > 0:
		for pack in scsi_target_utils :
			if pack in to_remove:
				uninst_cmd = 'dpkg -r %s && dpkg -P %s '%(pack)
				ret = os.system(uninst_cmd)
				to_remove.remove(pack)
		fd = os.open ('uninstall.log',os.O_APPEND|os.O_WRONLY)
		os.write(fd,"Removing  packages %s\n"%(' ,'.join(to_remove)))
		uninst_cmd = 'dpkg -r ' + ' '.join(to_remove) + '>> uninstall.log 2>&1'
		os.write(fd,"CMD: %s\n\n"%(uninst_cmd)) 
		ret = os.system(uninst_cmd)
		os.write(fd,"\nPurging  packages %s\n"%(' ,'.join(to_remove)))
                uninst_cmd = 'dpkg -P ' + ' '.join(to_remove) + '>> uninstall.log 2>&1'
                os.write(fd,"CMD: %s\n\n"%(uninst_cmd))
                ret = os.system(uninst_cmd)
                os.close(fd)
		res = ret >> 8;
		sig = ret &127;
		for loc in [ "/usr/local/lib64", "/usr/local/lib32", "/usr/lib64", "/usr/lib32", "/usr/lib", "/usr/local/lib" ]:
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
	uninstall()
	fixIscsiLink()
	os.system('rm -f /lib/modules/%s/updates/kernel/net/ipv6/ipv6.ko'%(kernel_ver))
	os.system('depmod -a')
	if os.path.isfile('/lib/modules/%s/updates/kernel/net/ipv6/ipv6.ko'%(kernel_ver)):
                os.system('rm -f /lib/modules/%s/updates/kernel/net/ipv6/ipv6.ko'%(kernel_ver))
        if os.path.isfile('/lib/modules/%s/updates/kernel/drivers/scsi/csioscst/csioscst.ko'%(kernel_ver)):
                os.system('rm -f /lib/modules/%s/updates/kernel/drivers/scsi/csioscst/csioscst.ko'%(kernel_ver))
	sys.exit(0)
