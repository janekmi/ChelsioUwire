#!/usr/bin/python
import os,sys,re,subprocess,threading
from threading import Thread
import commands,platform
import ConfigParser
import math
import cStringIO,operator
import getopt,time
sys.path.append(os.getcwd())

HEADER = '\033[1;34m'
BLUE = '\033[1;34m'
GREEN = '\033[0;32m'
WARNING = '\033[93m'
FAIL = '\033[91m'
RESET = '\033[0m'
U_LINE = '\e[4m'
R_U_LINE = '\e[0m'
H_RESET = '\033[0m\e[0m'

def shell(cmd):
	sts, out = commands.getstatusoutput(cmd)
	return (sts,out.strip())

def show_heading(heading):
	underline = ''
	for line in range(len(heading)):
		underline += '-'
	print underline
	print heading
	print underline

def print_underline():
	underline = ''
	for line in range(0, column):
		underline += '-'
	print underline

pathVar = '/'.join(sys.argv[0].split('/')[:-1])
if pathVar.strip() != '':
	os.chdir(pathVar)
dist = None
DISTRO = None
rpm_dir = None
fcoe_support = False
fcoe_tgt_support = False
bypass_support = True
wdtoe_support = False
wd_support = True
udpso_support = False
uwire_support = True
um_support = False
ofed_rpm = os.getcwd() + '/OFED-RPMS'
ofed_build_drv_rpm = os.getcwd() + '/DRIVER-RPMS/ofed'
kernel_build_drv_rpm = os.getcwd() + '/DRIVER-RPMS/inbox'
config_dir = os.getcwd() + '/config'
kernel_ver =  shell('uname -r')[1]
arch = shell('uname -m')[1]
column = 60
dist_rpm = None
inbox = False
ofed = False
nic_toe = False
target = False
bypass = False
wdtoe = False
wd = False
udpso = False
enable_rbd = False
conf_uwire = False
conf_ll = False
conf_hctoe = False
conf_hcrdma = False
conf_tgt = False
conf_udpso = False
conf_edc_only = False
conf_hcll = False
conf_hfilter = False
conf_rdma_perf = False
conf_iscsi_perf = False
conf_memfree = False
exit = False
ofed_not_supported_on_platform = False
version = '2.12.0.3'
UM_VERSION = "2.4-78"
log_file = os.getcwd() + '/install.log'
handler = open(log_file,'w')
handler.writelines("\n+----------------------------------------+" \
	      "\n|Chelsio Unified Wire 2.12.0.3 Installer |" \
	      "\n+----------------------------------------+\n")
handler.close()
config_dict = {}
install_dict = {}
install_dict_new = {}
debug=0
clusterInstall = False
machine_file = None
clus_config_file = None
nodes = []
logDir = os.path.abspath('.') + os.sep + "logs"
chkconfig = False
chkinstall = False
clus_install_opt = None
chkuninstall = False
cluster_file = ""
CUSTOMENU = 0

def isAllow(): 
        cmd = 'cat /etc/issue'
        sts,out = commands.getstatusoutput(cmd)
        if out.find('suse') != -1 or out.find('SUSE') != -1:
             cmd = 'uname -r'
             sts,out = commands.getstatusoutput(cmd)
             if out.find('2.6.16') != -1:
                 return ' '
             return " --allow"
        else:
             return ' '

def addToModprobeConf(): 
        global conf_hfilter
        if  os.path.exists("/etc/modprobe.d/chelsio.conf") :
            os.remove("/etc/modprobe.d/chelsio.conf")
        handlers=open("/etc/modprobe.d/chelsio.conf",'w')
        msg = ""
        options = "-C " #Disable binding IRQs to CPUs (smp_affinity).
        if conf_hfilter:
             hashfilter = "use_ddr_filters=1"
        else :
             hashfilter = ""
        msg = 'install cxgb4 /sbin/modprobe cxgb4 %s --ignore-install'%(hashfilter) + str(isAllow()) + ' $CMDLINE_OPTS;'
        msg += ' /sbin/t4_perftune.sh ' + options
        msg += ' > /dev/null ||. ; \n'
        handlers.write(msg)
        handlers.close()

def dist_check():
	global dist_rpm
	global DISTRO
	global dist
	global fcoe_tgt_support 
	global fcoe_support 
	global um_support 
	global bypass_support
	global wdtoe_support
	global udpso_support
	global log_file 
	global install_dict
	global config_dict
	global ofed_not_supported_on_platform
	global cluster_file

	if os.path.isfile('/etc/issue'):
		dist_rpm = shell('rpm -qf /etc/issue | head -1')[1]
		dist_rpm = shell('rpm -q --queryformat "[%{NAME}]-[%{VERSION}]-[%{RELEASE}]" ' + dist_rpm)[1]
	else:
		dist_rpm = "unsupported"

	if re.search('sles-release-12\.1',dist_rpm) != None:
                dist = 'sles12sp1'
                DISTRO = 'SLES12.1'
                bypass_support = True
                fcoe_support = True
                fcoe_tgt_support = False
                udpso_support = True
                wdtoe_support = False
		ofed_not_supported_on_platform = True
                cluster_file = "SLES12sp1"
 	elif re.search('sles-release-12',dist_rpm) != None:
                dist = 'sles12'
                DISTRO = 'SLES12'
                bypass_support = True
                fcoe_support = True
                fcoe_tgt_support = False
                udpso_support = True
                wdtoe_support = False
		ofed_not_supported_on_platform = False
                cluster_file = "SLES12"
	elif re.search('sles-release-11.4',dist_rpm) != None:
                dist = 'sles11sp4'
                DISTRO = 'SLES11.4'
                bypass_support = True
                fcoe_support = True
                fcoe_tgt_support = False
		ofed_not_supported_on_platform = False
                udpso_support = True
                wdtoe_support = False
                um_support = True
		cluster_file = "SLES11sp4"
	elif re.search('sles-release-11.3',dist_rpm) != None:
                dist = 'sles11sp3'
                DISTRO = 'SLES11.3'
                bypass_support = True
                fcoe_support = True
                fcoe_tgt_support = False
		ofed_not_supported_on_platform = False
                udpso_support = True
                wdtoe_support = False
                um_support = True
		cluster_file = "SLES11sp3"
	elif re.search('redhat-release-.*-6.5|centos-release-6-5',dist_rpm) != None:
                dist = 'rhel6u5'
                DISTRO = 'RHEL6.5'
                fcoe_support = True
                fcoe_tgt_support = False
                bypass_support = True
                ofed_not_supported_on_platform = False
                wdtoe_support = False
                udpso_support = True
                um_support = False
                cluster_file = "RHEL6.5"
	elif re.search('redhat-release-.*-6.6|centos-release-6-6',dist_rpm) != None:
                dist = 'rhel6u6'
                DISTRO = 'RHEL6.6'
                fcoe_support = True
                fcoe_tgt_support = False
                bypass_support = True
                ofed_not_supported_on_platform = False
                wdtoe_support = False
                udpso_support = True
                um_support = True
                cluster_file = "RHEL6.6"
	elif re.search('redhat-release-.*-6.7|centos-release-6-7',dist_rpm) != None:
                dist = 'rhel6u7'
                DISTRO = 'RHEL6.7'
                fcoe_support = True
                fcoe_tgt_support = False
                bypass_support = True
                ofed_not_supported_on_platform = False
                wdtoe_support = False
                udpso_support = True
                um_support = False
                cluster_file = "RHEL6.7"
	elif re.search('redhat-release-.*-7.2|centos-release-7-2',dist_rpm) != None:
                dist = 'rhel7u2'
                DISTRO = 'RHEL7.2'
                fcoe_support = True
                fcoe_tgt_support = False
                bypass_support = True
                ofed_not_supported_on_platform = True
                wdtoe_support = False
                udpso_support = True
                um_support = False
                cluster_file = "RHEL7.2"
	elif re.search('redhat-release-.*-7.1|centos-release-7-1',dist_rpm) != None:
                dist = 'rhel7u1'
                DISTRO = 'RHEL7.1'
                fcoe_support = True
                fcoe_tgt_support = False
                bypass_support = True
                ofed_not_supported_on_platform = False
                wdtoe_support = False
                udpso_support = True
                um_support = False
                cluster_file = "RHEL7.1"
	else :
		print BLUE + 'The Operating System is not supported.\n' + RESET
		print BLUE + 'For the list of Supported Platforms and Operating Systems see' + RESET
		print BLUE + '%s/docs/README.txt'%(os.getcwd()) + RESET
		sys.exit(1)
	handler = open(log_file,'a')
	handler.writelines("\n+-----------------+" \
		      "\n| Machine Details |"\
		      "\n+-----------------+\n")
	handler.writelines("\nhostname = %s"%(shell('hostname')[1]))
	handler.writelines("\nuname = %s"%(shell('uname -a')[1]))
	handler.writelines("\nDIST = %s"%(DISTRO))
	handler.writelines("\nwho am i = %s\n"%(shell('who am i')[1]))
	handler.close()
	config_dict['UNIFIED_WIRE' ] = 'conf_uwire'
	config_dict['HIGH_CAPACITY_TOE'] = 'conf_hctoe'
	config_dict['HIGH_CAPACITY_RDMA'] = 'conf_hcrdma'
	config_dict['LOW_LATENCY'] = 'conf_ll'
	config_dict['T5_WIRE_DIRECT'] = 'conf_edc_only'
	config_dict['HIGH_CAPACITY_WD'] = 'conf_hcll'
	config_dict['T5_HASH_FILTER'] = 'conf_hfilter'
	config_dict['RDMA_PERFORMANCE'] = 'conf_rdma_perf'
	config_dict['ISCSI_PERFORMANCE'] = 'conf_iscsi_perf'
	config_dict['MEMORY_FREE'] = 'conf_memfree'
	if udpso_support:
		config_dict['UDP_OFFLOAD'] = 'conf_udpso'
	install_dict['all'] = 'inbox'
	install_dict['nic_toe'] = 'nic_toe'
	if fcoe_tgt_support:
		config_dict['T4_CONF_TGT'] = 'conf_tgt'
		install_dict['target'] = 'target'
	if bypass_support:
		install_dict['bypass'] = 'bypass'
	if udpso_support:
		install_dict['udpso'] = 'udpso'
	if wd_support:
		install_dict['wd'] = 'wd'

def kernel_check():
	if re.search('2.6.32-431.el6|2.6.32-504.el6|2.6.32-573.el6|3.10.0-229.el7|3.10.0-229.el7.ppc64|3.10.0-229.ael7b.ppc64le|3.10.0-327.el7|' \
			'3.0.76-0.11-default|3.0.101-63-default|3.12.28-4-default|3.12.49-11-default',kernel_ver ) == None:
		print BLUE + 'The Operating System kernel version is not supported.\n' + RESET
		print BLUE + 'For the list of Supported Platforms and Operating Systems see' + RESET
		print BLUE + '%s/docs/README.txt'%(os.getcwd()) + RESET
		sys.exit(1)
	'''if dist != 'rhel6u5':
                print FAIL + 'The package is supported only for Red Hat Enterprise Linux Server release 6.5, kernel version 2.6.32-431.el6' + RESET
                print FAIL + 'Kindly download the correct package for %s distribution from service.chelsio.com'%(DISTRO) + RESET
                sys.exit(1)'''
	if re.search('3.17',kernel_ver ) != None:
		enable_rbd = True

def arch_check():
	if arch not in [ "x86_64", "ppc64", "ppc64le" ] :
		print BLUE + 'The %s architecture is not supported.\n'%(arch) + RESET
		print BLUE + 'The package supports only x86_64/ppc64le architecture.' + RESET
		sys.exit(1)

if commands.getstatusoutput('which rpm')[0] != 0 :
	print BLUE + 'rpm command not found.\n' + RESET
	sys.exit(1)

ofed_packages = []

ofed_packages_3u5 = ["compat-rdma","compat-rdma-devel","libibverbs", "libibverbs1", "libibverbs-debuginfo",
		"libibverbs-devel","libibverbs-devel-static","libibverbs-utils","libipathverbs",
                "libipathverbs-debuginfo","libipathverbs-devel", "librdmacm1",
                "librdmacm","librdmacm-debuginfo","librdmacm-devel","librdmacm-utils",
                "libcxgb3","libcxgb3-debuginfo","libcxgb3-devel",
                "libibcm","libibcm-debuginfo",
                "libibcm-devel","libibumad","libibumad-debuginfo","libibumad-devel","libibumad-static",
                "libibmad","libibmad-debuginfo","libibmad-devel","libibmad-static",
                "opensm-libs","opensm","opensm-debuginfo","opensm-devel","opensm-static",
		"ibutils","ibutils-debuginfo","infinipath-psm","infinipath-psm-debuginfo",
                "infinipath-psm-devel",
                "compat-dapl","compat-dapl-debuginfo","compat-dapl-devel",
                "compat-dapl-devel-static","compat-dapl-utils",
                "dapl","dapl-debuginfo","dapl-devel","dapl-devel-static",
                "ofed-docs","ofed-scripts","perftest","perftest-debuginfo","qperf",
                "qperf-debuginfo","rds-devel","rds-tools",
                "rds-tools-debuginfo"]

ofed_packages_1 = ["kernel-ib", "kernel-ib-devel", "ib-bonding", "ib-bonding-debuginfo",
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
                 "ibsim", "ibsim-debuginfo", "ibacm", "ibacm-debuginfo",
                 "librdmacm", "librdmacm-utils", "librdmacm-devel", "librdmacm-debuginfo",
                 "libsdp", "libsdp-devel", "libsdp-debuginfo",
                 "opensm-libs", "opensm", "opensm-devel", "opensm-debuginfo", "opensm-static",
                 "dapl", "dapl-devel", "dapl-devel-static", "dapl-utils", "dapl-debuginfo",
                 "perftest", "mstflint","perftest-debuginfo","mstflint-debuginfo",
                 "sdpnetstat", "sdpnetstat-debuginfo", "srptools", "srptools-debuginfo", "rds-tools", "rds-devel",
                 "ibutils", "ibutils-debuginfo", "infiniband-diags", "infiniband-diags-debuginfo",
		 "qperf", "qperf-debuginfo", "rds-tools-debuginfo", 
                 "ofed-docs", "ofed-scripts", "tgt-generic", "tgt","scsi-target-utils",
                 "infinipath-psm", "infinipath-psm-devel","infinipath-psm-debuginfo", "mpi-selector",
		 "mvapich_gcc", "mvapich2_gcc", "openmpi_gcc", 
		 "mpitests_mvapich_gcc", "mpitests_mvapich2_gcc", "mpitests_openmpi_gcc" ]
                     
	
chelsio_package = [ "chelsio-series4-firmware", "cxgb4", "cxgb4toe", "cxgb4vf", "chiwarp",
		    "bonding", "libcxgb4", "libcxgb4-debuginfo", "libcxgb4-devel",
		    "sniffer", "libcxgb4_udp", "libcxgb4_sock", "chelsio-utils",
		    "libcxgb4_udp_debug", "libcxgb4_sock_debug", "rdma-block-device" ]
chelsio_bypass_package = ["chelsio-series4-firmware","bypass", "chelsio-bypass-utils","chelsio-utils" ] 

chelsio_stor_package = [ "chiscsi", "cxgb4i", "csiostor-initiator", "csiostor-target" ]

chelsio_udpso_package = [ "chelsio-series4-firmware", "cxgb4", "cxgb4toe", "bonding", "chelsio-utils" ]

chelsio_wdtoe_package = [ "chelsio-series4-firmware", "cxgb4", "chiwarp", "libcxgb4", 
                    "libcxgb4-debuginfo", "libcxgb4-devel", "libcxgb4_udp", "libcxgb4_sock", 
                    "libcxgb4_udp_debug", "libcxgb4_sock_debug", "cxgb4wdtoe", "libwdtoe", "libwdtoe_dbg","chelsio-utils" ]

chelsio_package_info = {'chelsio-series4-firmware' : { 'name' : 'Chelsio Terminator 4 firmware',
			      	                       'available' : 1, 'requires' : []},
			'cxgb4' : { 'name' : 'NIC driver',
                                    'available' : 1, 'requires' : ['chelsio-series4-firmware'] },
			'cxgb4toe' : { 'name' : 'TOE driver',
                                       'available' : 1, 'requires' : ['cxgb4'] },
			'cxgb4vf' : { 'name' : 'SRIOV VF driver',
                                      'available' : 1, 'requires' : [] },
			'chiwarp' : { 'name' : 'iWARP RDMA driver',
                                      'available' : 1, 'requires' : ['cxgb4'] },
			'bonding' : { 'name' : 'TOE bonding driver',
                                      'available' : 1, 'requires' : ['cxgb4toe'] },
			'libcxgb4' : { 'name' : 'iWARP RDMA libarary',
                                       'available' : 1, 'requires' : [] },
			'libcxgb4-debuginfo' : { 'name' : 'iWARP RDMA lib debuginfo',
	                                         'available' : 1, 'requires' : ['libcxgb4'] },
			'libcxgb4-devel' : { 'name' : 'iWARP RDMA lib devel',
                                             'available' : 1, 'requires' : ['libcxgb4'] },
			'libcxgb4_udp' : { 'name' : 'WD UDP lib',
                                           'available' : 1, 'requires' : ['libcxgb4','chiwarp'] },
                        'libcxgb4_sock' : { 'name' : 'WD UDP Sock lib',
                                            'available' : 1, 'requires' : ['libcxgb4_udp'] },
			'libcxgb4_udp_debug' : { 'name' : 'WD UDP Debug lib',
                                           'available' : 1, 'requires' : ['libcxgb4','chiwarp'] },
			'libcxgb4_sock_debug' : { 'name' : 'WD UDP Sock Debug lib',
                                            'available' : 1, 'requires' : ['libcxgb4_udp'] },
			'sniffer' : { 'name' : 'Chelsio Filtering and Tracing app',
                                       'available' : 1, 'requires' : ['chiwarp','libcxgb4'] },
			'rdma-block-device' : { 'name' : 'Chelsio RDMA block device',
                                      'available' : 1, 'requires' : ['chiwarp','libcxgb4'] },
			'chelsio-utils' : { 'name' : 'Chelsio Utilities and Management',
                                            'available' : 1, 'requires' : [] },
# disable component is used for disabling all the features present in the current dictionary
			'disable'  : { 'name' : 'Disable All (for script purpose)',
				       'available' : 1, 'requires' : [] }
			}

chelsio_bypass_package_info = { 'chelsio-series4-firmware' : { 'name' : 'Chelsio Terminator 4 firmware',
                                                               'available' : 1, 'requires' : []},
				'bypass' : { 'name' : 'Chelsio Bypass drivers Package',
                                             'available' : 1, 'requires' : ['chelsio-series4-firmware']},
			        'chelsio-bypass-utils' : { 'name' : 'Chelsio Bypass Utilities',
                                             'available' : 1, 'requires' : []},
				'chelsio-utils' : { 'name' : 'Chelsio Utilities and Management',
	                                            'available' : 1, 'requires' : [] },
# disable component is used for disabling all the features present in the current dictionary
	                        'disable'  : { 'name' : 'Disable All (for script purpose)',
        	                               'available' : 1, 'requires' : [] }
				}

chelsio_stor_package_info = { 'chiscsi' : { 'name' : 'Chelsio iSCSI Target',
                                            'available' : 1, 'requires' : ['cxgb4toe']},
			      'cxgb4i' : { 'name' : 'Open iSCSI Accelerator',
                                           'available' : 1, 'requires' : ['cxgb4']},
			      'csiostor-initiator' :  { 'name' : 'Chelsio FCoE Initiator driver',
	                                                'available' : 1, 'requires' : ['chelsio-series4-firmware']},
			      'csiostor-target' : { 'name' : 'Chelsio FCoE Target driver',
                                                    'available' : 0, 'requires' : ['chelsio-series4-firmware']},
	                        'disable'  : { 'name' : 'Disable All (for script purpose)',
        	                               'available' : 1, 'requires' : [] }
	
			      }

chelsio_udpso_package_info = {
			'chelsio-series4-firmware' : { 'name' : 'Chelsio Terminator 4 firmware',
                                                               'available' : 1, 'requires' : []},
			'cxgb4' : { 'name' : 'NIC driver',
                                    'available' : 1, 'requires' : ['chelsio-series4-firmware'] },
			'cxgb4toe' : { 'name' : 'UDP SO TOE driver',
                                       'available' : 0, 'requires' : ['cxgb4'] },
			'bonding' : { 'name' : 'TOE bonding driver',
                                      'available' : 1, 'requires' : ['cxgb4toe'] },
			'chelsio-utils' : { 'name' : 'Chelsio Utilities and Management',
                                            'available' : 0, 'requires' : [] },
			'disable'  : { 'name' : 'Disable All (for script purpose)',
                                               'available' : 0, 'requires' : [] }
			}

chelsio_wdtoe_package_info = {
                        'chelsio-series4-firmware' : { 'name' : 'Chelsio Terminator 4 firmware',
                                                               'available' : 1, 'requires' : []},
                        'cxgb4' : { 'name' : 'NIC driver',
                                    'available' : 1, 'requires' : ['chelsio-series4-firmware'] },
                        'chiwarp' : { 'name' : 'iWARP RDMA driver',
                                      'available' : 1, 'requires' : ['cxgb4'] },
                        'libcxgb4' : { 'name' : 'iWARP RDMA libarary',
                                       'available' : 1, 'requires' : [] }, 
                        'libcxgb4-debuginfo' : { 'name' : 'iWARP RDMA lib debuginfo',
                                                 'available' : 1, 'requires' : ['libcxgb4'] },
                        'libcxgb4-devel' : { 'name' : 'iWARP RDMA lib devel',
                                             'available' : 1, 'requires' : ['libcxgb4'] },
                        'libcxgb4_udp' : { 'name' : 'WD UDP lib',
                                           'available' : 1, 'requires' : ['libcxgb4','chiwarp'] },
                        'libcxgb4_sock' : { 'name' : 'WD UDP Sock lib',
                                            'available' : 1, 'requires' : ['libcxgb4_udp'] },
                        'libcxgb4_udp_debug' : { 'name' : 'WD UDP Debug lib',
                                           'available' : 1, 'requires' : ['libcxgb4','chiwarp'] },
                        'libcxgb4_sock_debug' : { 'name' : 'WD UDP Sock Debug lib',
                                            'available' : 1, 'requires' : ['libcxgb4_udp'] },
                        'cxgb4wdtoe' : { 'name' : 'WD-TOE driver',
                                       'available' : 1, 'requires' : ['cxgb4'] },
	                'libwdtoe' : { 'name' : 'WD TOE library',
                                       'available' : 1, 'requires' : ['cxgb4'] },
			'libwdtoe_dbg' : { 'name' : 'WD TOE Debug library',
                                       'available' : 1, 'requires' : ['cxgb4'] },
                        'chelsio-utils' : { 'name' : 'Chelsio Utilities and Management',
                                            'available' : 1, 'requires' : [] },
                        'disable'  : { 'name' : 'Disable All (for script purpose)',
                                               'available' : 0, 'requires' : [] }
                        }

def checkOfedOnMachine():
	sts, ib_core_info = shell('modinfo -F filename ib_core')
	if sts != 0:
		return 0
	if ib_core_info.find('updates') != -1 :
		sts, rpm_full_name = shell('rpm -qf %s'%ib_core_info)
		if sts != 0:
			return 0
		sts, rpm_name = shell('rpm -q --queryformat "[%{NAME}]" ' + rpm_full_name)
		if rpm_name == "kernel-ib" or rpm_name == "compat-rdma":
			print FAIL + "Error : Non-inbox OFED is installed on Machine and will",
			print " not work with current installation configuration." + RESET
			print FAIL + "Kindly restart the installer and choose to install OFED using custom option",
			print "or use the Source package available at service.chelsio.com" + RESET
			sys.exit(-1)
		
def prompt_ofed():
	global ofed
	ix = 1
	data = ''
	menu ={}	
	os.system('clear')
	show_heading("Chelsio Unified Wire 2.12.0.3 Installer\nSelect the OFED installation: ")
	data += \
                '''Press %d, Install OFED-3.18-1,Ideal for iWARP/WD Users'''%(ix)
        menu[ix] = 'ofed'
        ix += 1
	if data != '':
                data = data + '\n'
        data +='''Press %d, To skip OFED installation,N/A'''%(ix)
        menu[ix] = 'next'
        ix += 1
	width=100
	rows = [row.strip().split(',')  for row in data.splitlines()]
        labels = ('Choice',' Installation Type','Supported Protocols/Drivers')
	print '\n' + indent([labels]+rows, hasHeader=True, separateRows=True,
                     prefix='| ', postfix=' |',
        	     wrapfunc=lambda x: wrap_always(x,width))
	while True :
                choice=raw_input("Input:")
        	choice = choice.strip()
	        if not choice.isdigit():
                        print "Incorrect input %s, please try again"%(choice)
        	elif int(choice) not in menu.keys():
                	print "Incorrect input %s, please try again"%(choice)
	        else:
                        break
	globals()[menu[int(choice)]] = True
	if ofed == False:
		checkOfedOnMachine()
        handler = open(log_file,'a')
	handler.writelines("\nOFED selection: %s\n"%(menu[int(choice)]))
	handler.close()

def prompt_install():
	global fcoe_tgt_support
	global fcoe_support
	global bypass_support
	global wdtoe_support
	global udpso_support
	global log_file
	global conf_hfilter 
	global ofed_not_supported_on_platform
	global uwire_support
	global CUSTOMENU
	global wd_support
        install_select=""
	menu ={}	
	os.system('clear')
	ix = 1
	if CUSTOMENU == 1 :
		data = ''
		show_heading("Chelsio Unified Wire 2.12.0.3 Installer\nSelect the Installation Type: ")
		if fcoe_support:
			data += \
			'''Press %d, Install all Chelsio drivers,NIC/TOE/iWARP/WD_UDP/FCoE-Init/iSCSI-T/iSCSI-I'''%(ix)
			menu[ix] = 'inbox'
			ix += 1
		elif fcoe_tgt_support:
			if data != '':
				data = data + '\n' 
			data +='''Press %d, Install all Chelsio drivers,NIC/TOE/iWARP/WD_UDP/iSCSI-T/iSCSI-I'''%(ix)
			menu[ix] = 'target'
			ix += 1
		elif uwire_support:
			if conf_hfilter :
				data += '''Press %d, Install Chelsio Hash Filter drivers,NIC'''%(ix)
			elif conf_ll :
				if wdtoe_support :
					data += '''Press %d, Install all Chelsio drivers,NIC/WDTOE/WDUDP/iWARP/FILTER/TRACE'''%(ix)
				else :
					data += '''Press %d, Install all Chelsio drivers,NIC/TOE/WDUDP/iWARP/FILTER/TRACE'''%(ix)
			elif conf_hctoe :
				data += '''Press %d, Install all Chelsio drivers,NIC/TOE/BONDING'''%(ix)
			elif conf_hcrdma :
				data += '''Press %d, Install all Chelsio drivers,NIC/TOE/iWARP/WDUDP/BONDING/FILTER/TRACE'''%(ix)
			elif conf_edc_only or conf_hcll :
				if wdtoe_support :
					data += '''Press %d, Install all Chelsio drivers,NIC/WDTOE/WDUDP/iWARP'''%(ix)
				else:
					data += '''Press %d, Install all Chelsio drivers,NIC/TOE/WDUDP/iWARP'''%(ix)
			elif conf_rdma_perf :
				data += '''Press %d, Install all Chelsio drivers,NIC/TOE/iWARP/WD_UDP'''%(ix)
			elif conf_iscsi_perf :
				data += '''Press %d, Install all Chelsio drivers,NIC/TOE/BONDING/iSCSI-T/iSCSI-I'''%(ix)
			elif conf_memfree :
				data += '''Press %d, Install all Chelsio drivers,NIC/TOE/iWARP/WD_UDP'''%(ix)
			else : 
				data += '''Press %d, Install all Chelsio drivers,NIC/TOE/iWARP/WD_UDP/iSCSI-T/iSCSI-I'''%(ix)
			menu[ix] = 'inbox'
			ix += 1
		if udpso_support :
			if data != '':
	                        data = data + '\n'
        	        data += '''Press %d, Install UDP segmentation offload capable NIC and TOE drivers,NIC/TOE/BONDING'''%(ix)
                	menu[ix] = 'udpso'
	                ix += 1
		elif not conf_hfilter:
			if data != '':
				data = data + '\n' 
			data += '''Press %d, Install NIC and TOE drivers,NIC/TOE'''%(ix)
			menu[ix] = 'nic_toe'
			ix += 1
		if bypass_support:
			if data != '':
				data = data + '\n'
			data += '''Press %d, Install bypass drivers and tools,Bypass'''%(ix)
			menu[ix] = 'bypass'
			ix += 1
		if wd_support:
        	        if data != '':
                	        data = data + '\n'
	                data += '''Press %d, Install WD drivers and library,'''%(ix)
			if wdtoe_support:
				data += '''WD-TOE/'''
			data += '''WD-UDP'''
        	        menu[ix] = 'wd'
                	ix += 1
		if data != '':
			data = data + '\n' 
		data += '''Press %d, EXIT,'''%(ix)
		menu[ix] = 'exit'
		width=100
		rows = [row.strip().split(',')  for row in data.splitlines()]
		labels = ('Choice',' Installation Type','Supported Protocols/Drivers')
		print '\n' + indent([labels]+rows, hasHeader=True, separateRows=True,
       		             prefix='| ', postfix=' |',
               		     wrapfunc=lambda x: wrap_always(x,width))
		while True :
		        choice=raw_input("Input:")
			choice = choice.strip()
			if not choice.isdigit():
				print "Incorrect input %s, please try again"%(choice)
			elif int(choice) not in menu.keys():
				print "Incorrect input %s, please try again"%(choice)
			else:
				break
	else :
                data = \
                '''Press %d, Install all Chelsio drivers,NIC/TOE/iWARP/WD_UDP/FCoE-Init/iSCSI-T/iSCSI-I'''%(ix)
                menu[ix] = 'inbox'
                choice = ix
		os.system('clear')
	        show_heading("Chelsio Unified Wire 2.12.0.3 Installer")
		print

	if menu[int(choice)] == "inbox" :
       		install_select="all"
	else :
      		install_select=menu[int(choice)]
	globals()[menu[int(choice)]] = True
	handler = open(log_file,'a')
	handler.writelines("\nInstallation selection: %s\n"%(install_select))
	handler.close()
	if exit :	
		sys.exit(1)
		

def promptCustomConfig():
        global fcoe_tgt_support
        global fcoe_support
        global udpso_support
	global CUSTOMENU
        menu ={}
        os.system('clear')
        ix = 1
        data = ''
        show_heading("Chelsio Unified Wire 2.12.0.3 Installer\nSelect the T5 / T4 Configuration:")
        if fcoe_support:
                data += \
                '''Press %d, Unified Wire, Install all the Chelsio drivers with FCoE Initiator'''%(ix)
                menu[ix] = 'conf_uwire'
                ix += 1
        else:
                data += \
                '''Press %d, Unified Wire, Install all the Chelsio drivers'''%(ix)
                menu[ix] = 'conf_uwire'
                ix += 1
        if not clusterInstall :
                if data != '':
                        data = data + '\n'
                data += \
                '''Press %d, T5 Wire Direct Latency, NIC;TOE;RDMA;WD*'''%(ix)
                menu[ix] = 'conf_edc_only'
                ix += 1
                if data != '':
                        data = data + '\n'
                data += \
                '''Press %d, Custom, Custom Installation'''%(ix)
                menu[ix] = 'custom'
                ix += 1
        if data != '':
                data = data + '\n'
        data += \
        '''Press %d, EXIT, '''%(ix)
        menu[ix] = 'exit'
        width=100
        rows = [row.strip().split(',')  for row in data.splitlines()]
        labels = ('Choice',' T5 / T4 Configuration',' Supported Protocols/Drivers')
        print '\n' + indent([labels]+rows, hasHeader=True, separateRows=True,
                     prefix='| ', postfix=' |',
                     wrapfunc=lambda x: wrap_always(x,width))
        while True :
                choice=raw_input("Input:")
                choice = choice.strip()
                if not choice.isdigit():
                        print "Incorrect input %s, please try again"%(choice)
                elif int(choice) not in menu.keys():
                        print "Incorrect input %s, please try again"%(choice)
                else:
                        break
        globals()[menu[int(choice)]] = True
        handler = open(log_file,'a')
        if menu[int(choice)] == "custom" :
		CUSTOMENU=1
		return True
        else:
                chtoprint=menu[int(choice)]
        handler.writelines("\nT5 / T4 Configuration selection: %s\n"%(chtoprint))
        handler.close()
        if exit :
                sys.exit(1)
	return False

def prompt_config():
	global fcoe_tgt_support
	global fcoe_support
	global udpso_support
        menu ={}
        os.system('clear')
        ix = 1
	data = ''
	show_heading("Chelsio Unified Wire 2.12.0.3 Installer\nSelect the T5 / T4 Configuration:")
	if fcoe_support:
		data += \
		'''Press %d, Unified Wire, Install all the Chelsio drivers with FCoE Initiator'''%(ix)
		menu[ix] = 'conf_uwire'
		ix += 1
	else:
		data += \
		'''Press %d, Unified Wire, Install all the Chelsio drivers'''%(ix)
		menu[ix] = 'conf_uwire'
		ix += 1
	if fcoe_tgt_support:
		if data != '':
			data = data + '\n' 
		data += \
		'''Press %d, Unified Wire (includes FCoE Target), Install all the Chelsio drivers with FCoE Target'''%(ix)
                menu[ix] = 'conf_tgt'
                ix += 1
	if data != '':
		data = data + '\n' 
	data += \
	'''Press %d, Low Latency Networking, NIC;TOE;RDMA;WD*'''%(ix)
	menu[ix] = 'conf_ll'
	ix += 1
	if not clusterInstall :
		if data != '':
			data = data + '\n' 
		data += \
		'''Press %d, High Capacity TOE, NIC;TOE'''%(ix)
		menu[ix] = 'conf_hctoe'
		ix += 1
	if data != '':
		data = data + '\n' 
	data += \
	'''Press %d, High Capacity RDMA, NIC;TOE;RDMA'''%(ix)
	menu[ix] = 'conf_hcrdma'
	ix += 1
	if data != '':
                data = data + '\n'
        data += \
        '''Press %d, RDMA Performance, NIC;TOE;RDMA'''%(ix)
        menu[ix] = 'conf_rdma_perf'
        ix += 1
	if data != '':
                data = data + '\n'
        data += \
        '''Press %d, Memory Free, NIC;TOE;RDMA'''%(ix)
        menu[ix] = 'conf_memfree'
        ix += 1

	if udpso_support and not clusterInstall :
		if arch.find("ppc") == -1 :
			if data != '':
				data = data + '\n'
	                data += \
		        '''Press %d, UDP Segmentation Offload & Pacing, UDP segmenation offload capable NIC;TOE'''%(ix)
			menu[ix] = 'conf_udpso'
	                ix += 1
	if not clusterInstall :
		if data != '':
			data = data + '\n'
	        data += \
		'''Press %d, T5 Wire Direct Latency, NIC;TOE;RDMA;WD*'''%(ix)
	        menu[ix] = 'conf_edc_only'
		ix += 1
		if arch.find("ppc") == -1 :
			if data != '':
			        data = data + '\n'
			data += \
			'''Press %d, T5 High Capacity WD, NIC;TOE;RDMA;WD*'''%(ix)
		        menu[ix] = 'conf_hcll'
			ix += 1

		if data != '':
		        data = data + '\n'
	        data += \
		'''Press %d, iSCSI Performance, NIC;TOE;iSCSI'''%(ix)
	        menu[ix] = 'conf_iscsi_perf'
		ix += 1
		if arch.find("ppc") == -1 :
			if data != '':
				data = data + '\n'
		        data += \
			'''Press %d, T5 Hash Filter, NIC'''%(ix)
			menu[ix] = 'conf_hfilter'
			ix += 1
	if data != '':
		data = data + '\n' 
	data += \
	'''Press %d, EXIT, '''%(ix)
	menu[ix] = 'exit'
	width=100
        rows = [row.strip().split(',')  for row in data.splitlines()]
        labels = ('Choice',' T5 / T4 Configuration',' Supported Protocols/Drivers')
        print '\n' + indent([labels]+rows, hasHeader=True, separateRows=True,
                     prefix='| ', postfix=' |',
                     wrapfunc=lambda x: wrap_always(x,width))
	while True :
	        choice=raw_input("Input:")
		choice = choice.strip()
		if not choice.isdigit():
			print "Incorrect input %s, please try again"%(choice)
		elif int(choice) not in menu.keys():
			print "Incorrect input %s, please try again"%(choice)
		else:
			break
        globals()[menu[int(choice)]] = True
	handler = open(log_file,'a')
	if menu[int(choice)] == "conf_edc_only" :
                chtoprint="conf_T5_WD_LATENCY"
        else:
                chtoprint=menu[int(choice)]
        handler.writelines("\nT5 / T4 Configuration selection: %s\n"%(chtoprint))
	handler.close()
	if exit :	
		sys.exit(1)

def process_config():
	global conf_ll
	global conf_hcrdma
	global conf_tgt
	global conf_hctoe
	global conf_edc_only
	global bypass
	global udpso
	global wdtoe
	global bypass_support
	global wdtoe_support
	global wd_support
	global udpso_support
	global fcoe_support
	global fcoe_tgt_support
	global uwire_support
	global ofed_not_supported_on_platform
	global log_file
	global clus_config_file 
	if clusterInstall :
		if conf_hcrdma :
			clus_config_file = "HIGH_CAPACITY_RDMA"
        	elif conf_ll :
			clus_config_file = "LOW_LATENCY"
		elif conf_tgt:
			clus_config_file = "UNIFIED_WIRE"
	        elif conf_hctoe:
			clus_config_file = "HIGH_CAPACITY_TOE"
        	elif conf_udpso:
			clus_config_file = "UDP_OFFLOAD"
		elif conf_edc_only:
			clus_config_file = "T5_WIRE_DIRECT"
		elif conf_hcll:
			clus_config_file = "HIGH_CAPACITY_WD"
		elif conf_hfilter:
			clus_config_file = "T5_HASH_FILTER"
		elif conf_rdma_perf:
			clus_config_file = "RDMA_PERFORMANCE"
		elif conf_iscsi_perf:
			clus_config_file = "ISCSI_PERFORMANCE"
		elif conf_memfree:
			clus_config_file = "MEMORY_FREE"
		else :
			clus_config_file = "UNIFIED_WIRE"
	if conf_hcrdma :
		fcoe_support = False
		fcoe_tgt_support = False	
		#uwire_support = False
		bypass_support = False
		udpso_support = False
		wdtoe_support = False
	elif conf_ll :
		fcoe_support = False
		fcoe_tgt_support = False
		#uwire_support = False
		bypass_support = False
		udpso_support = False
		#wdtoe_support = True
	elif conf_edc_only :
		fcoe_support = False
                fcoe_tgt_support = False
                #uwire_support = False
                bypass_support = False
                udpso_support = False
                #wdtoe_support = True
	elif conf_tgt:
		fcoe_support = False
		bypass_support = False
		udpso_support = False
		wdtoe_support = False
	elif conf_hctoe:
		fcoe_support = False
		fcoe_tgt_support = False
		#uwire_support = False
		bypass_support = False
		udpso_support = False
		ofed_not_supported_on_platform = True
		wdtoe_support = False
	elif conf_udpso:
		fcoe_support = False
		fcoe_tgt_support = False
		uwire_support = False
		wdtoe_support = False
		wd_support = False
		bypass_support = False
		ofed_not_supported_on_platform = True
		ofed = False
		inbox = False
		target = False
	elif conf_hcll:
		fcoe_support = False
		fcoe_tgt_support = False
		#uwire_support = False
		bypass_support = False
		udpso_support = False
		#wdtoe_support = True
	elif conf_hfilter:
		fcoe_support = False
		fcoe_tgt_support = False
		wdtoe_support = False
		wd_support = False
		bypass_support = False
		ofed_not_supported_on_platform = True
		ofed = False
		target = False
		udpso_support = False
	elif conf_uwire:
                udpso_support = False
	elif conf_rdma_perf or conf_memfree:
		fcoe_support = False
                fcoe_tgt_support = False
                #uwire_support = False
                bypass_support = False
                udpso_support = False
                wdtoe_support = False
	elif conf_iscsi_perf:
		fcoe_support = False
                fcoe_tgt_support = False
                #uwire_support = False
                bypass_support = False
                udpso_support = False
                wdtoe_support = False
		wd_support = False
		ofed_not_supported_on_platform = True

def read_eula():
	eula = os.getcwd() + os.sep + 'EULA'
	if os.path.isfile(eula):
		os.system('more -d ' + eula)
		print ""
		#print_underline()
		show_heading("Do you agree with the terms and conditions of this license agreement?")
		while True :
			choice = raw_input("Type \"y\" to accept the EULA and continue or \"q\" to quit:").strip()
			if choice == "q":
				sys.exit(1)
			elif choice == "y":
				break
			else:
				print "Incorrect input %s, please try again"%(choice)
	else:
		print "Unable to locate EULA in Package."
		sys.exit(-1)
	
def prompt_welcome():
	os.system('clear')
	show_heading("Welcome to the Chelsio Unified Wire 2.12.0.3 Installer")
	print ""
	while True :
		choice = raw_input("Press Enter to read EULA or q to quit:").strip()
		if choice == "q" or choice == '':
			break
		else :
			print "Incorrect input %s, please try again"%(choice)
	if choice == 'q':
		sys.exit(1)
	elif choice == '':
		read_eula()

def get_clus_config() :
	global ofed_not_supported_on_platform
	global chkconfig
	global chkinstall
	global ofed
        #prompt_welcome()
        dist_check()
        kernel_check()
        arch_check()
	if not chkuninstall :
		if not chkconfig :
			prompt_config()
		process_config()
		if not ofed_not_supported_on_platform and not ofed:
                	prompt_ofed()
	        if ofed_not_supported_on_platform and ofed:
			print "Ofed is Not Supported in current Platform, Restart Installation without -o option"
                	sys.exit(1)
		if not chkinstall : 
			prompt_install()

def process_clus_cmd():
	global ofed
	global clus_config_file
	global clus_cmd
	global clus_install_opt
	if clus_install_opt == None: 
		if nic_toe :
			clus_install_opt = "nic_toe"
		elif bypass :
			clus_install_opt = "bypass"
		elif wdtoe :
			clus_install_opt = "wd"
		elif udpso :
			clus_install_opt = "udpso"
		else :
			clus_install_opt = "all"

	clus_cmd = "./install.py -i " + clus_install_opt + " "
	if ofed :
		clus_cmd += "-o "
	clus_cmd += "-c %s"%(clus_config_file)
	print clus_cmd		
	

def get_config():
	global ofed_not_supported_on_platform
	global CUSTOMENU
	#prompt_welcome()
	dist_check()
	kernel_check()
	arch_check()
	if promptCustomConfig() : 
		prompt_config()
	process_config()
	if CUSTOMENU == 0 :
		ofed = False
		checkOfedOnMachine()
	else:
		if not ofed_not_supported_on_platform:
			prompt_ofed()
	prompt_install()

def set_availablity() :
	global chelsio_package
	global chelsio_stor_package
	global chelsio_bypass_package
	global chelsio_udpso_package
	global chelsio_wdtoe_package
	global chelsio_package_info
	global chelsio_stor_package_info
	global chelsio_bypass_package_info
	global chelsio_wdtoe_package_info
	global chelsio_udpso_package_info
	global chelsio_hcll_package_info
	global chelsio_hfilter_package_info
	global conf_uwire 
	global conf_ll 
	global conf_hctoe
	global conf_hcrdma
	global conf_tgt
	global conf_edc_only
	global conf_hcll
	global conf_hfilter
	global conf_rdma_perf
	global conf_iscsi_perf
	global conf_memfree
	global DISTRO
	global dist
	global fcoe_support
	global wdtoe_support
	global fcoe_tgt_support
	global bypass_support 
	global inbox
	global ofed 
	global nic_toe
	global target 
	global bypass 
	global wdtoe
	global udp_so
	global enable_rbd

	"""
	   Disable availablity of packages on the basis of config chosen.
	"""
	if conf_uwire :
		chelsio_bypass_package_info['disable']['available'] = 0 
		chelsio_stor_package_info['csiostor-target']['available'] = 0
		chelsio_udpso_package_info['disable']['available'] = 0
	if conf_ll or conf_edc_only or conf_hcll :
		chelsio_stor_package_info['disable']['available'] = 0
                chelsio_bypass_package_info['disable']['available'] = 0
                chelsio_udpso_package_info['disable']['available'] = 0
		if inbox:
			if wdtoe_support:
				chelsio_wdtoe_package_info['disable']['available'] = 1
				for packs in ['chiwarp', 'libcxgb4', 'libcxgb4-devel', 'libcxgb4_udp', 'libcxgb4_sock', \
					'libcxgb4_udp_debug', 'libcxgb4_sock_debug', 'libcxgb4-debuginfo', 'cxgb4', 'chelsio-utils' ] :
					chelsio_wdtoe_package_info[packs]['available'] = 0
				chelsio_wdtoe_package_info['cxgb4wdtoe']['available'] = 1
				chelsio_wdtoe_package_info['libwdtoe']['available'] = 1
				chelsio_wdtoe_package_info['libwdtoe_dbg']['available'] = 1
				chelsio_wdtoe_package_info['chelsio-series4-firmware']['available'] = 1
				chelsio_package_info['chelsio-series4-firmware']['available'] = 0
	        	        chelsio_package_info['cxgb4toe']['available'] = 0
				chelsio_package_info['cxgb4vf']['available'] = 0
			else :
				chelsio_wdtoe_package_info['disable']['available'] = 0
				chelsio_package_info['cxgb4vf']['available'] = 0
			if conf_edc_only or conf_hcll :
				chelsio_package_info['sniffer']['available'] = 0
			chelsio_package_info['bonding']['available'] = 0
	if conf_hcrdma:
		chelsio_stor_package_info['disable']['available'] = 0
		chelsio_bypass_package_info['disable']['available'] = 0
		chelsio_udpso_package_info['disable']['available'] = 0
	        chelsio_wdtoe_package_info['disable']['available'] = 0
		chelsio_package_info['cxgb4vf']['available'] = 0
	if conf_hctoe or conf_hfilter:
		chelsio_stor_package_info['disable']['available'] = 0
		chelsio_package_info['sniffer']['available'] = 0
		chelsio_package_info['chiwarp']['available'] = 0
		chelsio_package_info['libcxgb4']['available'] = 0
		chelsio_package_info['libcxgb4-devel']['available'] = 0
		chelsio_package_info['libcxgb4_udp']['available'] = 0
		chelsio_package_info['libcxgb4_sock']['available'] = 0
		chelsio_package_info['libcxgb4_udp_debug']['available'] = 0
		chelsio_package_info['libcxgb4_sock_debug']['available'] = 0
		chelsio_package_info['libcxgb4-debuginfo']['available'] = 0
		chelsio_bypass_package_info['disable']['available'] = 0
		chelsio_udpso_package_info['disable']['available'] = 0
		chelsio_wdtoe_package_info['disable']['available'] = 0
		chelsio_package_info['cxgb4vf']['available'] = 0
		chelsio_package_info['rdma-block-device']['available'] = 0
		if conf_hfilter :
			chelsio_package_info['cxgb4toe']['available'] = 0
			chelsio_package_info['bonding']['available'] = 0
	if conf_rdma_perf or conf_memfree :
		chelsio_stor_package_info['disable']['available'] = 0
                chelsio_bypass_package_info['disable']['available'] = 0
                chelsio_udpso_package_info['disable']['available'] = 0
                chelsio_wdtoe_package_info['disable']['available'] = 0
		chelsio_package_info['sniffer']['available'] = 0
                chelsio_package_info['cxgb4vf']['available'] = 0
                chelsio_package_info['bonding']['available'] = 0
	if conf_iscsi_perf :
                chelsio_package_info['sniffer']['available'] = 0
                chelsio_package_info['chiwarp']['available'] = 0
                chelsio_package_info['libcxgb4']['available'] = 0
                chelsio_package_info['libcxgb4-devel']['available'] = 0
                chelsio_package_info['libcxgb4_udp']['available'] = 0
                chelsio_package_info['libcxgb4_sock']['available'] = 0
                chelsio_package_info['libcxgb4_udp_debug']['available'] = 0
                chelsio_package_info['libcxgb4_sock_debug']['available'] = 0
                chelsio_package_info['libcxgb4-debuginfo']['available'] = 0
                chelsio_bypass_package_info['disable']['available'] = 0
                chelsio_udpso_package_info['disable']['available'] = 0
                chelsio_wdtoe_package_info['disable']['available'] = 0
                chelsio_package_info['cxgb4vf']['available'] = 0
                chelsio_package_info['bonding']['available'] = 1
		chelsio_stor_package_info['chiscsi']['available'] = 1
		chelsio_stor_package_info['cxgb4i']['available'] = 1
                chelsio_stor_package_info['csiostor-initiator']['available'] = 0
                chelsio_stor_package_info['csiostor-target']['available'] = 0
		chelsio_package_info['rdma-block-device']['available'] = 0
	if conf_tgt:
		chelsio_stor_package_info['csiostor-initiator']['available'] = 0
		chelsio_bypass_package_info['disable']['available'] = 0
		chelsio_stor_package_info['csiostor-target']['available'] = 1
		chelsio_udpso_package_info['disable']['available'] = 0
	        chelsio_wdtoe_package_info['disable']['available'] = 0
		chelsio_package_info['cxgb4vf']['available'] = 0
	if conf_udpso:
		chelsio_udpso_package_info['cxgb4toe']['available'] = 1
		chelsio_udpso_package_info['bonding']['available'] = 1
		chelsio_udpso_package_info['chelsio-utils']['available'] = 1
		chelsio_udpso_package_info['disable']['available'] = 1
		chelsio_bypass_package_info['disable']['available'] = 0
		chelsio_stor_package_info['disable']['available'] = 0
	        chelsio_wdtoe_package_info['disable']['available'] = 0
		chelsio_package_info['rdma-block-device']['available'] = 0
		chelsio_package_info['cxgb4vf']['available'] = 0
		ofed = False

	"""
	   Disable availability based on architecture.
	"""
	if arch.find('ppc') != -1 :
	        chelsio_package_info['sniffer']['available'] = 0
	        chelsio_package_info['libcxgb4_udp']['available'] = 0
		chelsio_package_info['libcxgb4_sock']['available'] = 0
	        chelsio_package_info['libcxgb4_udp_debug']['available'] = 0
		chelsio_package_info['libcxgb4_sock_debug']['available'] = 0
	        chelsio_package_info['libcxgb4-debuginfo']['available'] = 0
		chelsio_package_info['cxgb4vf']['available'] = 0
	        chelsio_package_info['bonding']['available'] = 0
		chelsio_stor_package_info['csiostor-initiator']['available'] = 0
	        chelsio_stor_package_info['csiostor-target']['available'] = 0
		chelsio_package_info['rdma-block-device']['available'] = 0
		
	"""
	   Disable availablity of packages on the basis of platform."
	"""
	if dist not in ["rhel7u1", "rhel7u2", "sles12", "sles12sp1"] :
		chelsio_package_info['rdma-block-device']['available'] = 0

	if not fcoe_support:
		chelsio_stor_package_info['csiostor-initiator']['available'] = 0
	if not fcoe_tgt_support:
		chelsio_stor_package_info['csiostor-target']['available'] = 0
	if not bypass_support:
		chelsio_bypass_package_info['disable']['available'] = 0
	if not wdtoe_support:
		chelsio_wdtoe_package_info['disable']['available'] = 0
	
	"""Disable iWARP on unsupported."""
	#nothing to do here.
	
	"""Disable iSCSI Target on unsupported."""
	#nothing to do here
	
	"""Disable iSCSI init on unsupported."""
	if chelsio_stor_package_info['cxgb4i']['available'] == 1 :
		if checkOpenssl():
			chelsio_stor_package_info['cxgb4i']['available'] = 0
	
	"""Disable bonding on unsupported."""
	#nothing to do here
	
	"""Disable ipv6  on unsupported.
	if dist == 'sles11sp2' or dist == 'sles11' or dist == 'rhel5u4' \
		or dist == 'rhel5u3':
		chelsio_package_info['ipv6']['available'] = 0
	"""
	"""
	   Disable availablity on the basis of installation choice.
	"""
	if nic_toe:
		chelsio_stor_package_info['disable']['available'] = 0
		chelsio_bypass_package_info['disable']['available'] = 0
	        chelsio_wdtoe_package_info['disable']['available'] = 0
		for package in [ 'cxgb4vf', 'chiwarp', 'bonding', 'libcxgb4', \
				'libcxgb4-debuginfo', 'libcxgb4-devel', 'libcxgb4_udp',\
				'libcxgb4_sock', 'sniffer',\
				'libcxgb4_sock_debug','libcxgb4_udp_debug', 'rdma-block-device']:
			chelsio_package_info[package]['available'] = 0
	if ofed:
		inbox = False
	if bypass:
		chelsio_stor_package_info['disable']['available'] = 0
                chelsio_package_info['disable']['available'] = 0
		chelsio_bypass_package_info['disable']['available'] = 1
		chelsio_wdtoe_package_info['disable']['available'] = 0
	if wd:
	        chelsio_wdtoe_package_info['disable']['available'] = 1
		if not wdtoe_support:
			chelsio_wdtoe_package_info['cxgb4wdtoe']['available'] = 0
			chelsio_wdtoe_package_info['libwdtoe']['available'] = 0
		chelsio_stor_package_info['disable']['available'] = 0
                chelsio_package_info['disable']['available'] = 0
                chelsio_bypass_package_info['disable']['available'] = 0
	if target:
		chelsio_stor_package_info['csiostor-initiator']['available'] = 0
		chelsio_wdtoe_package_info['disable']['available'] = 0

def uninstall():
	print "Uninstalling previously installed packages (if any)"
	uninstall_script = os.getcwd() + '/uninstall.py'
	if ofed :
		ret = os.system('python %s ofed'%(uninstall_script))
	else:
		ret = os.system('python %s inbox'%(uninstall_script))
	if ret != 0:
		print "Resolve the above errors manually and restart the installation"
		sys.exit(1)

def install_deps():
	global kernel_build_drv_rpm
	global debug
	to_install = []
	libibverbs_ver = "1"
	librdmacm_ver = "1"
	for package in [ "libibverbs", "libibverbs1", "libibverbs-runtime" ,"libibverbs-devel", "libibverbs-devel-static", \
			 "libibverbs-utils", "libibverbs-debuginfo", "librdmacm", "librdmacm1", \
			 "librdmacm-devel", "librdmacm-debuginfo", "librdmacm-utils", "perftest"] :
		sts,out = shell('rpm -q ' + package)
		if sts != 0:
			to_install.append(package)
		elif debug:
			print 'package : %s installed'%(package)
	if debug :
		print 'Installing dependencies ',to_install
	content_kernel_build_drv_rpm = os.listdir(kernel_build_drv_rpm)
	if debug:
        	print 'deps content :',content_kernel_build_drv_rpm
	content_kernel_build_drv_rpm = os.listdir(kernel_build_drv_rpm)
	for package in to_install:
		full_pack_name = None
		for i in content_kernel_build_drv_rpm:
			if i.find('ibverbs') != -1:
	                        if re.search('^' + package + '-' + libibverbs_ver,i) != None:
        	                        full_pack_name=i
			elif i.find('rdmacm') != -1:
	                        if re.search('^' + package + '-' + librdmacm_ver,i) != None:
        	                        full_pack_name=i
			else :
				if re.search('^' + package + '-',i) != None:
                                        full_pack_name=i
		if full_pack_name != None:
			path_to_pack = kernel_build_drv_rpm + os.sep + full_pack_name
			inst_cmd = 'rpm --nodeps -ivh ' + path_to_pack
			sts,out = commands.getstatusoutput(inst_cmd)

def install_um():
	global config_dir
	global DISTRO
	global debug
	um_dir=config_dir + os.sep + "um"
	um_rpm_dir = um_dir + os.sep + DISTRO
	if DISTRO == "RHEL6.6":
                for rpm in ["sqlite", "db4-cxx", "db4-devel", "expat-devel", "cyrus-sasl-devel", "openldap", "openldap-devel", \
				"apr", "apr-devel", "apr-util", "apr-util-devel", "apr-util-ldap", "mailcap", "httpd", \
				"mod_python", "python-simplejson", "mod_ssl", "dbus", "NetworkManager-glib", "boost-python", \
				"httpd-devel"] :
			cmd = "rpm -q " + rpm;
                        sts,out = commands.getstatusoutput(cmd)
                        if sts != 0:
                                cmd = "rpm -ivh " + um_rpm_dir + os.sep + rpm + "*"
                                print "\nInstalling Package : %s "%(rpm)
                                handler = open(log_file,'a')
                                handler.writelines("\nInstalling package : %s\n"%(rpm))
                                sts,out = commands.getstatusoutput(cmd)
                                print out 
                                if sts != 0:
                                        depserr = "\nERROR : UM Installation Failed\nPlease Resolve Above Dependencies Manually and Restart the Installation\n"
                                        print FAIL + depserr + RESET
                                        out = out + depserr
                                        handler.writelines(out + '\n')
                                        sys.exit(1)
                                handler.writelines(out + '\n')
                                handler.close()
		for rpm in [ "chelsio-uwire_mgmt-agent-rhel6u6", "chelsio-uwire_mgmt-client-rhel6u6",\
			     "chelsio-uwire_mgmt-station-rhel6u6"] :
			cmd = "rpm -q " + rpm +"-"+UM_VERSION
                        sts,out = commands.getstatusoutput(cmd)
			if sts != 0:
				cmd = "rpm -q " + rpm
				sts,out = commands.getstatusoutput(cmd)
				if sts != 0:
					cmd = "rpm -ivh " + um_rpm_dir + os.sep + rpm + "*"
					print "\nInstalling Package : %s "%(rpm)
					handler = open(log_file,'a')
					handler.writelines("\nInstalling package : %s\n"%(rpm))
					sts,out = commands.getstatusoutput(cmd)
					print out
					if sts != 0:
						depserr = "\nERROR : UM Installation Failed\nPlease Resolve " + \
								"Above Dependencies Manually and Restart the Installation\n"
						print FAIL + depserr + RESET
						out = out + depserr
						handler.writelines(out + '\n')
						sys.exit(1)
					handler.writelines(out + '\n')
					handler.close()
				else :
					cmd = "rpm -Uvh " + um_rpm_dir + os.sep + rpm + "*"
	                                print "\nUpgrading Package : %s "%(rpm)
		                        handler = open(log_file,'a')
			                handler.writelines("\nUpgrading package : %s\n"%(rpm))
				        sts,out = commands.getstatusoutput(cmd)
	                                print out
		                        if sts != 0:
			                        depserr = "\nERROR : UM Upgrade Failed\n"
				                #print FAIL + depserr + RESET
					        out = out + depserr
						handler.writelines(out + '\n')
	                                handler.writelines(out + '\n')
		                        handler.close()
			else:
				print "Latest Version of %s already present"%(rpm) 
		if os.path.isfile("/etc/httpd/conf/httpd.conf"):
			cmd = "mv -f /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd_bak"
			sts,out = commands.getstatusoutput(cmd)
		cmd = "cp -f %s/httpd_conf/httpd.conf /etc/httpd/conf/httpd.conf"%(um_rpm_dir)
		sts,out = commands.getstatusoutput(cmd)
	elif DISTRO == "SLES11.3":
		for rpm in [ "sqlite3", "libapr1", "libapr-util1", "apache2-utils-2.2.12", "NetworkManager-glib" ] :
			cmd = "rpm -q " + rpm;
                        sts,out = commands.getstatusoutput(cmd)
			if sts != 0:
				cmd = "rpm -ivh " + um_rpm_dir + os.sep + rpm + "*"
				sts,out = commands.getstatusoutput(cmd)
				if sts != 0:
					depserr = "\nERROR : UM Installation Failed\nPlease Resolve Above Dependencies Manually and Restart the Installation\n"
					print FAIL + depserr + RESET
					handler = open(log_file,'a')
					out = out + depserr
					handler.writelines(out + '\n')
					handler.close()
					sys.exit(1)
		cmd = "rpm -q apache2-2.2.12"
                sts,out = commands.getstatusoutput(cmd)
		if sts != 0:
			cmd = "rpm -ivh " + um_rpm_dir + os.sep + "apache2-2.2.12* " + um_rpm_dir + os.sep + "apache2-prefork*"
			sts,out = commands.getstatusoutput(cmd)
			if sts != 0:
                                        depserr = "\nERROR : UM Installation Failed\nPlease Resolve Above Dependencies Manually and Restart the Installation\n"
                                        print FAIL + depserr + RESET
                                        handler = open(log_file,'a')
                                        out = out + depserr
                                        handler.writelines(out + '\n')
                                        handler.close()
                                        sys.exit(1)
		cmd = "rpm -q apache2-mod_python"
                sts,out = commands.getstatusoutput(cmd)
		if sts != 0:
			cmd = "rpm -ivh " + um_rpm_dir + os.sep + "apache2-mod_python*" 
			sts,out = commands.getstatusoutput(cmd)
			if sts != 0:
                                        depserr = "\nERROR : UM Installation Failed\nPlease Resolve Above Dependencies Manually and Restart the Installation\n"
                                        print FAIL + depserr + RESET
                                        handler = open(log_file,'a')
                                        out = out + depserr
                                        handler.writelines(out + '\n')
                                        handler.close()
                                        sys.exit(1)

		for rpm in [ "chelsio-uwire_mgmt-agent-sles11sp3", "chelsio-uwire_mgmt-client-sles11sp3",\
                             "chelsio-uwire_mgmt-station-sles11sp3"] :
                        cmd = "rpm -q " + rpm +"-"+UM_VERSION
                        sts,out = commands.getstatusoutput(cmd)
                        if sts != 0:
                                cmd = "rpm -q " + rpm
                                sts,out = commands.getstatusoutput(cmd)
                                if sts != 0:
                                        cmd = "rpm -ivh " + um_rpm_dir + os.sep + rpm + "*"
                                        print "\nInstalling Package : %s "%(rpm)
                                        handler = open(log_file,'a')
                                        handler.writelines("\nInstalling package : %s\n"%(rpm))
                                        sts,out = commands.getstatusoutput(cmd)
                                        print out
                                        if sts != 0:
                                                depserr = "\nERROR : UM Installation Failed\nPlease Resolve " + \
                                                                "Above Dependencies Manually and Restart the Installation\n"
                                                print FAIL + depserr + RESET
                                                out = out + depserr
                                                handler.writelines(out + '\n')
                                                sys.exit(1)
                                        handler.writelines(out + '\n')
                                        handler.close()
                                else :
                                        cmd = "rpm -Uvh " + um_rpm_dir + os.sep + rpm + "*"
                                        print "\nUpgrading Package : %s "%(rpm)
                                        handler = open(log_file,'a')
                                        handler.writelines("\nUpgrading package : %s\n"%(rpm))
                                        sts,out = commands.getstatusoutput(cmd)
                                        print out
                                        if sts != 0:
                                                depserr = "\nERROR : UM Upgrade Failed\n"
                                                #print FAIL + depserr + RESET
                                                out = out + depserr
                                                handler.writelines(out + '\n')
                                        handler.writelines(out + '\n')
                                        handler.close()
                        else:
                                print "Latest Version of %s already present"%(rpm)

		for file in [ "httpd.conf", "default-server.conf", "ssl-global.conf", "listen.conf" ]:
			if os.path.isfile("/etc/apache2/%s"%(file)):
				cmd = "mv -f /etc/apache2/%s /etc/apache2/bak_%s"%(file,file)
			cmd = "cp -f %s/apache_conf/%s /etc/apache2/%s"%(um_rpm_dir,file,file)
			sts,out = commands.getstatusoutput(cmd)
		if os.path.isfile("/etc/apache2/vhosts.d/vhost-ssl.conf"):
			cmd = "mv -f /etc/apache2/vhosts.d/vhost-ssl.conf /etc/apache2/vhosts.d/bak_vhost-ssl.conf"
			sts,out = commands.getstatusoutput(cmd)
		if os.path.isfile("/etc/apache2/sysconfig.d/loadmodule.conf"):
			cmd = "mv -f /etc/apache2/sysconfig.d/loadmodule.conf /etc/apache2/sysconfig.d/bak_loadmodule.conf"
			sts,out = commands.getstatusoutput(cmd)

def install_ofed():
	global debug
	global ofed_rpm 
	content_ofed_rpm = os.listdir(ofed_rpm)
	os.system('clear')
	show_heading("Chelsio Unified Wire 2.12.0.3 Installer\nInstalling OFED:")
	if debug:
		print 'content_ofed_rpm directory content :',content_ofed_rpm
	if dist in ["rhel6u5", "rhel6u6", "rhel6u7", "rhel7u1", "rhel7u2", "sles11sp3","sles11sp4", "sles12", "sles12sp1"] :
		ofed_packages = ofed_packages_3u5
	else :
		ofed_packages = ofed_packages_1
	for package in ofed_packages:
		full_pack_name = None
                for i in content_ofed_rpm:
			if re.search('^' + package + '-\d',i) != None:
                        	full_pack_name=i
		if full_pack_name != None:
	        	path_to_pack = ofed_rpm + os.sep + full_pack_name
                        inst_cmd = 'rpm -ivh ' + path_to_pack
        	        print "\nInstalling Package : %s"%(package)
			handler = open(log_file,'a')
			handler.writelines("\nInstalling package : %s\n"%(package))
			sts,out = commands.getstatusoutput(inst_cmd)
			#sts = os.system(inst_cmd)
			print out
			handler.writelines(out + '\n')
			handler.close()
			if sts != 0 : 
				print "Installing %s package failed"%(package)
				print "cmd output : %s"%(out)
				sys.exit(1)
		elif debug:
			print "Package : %s not found"%(package)

def start_install():
	global chelsio_package
        global chelsio_stor_package
        global chelsio_bypass_package
        global chelsio_udpso_package
        global chelsio_package_info
        global chelsio_stor_package_info
        global chelsio_bypass_package_info
        global chelsio_udpso_package_info
        global conf_uwire
        global conf_ll
        global conf_hctoe
        global conf_hcrdma
        global conf_tgt
	global conf_edc_only 
	global conf_rdma_perf
        global conf_iscsi_perf
	global conf_memfree
	global ofed_rpm 
	global ofed_build_drv_rpm 
	global kernel_build_drv_rpm 
        global DISTRO
        global dist
        global fcoe_support
        global fcoe_tgt_support
        global bypass_support
        global udpso_support
        global inbox
        global ofed
        global nic_toe
        global target
        global bypass
        global udpso
	global log_file 
	global debug
	os.system('clear')
	show_heading("Chelsio Unified Wire 2.12.0.3 Installer\nStarting Installation:")
	"""First Check for bypass."""
	if chelsio_bypass_package_info['disable']['available'] == 1 :
		if ofed:
			content_kernel_build_drv_rpm = os.listdir(ofed_build_drv_rpm)
		else:
			content_kernel_build_drv_rpm = os.listdir(kernel_build_drv_rpm)
		if debug:
			print 'bypass content :',content_kernel_build_drv_rpm
		for package in chelsio_bypass_package:
			if chelsio_bypass_package_info[package]['available'] == 1 :
				full_pack_name = None
				for i in content_kernel_build_drv_rpm:
					if re.search('^' + package + '-' + version,i) != None:
						full_pack_name=i
				if full_pack_name != None:
					if ofed:
						path_to_pack = ofed_build_drv_rpm + os.sep + full_pack_name
					else:
						path_to_pack = kernel_build_drv_rpm + os.sep + full_pack_name
					inst_cmd = 'rpm -ivh ' +  path_to_pack
					print "\nInstalling Package : %s "%(package)
					handler = open(log_file,'a')
					handler.writelines("\nInstalling package : %s\n"%(package))
					sts,out = commands.getstatusoutput(inst_cmd)
					print out
					handler.writelines(out + '\n')
					handler.close()
					if sts != 0 : 
						print "Installing %s package failed"%(package)
						print "cmd output : %s"%(out)
						sys.exit(1)
				elif debug:
	                                print "Package : %s not found"%(package)
	if chelsio_wdtoe_package_info['disable']['available'] == 1 :
		install_deps()
                if ofed:
                        content_kernel_build_drv_rpm = os.listdir(ofed_build_drv_rpm)
                else:
                        content_kernel_build_drv_rpm = os.listdir(kernel_build_drv_rpm)
                if debug:
                        print 'wdtoe content :',content_kernel_build_drv_rpm
                for package in chelsio_wdtoe_package:
                        if chelsio_wdtoe_package_info[package]['available'] == 1 :
                                full_pack_name = None
                                for i in content_kernel_build_drv_rpm:
                                        if re.search('^' + package + '-' + version,i) != None:
                                                full_pack_name=i
                                if full_pack_name != None:
                                        if ofed:
                                                path_to_pack = ofed_build_drv_rpm + os.sep + full_pack_name
                                        else:
                                                path_to_pack = kernel_build_drv_rpm + os.sep + full_pack_name
                                        if package == 'cxgb4wdtoe':
                                                inst_cmd = 'rpm -ivh --force ' +  path_to_pack
                                        else:
                                                inst_cmd = 'rpm -ivh ' +  path_to_pack
                                        print "\nInstalling Package : %s "%(package)
                                        handler = open(log_file,'a')
                                        handler.writelines("\nInstalling package : %s\n"%(package))
                                        sts,out = commands.getstatusoutput(inst_cmd)
                                        print out
                                        handler.writelines(out + '\n')
                                        handler.close()
                                        if sts != 0 :
                                                print "Installing %s package failed"%(package)
                                                print "cmd output : %s"%(out)
                                                sys.exit(1)
                                elif debug:
                                        print "Package : %s not found"%(package)
	if chelsio_udpso_package_info['disable']['available'] == 1 :
                content_kernel_build_drv_rpm = os.listdir(kernel_build_drv_rpm)
                if debug:
                        print 'udpso  content :',content_kernel_build_drv_rpm
                for package in chelsio_udpso_package:
                        if chelsio_udpso_package_info[package]['available'] == 1 :
                                full_pack_name = None
                                for i in content_kernel_build_drv_rpm:
                                        if re.search('^' + package + '-' + version,i) != None:
                                                full_pack_name=i
                                if full_pack_name != None:
                                        path_to_pack = kernel_build_drv_rpm + os.sep + full_pack_name
                                        inst_cmd = 'rpm -ivh ' +  path_to_pack
                                        print "\nInstalling Package : %s "%(package)
                                        handler = open(log_file,'a')
                                        handler.writelines("\nInstalling package : %s\n"%(package))
                                        sts,out = commands.getstatusoutput(inst_cmd)
                                        print out
                                        handler.writelines(out + '\n')
                                        handler.close()
                                        if sts != 0 :
                                                print "Installing %s package failed"%(package)
                                                print "cmd output : %s"%(out)
                                                sys.exit(1)
                                elif debug:
                                        print "Package : %s not found"%(package)
	"""Check for OFED"""
	if ofed and chelsio_package_info['disable']['available'] == 1 :
		'''if conf_ll or conf_edc_only:
                        chelsio_package.remove('cxgb4toe')
                        chelsio_package.remove('bonding')'''
		content_ofed_build_drv_rpm = os.listdir(ofed_build_drv_rpm)
		if debug:
			print 'content_ofed_build_drv_rpm directory content :',content_ofed_build_drv_rpm
		for package in chelsio_package:
			if chelsio_package_info[package]['available'] == 1 :
				full_pack_name = None
                                for i in content_ofed_build_drv_rpm:
					if re.search('^' + package + '-' + version,i) != None:
                                                full_pack_name=i
				if full_pack_name != None:
                                        path_to_pack = ofed_build_drv_rpm + os.sep + full_pack_name
                                        inst_cmd = 'rpm -ivh ' + path_to_pack
                                        print "\nInstalling Package : %s"%(package)
					handler = open(log_file,'a')
					handler.writelines("\nInstalling package : %s\n"%(package))
					sts,out = commands.getstatusoutput(inst_cmd)
					print out
					handler.writelines(out + '\n')
					handler.close()
					if sts != 0 : 
						print "Installing %s package failed"%(package)
						print "cmd output : %s"%(out)
						sys.exit(1)
				elif debug:
                                        print "Package : %s not found"%(package)
	elif inbox and chelsio_package_info['disable']['available'] == 1 :
		'''if conf_ll  or conf_edc_only:
			chelsio_package.remove('cxgb4toe')
			chelsio_package.remove('bonding')'''
		install_deps()
		content_kernel_build_drv_rpm = os.listdir(kernel_build_drv_rpm)
		if debug:
			print 'content_kernel_build_drv_rpm directory content :',content_kernel_build_drv_rpm
		for package in chelsio_package:
                        if chelsio_package_info[package]['available'] == 1 :
                                full_pack_name = None
                                for i in content_kernel_build_drv_rpm:
					if re.search('^' + package + '-' + version,i) != None:
                                                full_pack_name=i
                                if full_pack_name != None:
                                        path_to_pack = kernel_build_drv_rpm + os.sep + full_pack_name
                                        inst_cmd = 'rpm -ivh ' + path_to_pack
                                        print "\nInstalling Package : %s"%(package)
					handler = open(log_file,'a')
					handler.writelines("\nInstalling package : %s\n"%(package))
					sts,out = commands.getstatusoutput(inst_cmd)
					print out
					handler.writelines(out + '\n')
					handler.close()
					if sts != 0 : 
						print "Installing %s package failed"%(package)
						print "cmd output : %s"%(out)
						sys.exit(1)
				elif debug:
                                        print "Package : %s not found"%(package)
	elif nic_toe and chelsio_package_info['disable']['available'] == 1 :
		content_kernel_build_drv_rpm = os.listdir(kernel_build_drv_rpm)
		nic_pack_toe = ["chelsio-series4-firmware", "cxgb4", "cxgb4toe", "chelsio-utils"]
		for package in nic_pack_toe:
			full_pack_name = None
                        for i in content_kernel_build_drv_rpm:
				if re.search('^' + package + '-' + version,i) != None:
                                        full_pack_name=i
                        if full_pack_name != None:
                                path_to_pack = kernel_build_drv_rpm + os.sep + full_pack_name
                                inst_cmd = 'rpm -ivh ' + path_to_pack
                                print "\nInstalling Package : %s"%(package)
				handler = open(log_file,'a')
				handler.writelines("\nInstalling package : %s\n"%(package))
				sts,out = commands.getstatusoutput(inst_cmd)
				print out
				handler.writelines(out + '\n')
				handler.close()
				if sts != 0 : 
					print "Installing %s package failed"%(package)
					print "cmd output : %s"%(out)
					sys.exit(1)
			elif debug:
                                print "Package : %s not found"%(package)

	if chelsio_stor_package_info['disable']['available'] == 1 :
		content_kernel_build_drv_rpm = os.listdir(kernel_build_drv_rpm)
		for package in chelsio_stor_package:
			 if chelsio_stor_package_info[package]['available'] == 1 :
                                full_pack_name = None
                                for i in content_kernel_build_drv_rpm:
					if re.search('^' + package + '-' + version,i) != None:
                                                full_pack_name=i
                                if full_pack_name != None:
                                        path_to_pack = kernel_build_drv_rpm + os.sep + full_pack_name
                                        inst_cmd = 'rpm -ivh ' + path_to_pack
                                        print "\nInstalling Package : %s"%(package)
					handler = open(log_file,'a')
					handler.writelines("\nInstalling package : %s\n"%(package))
					sts,out = commands.getstatusoutput(inst_cmd)
					print out
					handler.writelines(out + '\n')
					handler.close()
					if sts != 0 : 
						print "Installing %s package failed"%(package)
						print "cmd output : %s"%(out)
						sys.exit(1)
				elif debug:
                                        print "Package : %s not found"%(package)
def check_install():
        global inbox
        global ofed
        global nic_toe
        global target
        global bypass
	global debug
	global conf_uwire
        global conf_ll
        global conf_hctoe
        global conf_hcrdma
        global conf_tgt
	global conf_edc_only
	global conf_rdma_perf
        global conf_iscsi_perf
	global conf_memfree
        global fcoe_support
	
	expected_ver="2.12.0.3"
	supported_libs = ["libcxgb4", "libcxgb4_sock", "libcxgb4_udp"]
	supported_wd_tools = [ "wd_tcpdump", "wd_tcpdump_trace", "wd_sniffer", "wdload" ]
	supported_tools = [ "chsetup", "chstatus", "cop", "cxgbtool" ]
	
	if conf_hctoe or conf_udpso or conf_hfilter:
        	supported_drivers = ["cxgb4", "toecore", "t4_tom"]
		if conf_hfilter:
			supported_drivers = ["cxgb4"]
		supported_libs  = []
	elif conf_hcrdma or conf_ll or conf_edc_only or conf_hcll:
	        supported_drivers = [ "cxgb4", "toecore", "t4_tom", "cxgb4vf", "iw_cxgb4" ]
	elif conf_uwire:
		if fcoe_support:
		        supported_drivers= [ "cxgb4", "toecore", "t4_tom", "iw_cxgb4", "cxgb4vf", "csiostor", "chiscsi", "chiscsi_t4", "cxgb4i" ]
		else:
		        supported_drivers= [ "cxgb4", "toecore", "t4_tom", "iw_cxgb4", "cxgb4vf", "chiscsi", "chiscsi_t4", "cxgb4i" ]
	elif conf_tgt:
	        supported_drivers= [  "cxgb4", "toecore", "t4_tom", "iw_cxgb4", "csiostor", "csioscst", "chiscsi", "chiscsi_t4", "cxgb4i" ]
	
	for drv in supported_drivers:
		vers=shell('modinfo %s | grep ^version | awk -F":" \'{print $2}\' | sed \'s/  *//g\''%(drv))[1]
		if vers != expected_ver:
	        	print "Error %s version mismatch."%(drv)
	        	print "Expected : " + expected_ver + " Got : " + vers 
	        	sys.exit(1)
		elif debug:
			print "Checking %s version"%(drv)
			print "Expected : " + expected_ver + " Got : " + vers +"\n"
	if ofed or inbox:
		for lib in  supported_libs:
        		vers=shell('rpm -qf /usr/lib64/%s.so | awk -F"-" \'{print $2}\''%(lib))[1]
        		if vers != expected_ver:
				print"Error %s version mismatch."%(lib)
		        	print "Expected : %s Got : %s "%(expected_ver,vers)
				sys.exit(1)
			elif debug:
				print "Checking %s version"%(drv)
				print "Expected : " + expected_ver + " Got : " + vers +"\n"
		for tool in  supported_wd_tools:
			if not os.path.isfile('/sbin/' + tool):
				print "Error wd tool %s not found."%(tool)
			        sys.exit(1)
			elif debug:
				print "Found wd_tool : %s"%(tool)

	for tool in  supported_tools:
		if not os.path.isfile('/sbin/' + tool):
			print "Error %s not found."%(tool)
		        sys.exit(1)
		elif debug:
			print "Found tool : %s"%(tool)


def prompt_end():
	global conf_hcrdma
	global conf_hctoe
	os.system('clear')
	show_heading("Chelsio Unified Wire 2.12.0.3 Installer\n")
	print "Installation completed successfully, installation logs can be found in %s file"%(log_file)
	print "Kindly reboot your machine/host for the changes to take effect." 

def indent(rows, hasHeader=False, headerChar='-', delim=' | ', justify='left',
           separateRows=True, prefix='', postfix='', wrapfunc=lambda x:x):
	# closure for breaking logical rows to physical, using wrapfunc
	def rowWrapper(row):
		newRows = [wrapfunc(item).split('\n') for item in row]
		return [[substr or '' for substr in item] for item in map(None,*newRows)]
	# break each logical row into one or more physical ones
	logicalRows = [rowWrapper(row) for row in rows]
	# columns of physical rows
	columns = map(None,*reduce(operator.add,logicalRows))
	# get the maximum of each column by the string length of its items
	maxWidths = [max([len(str(item)) for item in column]) for column in columns]
	rowSeparator = headerChar * (len(prefix) + len(postfix) + sum(maxWidths) + \
                             len(delim)*(len(maxWidths)-1))
	# select the appropriate justify method
	justify = {'center':str.center, 'right':str.rjust, 'left':str.ljust}[justify.lower()]
	output=cStringIO.StringIO()
	print >> output, rowSeparator
	for physicalRows in logicalRows:
		for row in physicalRows:
			print >> output, \
			prefix \
			+ delim.join([justify(str(item),width) for (item,width) in zip(row,maxWidths)]) \
			+ postfix
		print >> output, rowSeparator
	return output.getvalue()


def wrap_always(text, width):
	"""A simple word-wrap function that wraps text on exactly width characters.
	It doesn't split the text in words."""
	return '\n'.join([ text[width*i:width*(i+1)] \
		for i in xrange(int(math.ceil(1.*len(text)/width))) ])

def Usage():
	global install_dict
	global config_dict
	global ofed_not_supported_on_platform
	print "\nUSAGE: python install.py -c <CONF> -i <INSTALL> "
        print "\nOptions: "
        print "\t-c, --config       T5 / T4 configuration selection."
	print "\t		    Available config opts : %s"%(','.join(config_dict.keys()))
        print "\t-i, --install      Select Installation mode."
	print "\t		    Available Installation modes : %s"%(', '.join(install_dict.keys()))
	if not ofed_not_supported_on_platform:
	        print "\t-o, --ofed         Install OFED on machine."
	print "\t-C, --cluster      Cluster Installation"
	print "\t-m, --machinefile  Specify the machine file   "
	print "\t-u, --uninst       Uninstall Drivers in Cluster machines(Use with cluster deployment(-C) ) "
        print "\t-h, --help         Displays this information."

def parse_args(cmdArgv):
	global conf_uwire 
	global conf_ll
	global conf_hcrdma
	global conf_tgt
	global conf_hctoe
	global conf_edc_only
	global conf_hcll
	global conf_hfilter
	global conf_rdma_perf
        global conf_iscsi_perf
	global conf_memfree
	global bypass
	global wdtoe
	global wdtoe_support
	global bypass_support
	global fcoe_support
	global fcoe_tgt_support
	global uwire_support
	global log_file
	global ofed
	global install_dict
        global config_dict
	global ofed_not_supported_on_platform
	global clusterInstall
	global machine_file
	global logDir
	global chkconfig
	global chkinstall
	global clus_install_opt
	global chkuninstall
	config = None
	config_key = None
	install = None
	install_key = None
	support_dict = \
			{ 'conf_uwire' : ['all', 'nic_toe', 'bypass','wd'],
			  'conf_tgt' : ['target'],
			  'conf_hctoe' : ['all','nic_toe'],
			  'conf_udpso' : ['udpso'],
			  'conf_hcrdma' : ['all','nic_toe'],
			  'conf_ll' : ['all','nic_toe','wd'],
			  'conf_edc_only' : ['all','nic_toe','wd'],
			  'conf_hcll' : ['all','nic_toe','wd'],
			  'conf_hfilter' : ['all'],
			  'conf_rdma_perf' : ['all'],
			  'conf_iscsi_perf' : ['all'],
			  'conf_memfree' : ['all']
			}
	
				
	try:
		if not ofed_not_supported_on_platform:
			opts, args = getopt.getopt(cmdArgv, "h:c:i:oum:C", ["help=", "config=", "install=","ofed","uninst","machinefile=","cluster"])
		else:
			opts, args = getopt.getopt(cmdArgv, "h:c:i:um:C", ["help=", "config=", "install=","uninst","machinefile=","cluster"])
	except getopt.GetoptError:
		print "Invalid Syntax"
		Usage()
		sys.exit(1)
	for opt, arg in opts:
		arg = arg.strip()
		if opt in ("-h", "--help"):
			Usage()		
			sys.exit(1)
	        elif opt in ("-c","--config"):
			if arg not in config_dict.keys():
				print "Unknown config mode %s provided.\nThe supported config modes are : %s"%(arg,','.join(config_dict.keys()))
				sys.exit(1)
			else:
				chkconfig = True
				globals()[config_dict[arg]] = True
				handler = open(log_file,'a')
				handler.writelines("T5 / T4 Configuration selection: %s\n"%(config_dict[arg]))
				handler.close()
				config = config_dict[arg]
				config_key = arg
		elif opt in ("-i", "--install"):
			if arg not in install_dict.keys():
                                print "Unknown installation option %s provided.\nThe supported installation options are : %s"%(arg,', '.join(install_dict.keys()))
                                sys.exit(1)
                        else:
                                globals()[install_dict[arg]] = True
				chkinstall = True
				handler = open(log_file,'a')
				install_dict_new[arg]=install_dict[arg]
				handler.writelines("T5 / T4 Installation selection: %s\n"%(install_dict_new[arg]))
				handler.close()
				install = install_dict[arg]
				install_key = arg
		elif opt in ("-o","--ofed") and not ofed_not_supported_on_platform:
			ofed = True
		elif opt in ("-C","--cluster") :
			clusterInstall = True
		elif opt in ("-m","--machinefile"):
			machine_file = arg
		elif opt in ("-u","--uninst"):
			chkuninstall=True
	if clusterInstall == True and machine_file == None :
                print "Install options (-m/--machinefile) should be provided for Cluster Installation"
                Usage()
                sys.exit(1)
	if clusterInstall and install == None :
		install_key = "wd"
		install = install_dict["wd"]
	elif clusterInstall and not install == None :
		clus_install_opt = install_key
	if install == None and install_key == None :
		print "Install options (-i/--install) should be provided"
		Usage()
		sys.exit(1)
	if config  == None and config_key == None:
		config = 'conf_uwire'
		config_key = 'UNIFIED_WIRE'
		globals()[config_dict['UNIFIED_WIRE']] = True
	support_list = support_dict[config]
	if install_key not in support_list:
		print "Installation option: %s is not supported with %s config mode."%(install_key,config_key)
		print "The following installation option are supported with %s config : %s"%(config_key,', '.join(support_list))
		sys.exit(1)
	if not clusterInstall :
		if not ofed and not config == "conf_hctoe":
			checkOfedOnMachine()
	if config == "conf_hctoe" and ofed :
		print FAIL + "\"-o\" OFED options cannot be used with HCTOE config file" + RESET
		sys.exit(1)


def copy_config():
	global conf_uwire
        global conf_ll
        global conf_hcrdma
        global conf_tgt
        global conf_hctoe
	global conf_edc_only
	global conf_rdma_perf
        global conf_iscsi_perf
	global conf_memfree
	global conf_hcll
	global conf_hfilter
	global config_dir
	if conf_uwire:
		os.system('install -m 644 %s/t4-config.txt /lib/firmware/cxgb4'%(config_dir))
                os.system('install -m 644 %s/t5-config.txt /lib/firmware/cxgb4'%(config_dir))
	elif conf_ll:
		os.system('install -m 644 %s/t4-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'low_latency_config'))
                os.system('install -m 644 %s/t5-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'low_latency_config'))
	elif conf_hcrdma:
		os.system('install -m 644 %s/t4-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'high_capacity_rdma'))
                os.system('install -m 644 %s/t5-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'high_capacity_rdma'))
	elif conf_hctoe:
		os.system('install -m 644 %s/t4-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'high_capacity_config'))
                os.system('install -m 644 %s/t5-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'high_capacity_config'))
	elif conf_tgt:
		os.system('install -m 644 %s/t4-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'fcoe_target_config'))
                os.system('install -m 644 %s/t5-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'fcoe_target_config'))
	elif conf_udpso:
		os.system('install -m 644 %s/t4-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'udp_so_config'))
                os.system('install -m 644 %s/t5-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'udp_so_config'))
	elif conf_edc_only :
		os.system('install -m 644 %s/t4-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'edc_only_config'))
                os.system('install -m 644 %s/t5-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'edc_only_config'))
	elif conf_hcll :
		os.system('install -m 644 %s/t4-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'high_capacity_wd'))
                os.system('install -m 644 %s/t5-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'high_capacity_wd'))
	elif conf_hfilter :
		os.system('install -m 644 %s/t4-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'hash_filter_config'))
		os.system('install -m 644 %s/t5-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'hash_filter_config'))
	elif conf_rdma_perf:
                os.system('install -m 644 %s/t4-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'rdma_perf_config'))
                os.system('install -m 644 %s/t5-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'rdma_perf_config'))
	elif conf_iscsi_perf :
                os.system('install -m 644 %s/t4-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'iscsi_perf_config'))
                os.system('install -m 644 %s/t5-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'iscsi_perf_config'))
	elif conf_memfree :
                os.system('install -m 644 %s/t4-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'memfree_config'))
                os.system('install -m 644 %s/t5-config.txt /lib/firmware/cxgb4'%(config_dir + os.sep + 'memfree_config'))
	os.system('install -m 644 %s/aq1202_fw.cld /lib/firmware/cxgb4'%(config_dir))
	os.system('install -m 644 %s/cubt4.bin /lib/firmware/cxgb4'%(config_dir))
	os.system('install -m 644 %s/uname_r /sbin'%(config_dir))

def checkOpenssl():
	ssl_head = "/usr/include/openssl/evp.h"
	if not os.path.isfile(ssl_head) :
		print "Open-ssl devel is needed for Chelsio ISCSI DATA Path Accelerator."
		print "Please install Open-ssl devel and restart the installation or Press 'Y' to skip ISCSI DATA Path Accelerator and continus installation"
		print "Press 'N' to exit"
		while True :
			ssl_input = raw_input("Input: ")
			if ssl_input.lower() == 'y':
				return True
				break
			elif ssl_input.lower() == 'n':
				sys.exit(1)
			else:
				print "Please enter a valid option."
	else:
		return False

def ipv6_check() :
        proc_list = []
        proc_list=os.listdir('/proc/sys/net')
        for dir in proc_list:
                if dir == 'ipv6' :
                        return 1
        return 0

def parseMachineFile():
	global machine_file
	global nodes
        readFile =  open(machine_file,'r')
        lines = readFile.readlines()
        readFile.close()
        for line in lines:
            if not line.startswith('#') or line.strip() == '':
                nodes.append(line.strip())
        if len(nodes) == 0 :
            print "Machinefile is empty, aborting the installer."
            sys.exit(-1)
        for ix in range(0,len(nodes)):
            node = nodes[ix]
            if ( ix < len(nodes) - 1 ) and node in nodes[ix+1:]:
                print "Error : Duplicate entries found in machinefile."
                sys.exit(-1)
	#print nodes

def checkSshConf():
	global nodes
        cmd = "cat /etc/ssh/sshd_config | grep MaxStartups"
        sts,out = commands.getstatusoutput(cmd)
        if sts != 0:
            return
        if out.startswith('#'):
            return
        maxStartUp = out.split()[-1]
        if int(maxStartUp) < len(nodes):
            print "Error : ssh is configured for a maximum of only %s session"%(maxStartUp)
            print "        Increase the value of MaxStartups in /etc/ssh/sshd_config to %d and restart the installation"%(len(nodes))
            sys.exit(1)

def checkNodes():
	global nodes
        err=0
        for node in nodes:
            cmd = "ping -c 3 " + node
            sts, out = commands.getstatusoutput(cmd)
            if sts != 0 :
                print "The %s machine is not reachable via ping, check the connectivity and restart the installation"%(node)
                err=1
        return err

def checkSshConn():
	global nodes
        err=0
	#print "Checking Passwordless ssh :", nodes
        for node in nodes:
            cmd = "ssh -o PasswordAuthentication=no %s ls"%(node)
            sts, out = commands.getstatusoutput(cmd)
            if sts != 0 :
                print "The password-less ssh is not setup for %s machine, setup password-less ssh and restart the installation"%(node)
                err=1
        return err

def getLogs():
	global nodes
        nodeThreadArr= []
        ix = 0
        for node in nodes:
            nodeThreadArr.append(threading.Thread(target = getLogsThread, args = (node, )))
            nodeThreadArr[ix].start()
            ix+=1
        for thread in nodeThreadArr:
            thread.join()

def parseLogs():
	global nodes
	global logDir
        print '\n---------------------------'
        print 'Deployment Result Summary'
        print '---------------------------'
        print ''
        failedNodes = []
        depsNodes = []
        for node in nodes:
            sumFile = logDir + os.sep + node + os.sep + 'Summary'
            depFile = logDir + os.sep + node + os.sep + 'deps.log'
            if os.path.isfile(sumFile):
               handler = open(sumFile,'r')
               content = handler.readlines()
               handler.close()
               for line in content:
                   if line.find('Failed') != -1:
                       failedNodes.append(node)
            if os.path.isfile(depFile):
                depsNodes.append(node)
        if len(failedNodes) == 0 and len(depsNodes) == 0:
            print "\nCluster Deployment is passed on  all the nodes."
        if len(failedNodes) != 0 :
            print "\nCluster Deployment is failed on the following nodes:"
            for node in failedNodes: print node
            print "\nThe installation logs can be found in %s directory"%(logDir + os.sep + node + os.sep + "install.log")
        if len(depsNodes) != 0 :
            print "\nCluster Deployment is failed due to dependency issues on the following nodes:"
            for node in depsNodes: print node
            print "\nThe dependencies logs can be found in %s file."%(logDir + os.sep + node + os.sep + "deps.log")

def createLogsDir():
	global logDir
	#print logDir
        if os.path.isdir(logDir):
            cmd = 'rm -rf ' + logDir
            sts, out = commands.getstatusoutput(cmd)
            if sts != 0:
                print "Removing exsisting logs directories failed, remove the logs directory and restart the installation."
                sys.exit(1)
        os.mkdir(logDir)
        for node in nodes:
            os.mkdir(logDir + os.sep + node)

def rpm_clus_deploy() :
	global nodes
	global logDir
	global cluster_file
	global arch

	parseMachineFile()
	#print "Parse"
	os.system('clear')
   	show_heading("Chelsio Unified Wire 2.12.0.3 Installer\nCluster Deployment: ")
        print "Starting Cluster Deployment. Kindly wait it may take some time."
        print "Deployment will start on following nodes : ",
        sys.stdout.flush()
        for node in nodes : print node+ ' ',
        print "\nChecking nodes connectivity ....",
        sys.stdout.flush()
	checkSshConf()
	print "\nChecking nodes connectivity ....",
        sys.stdout.flush()
	if checkNodes() != 0 :
		sys.exit(1)
	print " Passed"
        print "Checking password-less ssh across nodes ....",
       	sys.stdout.flush()
	if checkSshConn() != 0 :
		sys.exit(1)
	print "Passed"
	print "Creating Logs directories ....",
	sys.stdout.flush()
	createLogsDir()
	print "Passed"
	nodeThreadArr= []
        ix = 0
        rawPkgName="ChelsioUwire-" + version + "-" + cluster_file + "-" + arch
        pkgName="ChelsioUwire-" + version + "-" + cluster_file + "-" + arch + ".tar.gz"
        pkgDir= os.path.abspath('../.')
        currDir = os.path.abspath('.')
        cmd = "ls " + pkgDir + os.sep + pkgName
        sts, out = commands.getstatusoutput(cmd)
        if sts != 0:
            os.chdir(pkgDir)
            cmd = "tar czfm " + pkgName + '  ' + rawPkgName
            sts, out = commands.getstatusoutput(cmd)
            if sts != 0:
                print "Creating tar-ball of %s failed, aborting the installation"%(pkgDir+ os.sep + rawPkgName)
                return -1
            os.chdir(currDir)
        for node in nodes:
	    #print node
            nodeThreadArr.append(threading.Thread(target = rpmclusterDeployerThread, args = ( node,logDir)))
            nodeThreadArr[ix].start()
            ix+=1
        for thread in nodeThreadArr:
            thread.join()
        return 0

def rpmclusterDeployerThread(nodew,logDir) :
	global clus_install_opt
	global chkuninstall
	global cluster_file
	global arch
	#uninstall = False
	rawPkgName="ChelsioUwire-" + version + "-" + cluster_file + "-" + arch
        pkgName="ChelsioUwire-" + version + "-" + cluster_file + "-" + arch + ".tar.gz"
    	pkgDir= os.path.abspath('../.')
    	absPkgPath= pkgDir + os.sep + rawPkgName
    	shscript= os.path.abspath('.') + os.sep + "scripts" + os.sep + "cp_rpm_cluster_install.sh"
	#print clus_config_file
    	if chkuninstall:
		if ofed :
			cmd = "sh %s %s %s %s %s %s %s %s"%(shscript,nodew,"no",absPkgPath,rawPkgName, logDir + os.sep + nodew, clus_config_file, "yes")
		else :
	        	cmd = "sh %s %s %s %s %s %s %s %s"%(shscript,nodew,"no",absPkgPath,rawPkgName, logDir + os.sep + nodew, clus_config_file, "no")
    	else:
        	if ofed:
                	cmd = "sh %s %s %s %s %s %s %s %s %s"%(shscript,nodew,"yes",absPkgPath,rawPkgName, logDir + os.sep + nodew, clus_config_file, "yes", clus_install_opt)
        	else:
                	cmd = "sh %s %s %s %s %s %s %s %s %s"%(shscript,nodew,"yes",absPkgPath,rawPkgName, logDir + os.sep + nodew, clus_config_file, "no", clus_install_opt)
    	sts,out = commands.getstatusoutput(cmd)

def getLogsThread(node):
    global cluster_file
    global arch
    rawPkgName="ChelsioUwire-" + version + "-" + cluster_file + "-" + arch
    pkgName="ChelsioUwire-" + version + "-" + cluster_file + "-" + arch + ".tar.gz"
    pkgDir= os.path.abspath('../.')
    absPkgPath= pkgDir + os.sep + rawPkgName
    shscript= os.path.abspath('.') + os.sep + "scripts" + os.sep + "get_logs.sh"
    if uninstall:
        cmd = "sh %s %s %s %s %s "%(shscript,node,absPkgPath,rawPkgName, logDir + os.sep + node)
    else:
        cmd = "sh %s %s %s %s %s "%(shscript,node,absPkgPath,rawPkgName,logDir + os.sep + node)
    sts,out = commands.getstatusoutput(cmd)
    if sts != 0 :
        print 'Getting Logs failed on %s machine'%(node)


if __name__ == "__main__":
	if ipv6_check() == 0 :
                print FAIL + "IPv6 is disabled, Please enable IPv6 support and restart installation or " + \
				"use Source Package to install drivers without IPv6 Support" + RESET
                sys.exit(1)
	if len(sys.argv) < 3 and len(sys.argv) >= 2:
		dist_check()
		Usage()
	elif len(sys.argv) >= 3:
		#print "there"
		dist_check()
		kernel_check()
		arch_check()
		parse_args(sys.argv[1:])
		if clusterInstall :
			get_clus_config()
			process_clus_cmd()
			rpm_clus_deploy()
			getLogs()
			parseLogs()
		else :
			process_config()
			set_availablity()
			uninstall()
			if not ofed_not_supported_on_platform and ofed:
				install_ofed()
			start_install()
			copy_config()
			addToModprobeConf()
			os.system('ldconfig')
			if um_support:
				install_um()
			#check_install()
			os.system('ldconfig')
			prompt_end()
		
	else:
		get_config()
		set_availablity()
		uninstall()
		if not ofed_not_supported_on_platform and ofed:
			install_ofed()
		start_install()
		copy_config()
		addToModprobeConf()
		os.system('ldconfig')
		if um_support:
			install_um()
		#check_install()
		os.system('ldconfig')
		prompt_end()
