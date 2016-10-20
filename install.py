#!/usr/bin/python

import os,platform,subprocess,threading,time,sys
import commands
from threading import Thread
import math
import cStringIO,operator
handler = open("install.log","w")
gDialog = True
D_BACK = -10
D_BACK2 = -15
D_BACK3 = -20
D_BACK4 = -25
D_BACK5 = -30
D_BACK6 = -35

class askUser:
    askinput = {"initial":"Install all Chelsio Components ,\n",}
    a = False
    prints = sys.stdout.write

    def __init__(self):
        pass

    def provideChoices(self):
        while not self.a :
            try :
                self.provideInitial()
                self.extracting()
            except KeyboardInterrupt :
                try :
                    r = raw_input("Do you wish to exit [ y/n ]")
                    if ( r == 'y' ):
                        self.prints("\n\n Aborted by user")
                        sys.exit(-2)
                    else :
                        pass
                except KeyboardInterrupt :
                    pass

    def provideInitial(self):
        k = None
        while k != 'e' :
            k = raw_input("\nInstall all Chelsio Componets : \n"+
                          "Please choose 'N' for installing "+
                          "individual components : [Y/n/e]").lower()
            if ( k == 'y' or k == 'yes' ) :
                # ask tune
                # install all
                self.promptAllSelect()
            elif ( k == 'e' ):
                self.prints("\n\nAborted by user \n")
                sys.exit(-1)
            else :
                # ask individual components.
                marked = self.promptMoreActions()
                self.prints("break")
                self.a = True
                break

    def ignoreKey(self):
        import signal
        return signal.signal(signal.SIGINT,signal.SIG_IGN)

    def promptMoreActions(self):
        self.prints("More choices will be provided")
        componentList = ["NIC",
                         "TOE",
                         "iWARP",
                         "iSCSI-target",
                         "iSCSI-initiator",
                         "chelsio-utils",
                         "chelsio-libraries"]
        descList = ["Chelsio Network Driver",
                    "Chelsio Network Offload Driver",
                    "Chelsio iWARP Driver",
                    "Chelsio iSCSI target",
                    "Chelsio Open iSCSI Offload Initiator",
                    "Chelsio Utils",
                    "Chelsio libraries"]
        marked = []
        for ind,i in enumerate(descList):
            k = None
            while ( k != 'y' and k != 'n' ):
                self.prints("Install  "+i+" ( "+componentList[ind]+" )")
                k = raw_input("[ Y/n ] : ").lower()
            marked.append(k)
        for i in marked :
            self.prints(i)
        return marked

    def extracting(self):
        os.system("clear")
        sys.stdout.write(summary)
        sys.stdout.write("cleared the screen\n")

    def promptAllSelect(self):
        t = None
        self.prints("You have choosen to install all the ")
        self.prints("components. do u wish to continue [ yes/no ] :")
        while ( t != 'yes' ):
            if t == 'yes' :
                self.prints("All the components will now be installed")
                self.prints("Please wait ... ")
            elif t == 'no' :
                return
            else :
                t = raw_input("Please provide yes/no").lower()

    def promptSummary(self):
        pass

    def askIndividual(self):
        pass

    def provideTuning(self):
        pass

class runtune:
    def __init__(self,tunnable):
        self.tunnable = tunnable

    def getPerftune(self):
        cmd = ""
	if ( self.tunnable == "Enable-affinity" or self.tunnable == "enable-affinity" ):
            cmd = " "
	elif ( self.tunnable == "Disable-affinity" or self.tunnable == "disable-affinity") :
            cmd = "-C"
        if ( self.tunnable == "Retain IRQ balance daemon" ) :
            cmd = "-D"
        if ( self.tunnable == "TX-Coalasce" ) :
            cmd = "-t"
        elif ( self.tunnable == "no TX-Coalasce" ) :
            cmd = "-T"
        return cmd

class prompt:
    components = []
    tunnables = []
    configTune = None
    ofa_kernel = None
    uninstall = False
    UNAME_R = None
    kvr = None
    kernel_ver = None
    ipv6_enable = False
    benchtools = False 
    customTarget = [ 'bonding', 'vnic','nic', 'nic_offload', 'toe','iwarp','sniffer','fcoe_full_offload_initiator','iscsi_pdu_target',
                     'fcoe_pdu_offload_target', 'iscsi_pdu_initiator','tools' ]
    supportMatrix = {"2.6.18-128.el5" : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "tools","udp_offload","benchmarks"], 
                     "2.6.18-164.el5" : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "tools","udp_offload","benchmarks"], 
                     "2.6.18-194.el5" : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "tools","udp_offload","benchmarks"], 
                     "2.6.18-238.el5" : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "tools","udp_offload","benchmarks"], 
                     "2.6.18-274.el5" : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "tools", "udp_offload","benchmarks"],
                     "2.6.18-308.el5" : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "tools", "udp_offload","benchmarks"],
                     "2.6.18-348.el5" : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "tools", "udp_offload","benchmarks"],
                     "2.6.18-371.el5" : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "tools", "udp_offload","benchmarks"],
                     "2.6.18-398.el5" : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "tools", "udp_offload","benchmarks"],
                     "2.6.32.12"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                     "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                     "sniffer", "tools","benchmarks"],
                     "3.0.13"     : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "udp_offload","iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "vnic", "iwarp", \
                                     "sniffer", "tools", "benchmarks"],
                     "3.0.76"     : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "udp_offload","iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "vnic", "iwarp", \
                                     "sniffer", "tools","benchmarks"],
                     "3.0.101"     : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "udp_offload","iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "vnic", "iwarp", \
                                     "sniffer", "tools","benchmarks"],
                     "3.12.28-4"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "udp_offload","iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "vnic", "iwarp", \
                                     "sniffer", "rdma_block_device", "tools","benchmarks"],
                     "3.12.49-11"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "udp_offload","iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "vnic", "iwarp", \
                                     "sniffer", "rdma_block_device", "tools","benchmarks"],
                     "2.6.32-71.el6"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools","benchmarks"],
                     "2.6.32-131.0.15.el6"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools","benchmarks"],
                     "2.6.32-220.el6"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools","benchmarks"],
                     "2.6.32-279.el6"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools","benchmarks"],
                     "2.6.32-358.el6"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools","benchmarks"],
                     "2.6.32-431.el6"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools","benchmarks"],
                     "2.6.32-504.el6"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools","benchmarks"],
                     "2.6.32-573.el6"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools","benchmarks"],
                     "3.10.0-123.el7.x86_64"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools","benchmarks"],
                     "3.10.0-229.el7.x86_64"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "rdma_block_device", "tools","benchmarks"],
                     "3.10.0-229.el7.ppc64"  : ["nic", "toe", "iwarp", "iscsi_pdu_target", "iscsi_pdu_initiator", \
                                          "tools", "benchmarks"],
                     "3.10.0-229.ael7b.ppc64le"  : ["nic", "toe", "iwarp", "iscsi_pdu_target", "iscsi_pdu_initiator", \
                                          "tools", "benchmarks"],
                     "3.10.0-327.el7.x86_64"  : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "rdma_block_device", "tools","benchmarks"],
                     "3.10.0-327.el7.ppc64le"  : ["nic", "toe", "iwarp", "iscsi_pdu_target", "iscsi_pdu_initiator", \
                                      "tools","benchmarks"],
                     "2.6.35"      : ["nic", "toe", "udp_offload","bypass", "fcoe_full_offload_initiator", "vnic", "iwarp", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "sniffer", "tools","benchmarks"],
                     "3.2.0-23"      : ["bonding", "nic", "toe", "vnic", "iwarp", "iscsi_pdu_target","bypass", \
					"udp_offload", "tools", "benchmarks"],
                     "3.5.0-23"      : ["bonding", "nic", "toe", "wdtoe_wdudp", "iwarp", "wdtoe", "bypass", "vnic", "udp_offload", \
                                        "tools","benchmarks"],
                     "3.13.0-32"     : ["bonding", "nic", "toe", "wdtoe_wdudp", "iwarp", "wdtoe", "bypass", "vnic", "udp_offload", \
                                        "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                        "sniffer", "tools","benchmarks"],
                     "3.16.0-30"     : ["bonding", "nic", "toe", "wdtoe_wdudp", "iwarp", "wdtoe", "bypass", "vnic", "udp_offload", \
                                        "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                        "sniffer", "tools","benchmarks"],
                     "3.19.0-25"     : ["bonding", "nic", "toe", "wdtoe_wdudp", "iwarp", "wdtoe", "bypass", "vnic", "udp_offload", \
                                        "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                        "sniffer", "tools","benchmarks"],
                     "3.1"      : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "vnic", "iwarp", "bypass", \
                                   "fcoe_full_offload_initiator", "iscsi_pdu_target","iscsi_pdu_initiator", \
                                   "sniffer", "tools", "udp_offload","benchmarks"],
                     "3.4"      : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "vnic", "iwarp", "bypass", \
                                   "fcoe_full_offload_initiator", "iscsi_pdu_target","iscsi_pdu_initiator", \
                                   "sniffer", "tools", "udp_offload","benchmarks"],
                     "3.5"      : ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "vnic", "iwarp", "bypass", \
                                   "fcoe_full_offload_initiator", "iscsi_pdu_target","iscsi_pdu_initiator", \
                                   "sniffer", "tools", "udp_offload","benchmarks"],
                     "3.6"	: ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "vnic", "iwarp", "bypass", \
                                   "fcoe_full_offload_initiator", "iscsi_pdu_target","iscsi_pdu_initiator", \
                                   "sniffer", "fcoe_pdu_offload_target", "tools", "udp_offload","benchmarks"],
                     "3.7"	: ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "vnic", "iwarp", "iscsi_pdu_target", \
                                   "iscsi_pdu_initiator", "bypass", "fcoe_full_offload_initiator", "sniffer", \
                                   "tools", "udp_offload","benchmarks"],
                     "3.8"      : ["bonding", "nic", "toe", "vnic", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "bypass", "tools", \
                                   "udp_offload", "benchmarks"],
                     "3.9"      : ["nic", "toe", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "bypass", "tools","benchmarks"],
                     "3.10"      : ["nic", "toe", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "bypass", "tools","benchmarks"],
                     "3.11"      : ["nic", "toe", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "bypass", "tools","benchmarks"],
                     "3.12"      : ["nic", "toe", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "bypass", "tools","benchmarks"],
                     "3.13"      : ["nic", "toe", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "fcoe_full_offload_initiator", \
                                    "bypass", "tools","benchmarks"],
                     "3.16"	: ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp", "vnic", "iwarp", "bypass", \
                                   "fcoe_full_offload_initiator", "iscsi_pdu_target","iscsi_pdu_initiator", \
                                   "sniffer", "tools", "udp_offload","benchmarks"],
                     "3.17"	: ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp","vnic", "iwarp", "bypass", \
                                   "fcoe_full_offload_initiator", "iscsi_pdu_target","iscsi_pdu_initiator", \
                                   "sniffer", "rdma_block_device", "tools", "udp_offload","benchmarks"],
                     "3.18"	: ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp","vnic", "iwarp", "bypass", \
                                   "fcoe_full_offload_initiator", "iscsi_pdu_target","iscsi_pdu_initiator", \
                                   "sniffer", "rdma_block_device", "tools", "udp_offload","benchmarks"],
                     "4.1"	: ["bonding", "nic", "toe", "wdtoe", "wdtoe_wdudp","vnic", "iwarp", "bypass", \
                                   "fcoe_full_offload_initiator", "iscsi_pdu_target","iscsi_pdu_initiator", \
                                   "sniffer", "rdma_block_device", "tools", "udp_offload","benchmarks"]


		}
    ofedsupportMatrix = dict.fromkeys(['2.6.18-274', '2.6.32-71', '2.6.32-131', '2.6.32.12', '2.6.35'], ['1.5.4.1'])
    ofedsupportMatrix.update(dict.fromkeys(["2.6.32-358"],['3.12-1']))
    ofedsupportMatrix.update(dict.fromkeys(["3.0.76", "2.6.32-431", "2.6.32-504", "3.10.0-123", "3.12.28-4"], ['3.18-1', '3.12-1']))
    ofedsupportMatrix.update(dict.fromkeys(["3.10.0-229", "2.6.32-573", "3.18.25", "3.0.101-63", "3.18"],['3.18-1']))
    installofed = False 
    def __init__(self):
        pass

    def promptLicense(self,a):
        desc = "Do you agree to the terms and conditions of EULA\n\n"
        desc += "Please find EULA in the root directory of the package \n"
        desc += "under the name EULA"
        code = a.yesno(
            desc,
            width="100",
            height="20",
            title="Agree with the EULA",
            yes_label="View EULA",
            no_label="Disagree")
        ret = checkExit(code,a)
        if ret == None :
            return -1
        self.promptEula(a)

    def promptEula(self,a):
        c,r = getRowColumn()
        desc = open("EULA",'r').read()
        desc = desc.splitlines()
        desc1 = ""
        for i in desc :
            desc1 += i + "\n"
        if ( (r != None) and (c != None) and (int(c) > 84 ) ):
            code = a.msgbox(desc1,width=84,height=(int(r)-5),
                             title="End User License Agreement",
                            ok_label="Agree")
        else :
            code = a.msgbox(desc1,ok_label="Agree")
        ret = checkExit(code,a)
        if ret == None :
            self.promptEula(a)

    def checkKernelSupport(self,a):
	pas=False
        kversion = platform.release()
        for ver in self.supportMatrix.keys():
            if kversion.find(ver) != -1 :
                pas=True
		self.kvr = ver ;
	        if kversion.find("default") != -1:
		    if not ver in ["3.12.49-11", "3.12.28-4", "3.0.13", "3.0.76", "3.0.101" ] :
	                pas=False
		    else:
			break
                if kversion.find("el7") != -1 :
		    if ver not in ["3.10.0-123.el7.x86_64", "3.10.0-123.el7.ppc64", "3.10.0-123.ael7b.ppc64le", \
						"3.10.0-229.el7.x86_64", "3.10.0-229.el7.ppc64", "3.10.0-229.ael7b.ppc64le", "3.10.0-327.el7.x86_64"]:
                        pas=False
		    else:
	                break
        if not pas :
            ret = self.promptUnsupported(a,kversion)
	    while ret == -1 :
		ret = self.promptUnsupported(a,kversion,inst=1)
	else:
	    self.kernel_ver = kversion

    def getOsSupportComp(self,a):
	kversion = self.kernel_ver
	supportedTarget = []
	comp = [("nic","Chelsio Network Driver   ( Non-offload disables all offload support- cxgb4 ) ",0),
                ("vnic","Chelsio Virtual Network Driver   ( Non-offload - cxgb4vf ) ",0),
                ("toe","Chelsio Network Driver   ( offload - t4_tom ) ",0),
                ("wdtoe","Chelsio WD-TOE Driver   ( offload - t4_tom ) ",0),
                ("wdtoe_wdudp","Chelsio WD-TOE & WD-UDP Driver   ( cxgb4, offload - t4_tom, iw_cxgb4 ) ",0),
                ("toe_ipv4","Chelsio Network Driver   ( offload - t4_tom with ipv6 offload disabled ) ",0),
                ("ipv6","Chelsio Network Driver   ( offload - ipv6 ) ",0),
                ("bonding","Chelsio Bonding Driver   ( offload - bonding ) ",0),
                ("iwarp","Chelsio iWARP Driver & WD-UDP libraries   ( offload - iw_cxgb4, WD-UDP ) ",0),
                ("udp_offload","Chelsio UDP offload Driver   ( offload - t4_tom ) ",0),
                ("bypass","Chelsio Bypass Driver    ( offload - cxgb4 ) ",0),
                ("sniffer","Chelsio filtering & tracing library   ( offload - sniffer ) ",0),
                ("fcoe_full_offload_initiator","Chelsio FCoE Full Offload Initiator Driver  ( offload - csiostor ) ",0),
                ("fcoe_pdu_offload_target","Chelsio FCoE PDU Offload Target Driver  ( pdu offload - chfcoe ) ", 0),
                ("iscsi_pdu_target", "Chelsio iSCSI Target   ( pdu offload - chiscsi_t4 ) ",0),
                ("iscsi_pdu_initiator","Chelsio iSCSI Initiator   ( pdu offload - cxgb4i ) ",0),
                ("rdma_block_device","Chelsio RDMA Block Device Driver   ( RBD ) ",0),
                ("tools","Chelsio user utilities   ( cxgbtool,cop,etc )",0),
                ("benchmarks", "Benchmark tools",0),
                ("libs",
                 "Chelsio libs             ( libcxgb4,libcxbg4_sock )",0)]
        sort = sorted(self.supportMatrix.keys(),reverse=True)
        for ix in range(0, len(self.supportMatrix.keys())):
            if kversion.find(sort[ix]) != -1 :
                supportedTarget = self.supportMatrix[sort[ix]]
                break
	toremove = []
        for i in range(0, len(comp)):
	    if comp[i][0] not in supportedTarget:
		toremove.append(i)
	toremove.sort(cmp=None, key=None, reverse=True)
        for ix in toremove:
            del(comp[ix])
        return comp 

    def getSupportList(self,a):
	customTarget = []
	kversion = self.kernel_ver
        sort = sorted(self.supportMatrix.keys(),reverse=True)
        for ix in range(0, len(self.supportMatrix.keys())):
            if kversion.find(sort[ix]) != -1 :
                customTarget.extend(self.supportMatrix[sort[ix]])
                break
	if self.uninstall:
	    self.components.extend(customTarget)
	    toRemove = [ "toe_ipv4", "libs", "udp_offload","wdtoe_wdudp"]
	    for i in toRemove:
	        if i in self.components:
		    self.components.remove(i)
	    return
	if self.configTune == "Balanced Uwire":
	    self.components = customTarget
	    if "udp_offload" in self.components:
	        self.components.remove("udp_offload")
            if "wdtoe_wdudp" in self.components:
		self.components.remove("wdtoe_wdudp")
            if "fcoe_pdu_offload_target" in self.components:
		self.components.remove("fcoe_pdu_offload_target")
	elif self.configTune == "Low latency Networking" : 
	    self.components = customTarget
	    toRemove = [ "vnic", "wdtoe","bonding","iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
	    "fcoe_pdu_offload_target", "udp_offload","wdtoe_wdudp"]
	    if kversion.find('2.6.35') != -1 or kversion.find("3.2.0-23") != -1 or  kversion.find("3.5.0-23") != -1:
		toRemove.remove("toe") 
	    for i in toRemove:
                if i in self.components:
                    self.components.remove(i)
            self.components.append("nic_offload")
	elif self.configTune == "T5 No External Memory" or self.configTune == "T5 High Capacity WD" :
            self.components = customTarget
            toRemove = [ "wdtoe","vnic","bonding","iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "fcoe_pdu_offload_target",\
                         "udp_offload","wdtoe_wdudp", "sniffer"]
            '''if kversion.find('2.6.35') != -1 or kversion.find("3.2.0-23") != -1 or  kversion.find("3.5.0-23") != -1 :
                toRemove.remove("toe")'''
            for i in toRemove:
                if i in self.components:
                    self.components.remove(i)
	    self.components.append("nic_offload")
	elif self.configTune == "High capacity RDMA" :
	    self.components = customTarget
            toRemove = [ "vnic", "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator","fcoe_pdu_offload_target", \
                         "udp_offload","wdtoe_wdudp"]
            for i in toRemove:
                if i in self.components:
                    self.components.remove(i)
	elif self.configTune == "RDMA Performance":
            self.components = customTarget
            toRemove = [ "vnic", "bonding", "sniffer", "iscsi_pdu_target", "iscsi_pdu_initiator", \
                         "fcoe_full_offload_initiator", "fcoe_pdu_offload_target", "udp_offload","wdtoe_wdudp"]
            for i in toRemove:
                if i in self.components:
                    self.components.remove(i)
	elif self.configTune == "Memory Free":
            self.components = customTarget
            toRemove = [ "vnic", "bonding", "sniffer", "iscsi_pdu_target", "iscsi_pdu_initiator", \
                         "fcoe_full_offload_initiator", "fcoe_pdu_offload_target", "udp_offload","wdtoe_wdudp", "rdma_block_device"]
            for i in toRemove:
                if i in self.components:
                    self.components.remove(i)
	elif self.configTune == "High capacity TOE":
	    self.components = customTarget
	    toRemove = [ "vnic", "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "fcoe_pdu_offload_target", \
			 "iwarp", "libs", "iscsi_pdu_target", "sniffer", "udp_offload","wdtoe_wdudp", \
			 "rdma_block_device"]
	    for i in toRemove:
                if i in self.components:
                    self.components.remove(i)
	elif self.configTune == "T5 Hash Filter" :
	    self.components = ["nic_offload", "tools"]
	elif self.configTune == "UDP Seg. Offload & Pacing":
	    self.components = [ "udp_offload", "tools" ]
	elif self.configTune == "iSCSI Performance" :
	    self.components = customTarget
	    toRemove = [ "nic", "vnic", "wdtoe","vnic", "fcoe_full_offload_initiator", "fcoe_pdu_offload_target", "iwarp", \
                         "libs", "sniffer", "udp_offload","wdtoe_wdudp", "rdma_block_device"]
	    for i in toRemove:
		if i in self.components:
		    self.components.remove(i)
	else:
	    print "Wrong config Tune option : ",self.configTune
	    sys.exit(-1)
	if kversion.find('2.6.16.60-0.21') == -1:
		if self.configTune == "Low latency Networking" or self.configTune == "T5 No External Memory" \
                   or self.configTune == "T5 High Capacity WD" :
			toRemove = [ "bypass","toe_ipv4", "libs", "nic", "wdtoe_wdudp"]
		else:
			toRemove = [ "bypass","toe_ipv4", "libs", "nic", "wdtoe","wdtoe_wdudp"]
		for i in toRemove:
		    if i in self.components:
			self.components.remove(i)
	if "benchmarks" in self.components:
		self.components.remove("benchmarks")
    
    def getSupportComp(self,a):
	allComp = []
	allComp = self.getOsSupportComp(a)
	if self.uninstall:
	    toremove = []
            for i in range(0, len(allComp)):
                if allComp[i][0].find('benchmarks') != -1:
                    toremove.append(i)
            toremove.sort(cmp=None, key=None, reverse=True)
            for ix in toremove:
                del(allComp[ix])
	    return allComp
	if self.configTune == "Balanced Uwire" or self.configTune == None:
	    toremove = []
	    for i in range(0, len(allComp)):
		if allComp[i][0].find('udp_offload') != -1:
		    toremove.append(i)
	    toremove.sort(cmp=None, key=None, reverse=True)
	    for ix in toremove:
                del(allComp[ix])
	    return allComp
	elif self.configTune == "Low latency Networking" or \
             self.configTune == "High capacity RDMA" :
	    toremove = []
	    for i in range(0, len(allComp)):
                if allComp[i][0].find('fcoe_full_offload') != -1 or \
		   allComp[i][0].find('fcoe_pdu_offload') != -1 or \
		   allComp[i][0].find('iscsi_pdu') != -1 or \
		   allComp[i][0].find('udp_offload') != -1 or \
		   allComp[i][0].find('bypass') != -1 or \
		   allComp[i][0].find('nic') != -1 or \
                   allComp[i][0].find('wdtoe') != -1 or \
		   allComp[i][0].find('vnic') != -1:
		   toremove.append(i)
	        '''if self.configTune == "High capacity RDMA" :
                   if allComp[i][0].find('wdtoe') != -1:
                      toremove.append(i)'''
	    toremove.sort(cmp=None, key=None, reverse=True)
	    for ix in toremove:
	        del(allComp[ix])
	    return allComp
	elif self.configTune == "RDMA Performance" or \
             self.configTune == "Memory Free" :
            toremove = []
            for i in range(0, len(allComp)):
                if allComp[i][0].find('fcoe_full_offload') != -1 or \
                   allComp[i][0].find('fcoe_pdu_offload') != -1 or \
                   allComp[i][0].find('iscsi_pdu') != -1 or \
                   allComp[i][0].find('udp_offload') != -1 or \
                   allComp[i][0].find('bypass') != -1 or \
                   allComp[i][0].find('nic') != -1 or \
                   allComp[i][0].find('wdtoe') != -1 or \
                   allComp[i][0].find('bonding') != -1 or \
                   allComp[i][0].find('sniffer') != -1 or \
                   allComp[i][0].find('vnic') != -1 :
                   toremove.append(i)
                if self.configTune == "Memory Free" :
		   if allComp[i][0].find('rdma_block_device') != -1 :
                      toremove.append(i)
            toremove.sort(cmp=None, key=None, reverse=True)
            for ix in toremove:
                del(allComp[ix])
            return allComp
	elif self.configTune == "T5 No External Memory"  or \
             self.configTune == "T5 High Capacity WD" : 
            toremove = []
            for i in range(0, len(allComp)):
                if allComp[i][0].find('fcoe_full_offload') != -1 or \
                   allComp[i][0].find('fcoe_pdu_offload') != -1 or \
                   allComp[i][0].find('iscsi_pdu') != -1 or \
                   allComp[i][0].find('udp_offload') != -1 or \
                   allComp[i][0].find('bypass') != -1 or \
                   allComp[i][0].find('nic') != -1 or \
                   allComp[i][0].find('sniffer') != -1 or \
                   allComp[i][0].find('bonding') != -1 or \
                   allComp[i][0].find('wdtoe') != -1 or \
		   allComp[i][0].find('vnic') != -1:
                   toremove.append(i)
                '''if self.configTune == "T5 High Capacity WD" :
                   if allComp[i][0] == 'wdtoe':
                      toremove.append(i)'''
            toremove.sort(cmp=None, key=None, reverse=True)
            for ix in toremove:
                del(allComp[ix])
            return allComp
	elif self.configTune == "High capacity TOE" or self.configTune == "iSCSI Performance" :
	    toremove = []
	    for i in range(0, len(allComp)):
                if allComp[i][0].find('fcoe_full_offload') != -1 or \
		   allComp[i][0].find('fcoe_pdu_offload') != -1 or \
		   allComp[i][0].find('bypass') != -1 or \
		   allComp[i][0].find('udp_offload') != -1 or \
		   allComp[i][0].find('iwarp') != -1 or \
		   allComp[i][0].find('rdma_block_device') != -1 or \
		   allComp[i][0].find('sniffer') != -1 or \
		   allComp[i][0].find('wdtoe') != -1 or \
		   allComp[i][0].find('libs') != -1 or \
		   allComp[i][0].find('nic') != -1 or \
		   allComp[i][0].find('vnic') != -1:
		   toremove.append(i)
		if self.configTune == "High capacity TOE" :
		    if allComp[i][0].find('iscsi_pdu') != -1 :
		        toremove.append(i)
	    toremove.sort(cmp=None, key=None, reverse=True)
	    for ix in toremove:
		del(allComp[ix])
	    return allComp
	elif self.configTune == "T5 Hash Filter" :
	    toremove = []
            for i in range(0, len(allComp)):
                if allComp[i][0].find('nic_offload') != 0  and \
                   allComp[i][0].find('tools') != 0 and \
                   allComp[i][0].find('benchmarks') != 0 :
                   toremove.append(i)
            toremove.sort(cmp=None, key=None, reverse=True)
            for ix in toremove:
                del(allComp[ix])
            return allComp
	elif self.configTune == "UDP Seg. Offload & Pacing":
	    toremove = []
            for i in range(0, len(allComp)):
                if allComp[i][0].find('udp_offload') != 0  and \
                   allComp[i][0].find('tools') != 0 and \
                   allComp[i][0].find('benchmarks') != 0 :
                   toremove.append(i)
            toremove.sort(cmp=None, key=None, reverse=True)
            for ix in toremove:
                del(allComp[ix])
            return allComp
	else:
	    print "Wrong config Tune option : ",self.configTune
	    sys.exit(-1)
    
    def promptOfedInstall(self,a,texts="choose an action"):
	ofed_ver = self.ofedsupportMatrix[self.ofedkver][0]
	self.ofed_fversion = ofed_ver
        choices=[
            ("Skip-OFED","Do Not Install OFED",1),
            ("Install-OFED","Compiles and Installs OFED-%s"%(ofed_ver),0)]
	if len(self.ofedsupportMatrix[self.ofedkver]) > 1 :
	    choices.append(("Choose-OFED-Version","To install different Version of OFED",0))
	(code,tag) = a.radiolist(
            text=texts,
            width=100,
	    choices=choices,
            cancel="Back")
	ret = checkExit(code,a,1)
	while ret == 1 :
	    #ret = self.promptTunnables(a)
	    return D_BACK3
	if ret == None :
	    ret = self.promptOfedInstall(a)
            return ret
	elif (( ret == 0 ) and ( tag in ["Install-OFED"])):
	    self.installofed = True
	    print "Install OFED"
	elif (( ret == 0 ) and ( tag in ["Choose-OFED-Version"])):
	    self.installofed = True
	    ret = self.promptOfedVersion(a, texts="Supported OFED Versions")
	    while ret == D_BACK4:
		ret = self.promptOfedInstall(a)
            	return ret
	    return ret
	elif ret == 0 :
	    self.installofed = False
	    print "Skip OFed"
	
    def promptOfedVersion(self,a,texts="Choose Different OFED Version"):
	ofed_ver = self.ofedsupportMatrix[self.ofedkver]
	ofedVersionList = ["1.5.4.1","3.12-1", "3.18-1"]
	ch=1
	choices=[]
	for i in ofedVersionList:
		for k in self.ofedsupportMatrix[self.ofedkver]:
			
			if i == k :
				choices.append(("OFED-%s"%i,"Compiles and Installs OFED-%s"%(i),ch))
				ch = 0
	print choices
        (code,tag) = a.radiolist(
            text=texts,
            width=100,
            choices=choices,
            cancel="Back"
	 )
        ret = checkExit(code,a,1)
	while ret == 1 :
            ret = self.promptOfedInstall(a)
            return ret
	if ret == None :
            self.promptOfedVersion(a)
            return ret
	elif (( ret == 0 ) and ( tag in ["OFED-1.5.4.1"])):
	    self.ofed_fversion = "1.5.4.1"
	elif (( ret == 0 ) and ( tag in ["OFED-3.12-1"])):
            self.ofed_fversion = "3.12-1"
	elif (( ret == 0 ) and ( tag in ["OFED-3.18-1"])):
            self.ofed_fversion = "3.18-1"
	

    def promptUninstall(self,a,texts="Choose an action"):
        (code,tag) = a.radiolist(
            text=texts,
            width=100,
            choices=[
                ("install","Install new components ",1),
                ("uninstall","Uninstall components",0)])
        ret = checkExit(code,a)
        if ret == None :
            ret = self.promptUninstall(a)
	    return ret
        elif ( ( ret == 0 ) and ( tag in ["uninstall"] ) ):
            self.uninstall = True
            ret = self.promptAllCustom(a, texts="Choose uninstall components")
            while ret == D_BACK2 or ret == D_BACK3 or ret == D_BACK6:	
	        if ret == D_BACK or ret == D_BACK6:
                    self.uninstall = False
		    return D_BACK
                ret = self.promptAllCustom(a, texts="Choose uninstall components")
            compstruct1 = ["iscsi_pdu_initiator", "iscsi_pdu_target", "fcoe_pdu_offload_target", "fcoe_full_offload_initiator", \
                           "sniffer", "wdtoe_wdudp", "iwarp", "bypass", "wdtoe", \
                           "bonding", "toe", "udp_offload", "nic", "vnic", "tools", "all"]
            compstruct2 = []
            for comp_emt in compstruct1 :
                if comp_emt in self.components :
                    compstruct2.append(comp_emt)
            if "all" in compstruct2 :
                self.components = "all" 
            else :
                self.components = compstruct2
	elif ret == 0 :
	    ret = None
	    ret = self.promptIpv6(a)
	    while ret == D_BACK5 or ret == D_BACK or ret == D_BACK6:
	        if ret == D_BACK or ret == D_BACK6:
		#    print "UN Prompt",ret;
		    return ret
		ret = self.promptIpv6(a)
   
    def promptIpv6(self,a,texts="Choose an action"):
        (code,tag) = a.radiolist(
            text=texts,
            width=100,
            choices=[
                ("Enable IPv6-Offload","Installs Drivers with IPv6 Offload Support",1),
                ("Disable IPv6-Offload","Installs Drivers without IPv6 Offload Support",0)],
            cancel="Back")
        ret = checkExit(code,a,1)
	#print "retval=",ret
	while ret == 1 :
          #  print "ret -1",ret;
           # print "DBACK4",D_BACK4;
            #if ret == D_BACK4:
             #   return D_BACK
            ret = self.promptUninstall(a)
            return ret
        if ret == None :
            ret = self.promptIpv6(a)
            return ret
        elif ( ( ret == 0 ) and ( tag in ["Enable IPv6-Offload"] ) ):
            self.ipv6_enable = True
        elif ( ( ret == 0 ) and ( tag in ["Disable IPv6-Offload"] ) ):
	    self.ipv6_enable = False
        ret = None
        ret = self.promptConf(a)
	#print "while ret", ret
        while ret == D_BACK5 or ret == D_BACK or ret == D_BACK6:
            if ret == D_BACK or ret == D_BACK6:
                #    print "UN Prompt",ret;
                ret = self.promptIpv6(a)
                return ret
            ret = self.promptConf(a)
 
    def promptConf(self,a):
	ret = None
        ret = self.promptConfigTune(a)
        while ret == -1 or ret == D_BACK4 or ret == D_BACK5:
	    #print "ret -1",ret;
	   # print "DBACK4",D_BACK4;
	    if ret == D_BACK4:
                return D_BACK
	    ret = self.promptConfigTune(a)
	ret = None
        ret = self.promptAllCustom(a, texts="Choose install components")
	while ret == D_BACK2 or ret == D_BACK3 or ret == D_BACK4 or ret == D_BACK5:
	     if ret == D_BACK5 or ret == D_BACK6:
	          return ret
	     ret = self.promptAllCustom(a, texts="Choose install components")
    
    def promptComponents(self,a,texts="Select the components to install"):
        if 'all' in self.install :
            self.getSupportList(a)
            return
        (code,tag) = a.checklist(
            text=texts,
            width=120,
            choices=self.getSupportComp(a),
            cancel="Back")
        ret = checkExit(code,a,1)
        if ret == None :
            ret = self.promptComponents(a)
	    return ret
        elif ret == 1 :
	    self.components = []
            return D_BACK2
        elif ret == 0 :
            if len(tag) == 0 :
		return -1
                self.promptComponents(
                    a,
                    texts="Select the components to install (choose atleast one)")
	    self.components = []
            self.components = tag
	    for ix in range(0,len(self.components)):
		self.components[ix] = self.components[ix].strip('"')
	    ix=0
            count = 0
	    tempArr = []
	    tret = 0
	    if not self.uninstall and "benchmarks" in self.components :
		self.benchtools = True
		tempArr.extend(self.components)
                tempArr.remove("benchmarks")
                if len(tempArr) == 0 :
			self.components.append("tools")
		self.components.remove("benchmarks")
            tempArr = []
	    if not self.uninstall and "bypass" in self.components and len(self.components) > 1 :
                tempArr.extend(self.components)
                tempArr.remove("bypass")
                if len(tempArr) > 1 :
                    tret = self.promptBypassError(a)
                if "tools" not in tempArr:
                    tret = self.promptBypassError(a)
	    tempArr = []
            if not self.uninstall and "wdtoe" in self.components and len(self.components) > 1 :
                tempArr.extend(self.components)
                tempArr.remove("wdtoe")
                if "iwarp" in self.components :
                    tempArr.remove("iwarp")
                    if not "tools" in self.components :
	                    tempArr.append("tools")
                if len(tempArr) > 1 :
                    tret = self.promptWDTOEError(a)
                elif "tools" not in tempArr:
                    tret = self.promptWDTOEError(a)
            tempArr = []
            if not self.uninstall and "wdtoe_wdudp" in self.components and len(self.components) > 1 :
                tempArr.extend(self.components)
                tempArr.remove("wdtoe_wdudp")
                if len(tempArr) > 1 :
                    tret = self.promptWDTOEError(a)
                elif "tools" not in tempArr:
                    tret = self.promptWDTOEError(a)
	    tempArr = []
	    if not self.uninstall and "nic" in self.components and len(self.components) > 1 :
                tempArr.extend(self.components)
                tempArr.remove("nic")
                if len(tempArr) > 1 :
                    tret = self.promptNicError(a)
                if "tools" not in tempArr:
                    tret = self.promptNicError(a)
	    tempArr = []
	    if not self.uninstall:
                if "fcoe_pdu_offload_target" in self.components and "iscsi_pdu_initiator" in self.components :
                    tret = self.promptFcoePduError(a,"iscsi_pdu_initiator")
            # Don't procced if toe_ipv4 & toe both are choosen.
	    if not self.uninstall:
                if "toe_ipv4" in self.components and "toe" in self.components :
                    tret = self.promptToeError(a,"toe")
                if "toe_ipv4" in self.components and "ipv6" in self.components :
                    tret = self.promptToeError(a,"ipv6")
                if "toe_ipv4" in self.components and "bonding" in self.components :
                    tret = self.promptToeError(a,"bonding")
	    
            if not self.uninstall :
                if "iwarp" in self.components or "sniffer" in self.components :
                    self.promptOFAKernel(a)
                if "libs" in self.components :
                    count += 1
                if "tools" in self.components :
                    count += 1
		#print count,len(self.components),tret,"count"
		if count != len(self.components) :
		    if tret == None :
			ret = self.promptComponents(a)
			return ret
		    else :
			    ret = self.promptTunnables(a)
		    while ret == -1 or ret == D_BACK3:
		        if ret == D_BACK3:
		            return D_BACK3
		        ret = self.promptTunnables(a,texts="Select the Performance Tuning (choose at least one)")
            elif self.uninstall :
                    if tret == None :
                        status = self.promptComponents(a,"choose uninstall components")
                        while status == -1 or status == D_BACK2 or status == D_BACK3:
                            if status == D_BACK2:
                                self.components = []
                                return D_BACK2
                            if status == D_BACK3:
                                status = self.promptComponents(a,"choose uninstall components")
                            elif status == -1:
                                status = self.promptComponents(a,"choose uninstall components(choose atleast one)")
            return 0

    def promptAllCustom(self,a,texts="Choose components for installation"):
	if self.uninstall :
             (code,tag) = a.radiolist(
                 text=texts,
                 width=100,
                 choices=[("all","Everything in this package ",1),
                         ("custom","Choose what to uninstall ",0)],cancel="Back")
        else :
             if self.configTune == "T5 Hash Filter" :
                 (code,tag) = a.radiolist(
                     text=texts,
                     width=100,
                     choices=[("all","Installs only NIC driver & Chelsio-Utils ",1)],cancel="Back")
             else :
                 (code,tag) = a.radiolist(
                     text=texts,
                     width=100,
                     choices=[("all","Everything in this package ",1),
                                 ("custom","Choose what to install ",0)],cancel="Back")

        ret = checkExit(code,a,1)
        if ret == None :
            ret = self.promptAllCustom(a)
	    return ret
        elif ( ret == 1 ):
	    self.components = []
	    if self.uninstall:
		return D_BACK6
	    return D_BACK5 
        elif ( ret == 0 ) :
            self.install = tag[:]
            self.getSupportList(a)
	    if "all" in self.install and self.uninstall:
		self.components = "all "
		return 0
            if "all" in self.install and not self.uninstall :
                self.promptOFAKernel(a)
		ret = self.promptTunnables(a)
		while ret == -1 or ret == D_BACK3:
		    if ret == D_BACK3:
		        return D_BACK3
		    ret = self.promptTunnables(a,texts="Select the Performance Tuning (choose at least one)")
            else :
                if self.uninstall :
                    status = self.promptComponents(a,"choose uninstall components")
		    while status == -1 or status == D_BACK2 or status == D_BACK3:
			if status == D_BACK2:
			    self.components = []
			    return D_BACK2
			if status == D_BACK3:
			    status = self.promptComponents(a,"choose uninstall components")
			elif status == -1:
			    status = self.promptComponents(a,"choose uninstall components(choose atleast one)")
                else :
                    status = self.promptComponents(a)
		    while status == -1 or status == D_BACK2 or status == D_BACK3:
			if status == D_BACK2:
			    self.components = []
			    return D_BACK2
			if status == D_BACK3:
			    status = self.promptComponents(a,"Select the components to install")
			elif status == -1:
			    status = self.promptComponents(a,"Select the components to install (choose atleast one)")

    def promptKernelSource(self,a, inst):
        elements = [
            ('KSRC (kernel source directory)',
             1,1,"/usr/src",1,50,50,100),
            ('KOBJ (Kernel object directory)',
             2,1,"/usr/src",2,50,50,100)]
	if inst > 0 :
             code,tags = a.form("Wrong path provided. Please provide the correct path to kernel source",
                              elements,
                              width = 110)
	else:
             code,tags = a.form("Please provide the path to kernel source.",
                              elements,
                              width = 90)
        tret = checkExit(code,a)
	if tret == None:
		tags = self.promptKernelSource(a,inst)
        return tags

    def promptOFAKernel(self,
                        a,
                        init_dir = "/usr/src",
                        texts="path for ofa_kernel"):
        ofaKernelPath = None
        for ofedp in [ 'kernel-ib-devel', 'compat-rdma-devel', 'mlnx-ofa_kernel-devel'] :
                cmd = 'rpm -qa | grep -i %s'%(ofedp)
                cmdOut = commands.getoutput(cmd)
                if cmdOut :
                        cmd = 'rpm -ql %s | grep -w Module.symvers'%(ofedp)
                        cmdOut = commands.getoutput(cmd)
                        self.ofa_kernel = cmdOut.split('Module')[0]
                        if ofedp == 'mlnx-ofa_kernel-devel' :
                                cmd = 'modinfo -F filename ib_core | grep extra'
                        else :
                                cmd = 'modinfo -F filename ib_core | grep updates'
                        cmdOut = commands.getoutput(cmd).strip()
                        if cmdOut == '' :
                                self.ofa_kernel=None
                        else :
                                break
        else :
                cmd = 'modinfo -F filename ib_core | grep updates'
                cmdOut = commands.getoutput(cmd)
                if cmdOut:
                        owner_rpm = None
                        ib_path = commands.getoutput("modinfo -F filename ib_core")
                        sts, owner_rpm = commands.getstatusoutput("rpm -qf " + ib_path)
                        if owner_rpm != None and owner_rpm.find('ofed-kmp-default') != -1:
                            return 0
                        status = self.promptNoOfaDevel(a)
                        if status :
                            return 0
                        else :
                            self.promptOFAError(a)
                            return 0
                else:
                        print 'Building with INBOX, no OFED is present :',cmdOut
                        return 0
 
        return 0

        """
        The following code is removed on a trial basis to see if we can handle OFED without prompting to USER.
        ret = self.promptOfaKernelYesNo(a)
        if ret :
            if not init_dir.endswith(os.sep):
                init_dir += os.sep
            (code, path) = a.fselect(init_dir, height=10, width=60)

            if code in (a.DIALOG_CANCEL, a.DIALOG_ESC):
                path = None
            elif code == a.DIALOG_OK:
                if path.endswith(".") or path.endswith("..") :
                    self.promptOFAKernel(a,init_dir=path)
                else :
                    mode = os.path.exists(path)
            else:
                a.msgbox("Unexpected exit status from the dialog-like program: %d"
                         % code)
            self.ofa_kernel = path
        """
	
    def promptTunnables(self,a,texts="Select the Performance Tuning"):
        checks = ["libs","tools","vnic"]
        count = 0
        for i in checks:
            if i in self.components :
                count += 1
        if ( count == len(self.components) ) :
            return
        (code,tag) = a.checklist(
            text=texts,
            width=100,
            choices = [("Enable Binding IRQs to CPUs","",0),
                       ("Retain IRQ balance daemon","",0),
                       ("TX-Coalasce","",0)],
            cancel="Back")
        ret = checkExit(code,a,1)
        if ret == None :
            ret = self.promptTunnables(a)
	    return ret
        elif ret == 1 :
	    return D_BACK3
            self.promptComponents(a)
        elif ret == 0 :
            if len(tag) == 0 :
		self.tunnables[:] = []
		self.tunnables.append('Disable-affinity')
	    else :
	        self.tunnables = tag[:]
	        for ix in range(0,len(self.tunnables)):
		    self.tunnables[ix] = self.tunnables[ix].strip('"')
		if "Enable Binding IRQs to CPUs" not in self.tunnables and "Disable-affinity" not in self.tunnables :
		    self.tunnables.append('Disable-affinity')
            if not ( self.configTune in [ "UDP Seg. Offload & Pacing", "High capacity TOE", "iSCSI Performance", "T5 Hash Filter"] ) :
	        kver = self.kernel_ver
	        for ver in self.ofedsupportMatrix.keys() :
		    if kver.find(ver) != -1 :
		        self.ofedkver = ver
	                ret = self.promptOfedInstall(a)
		        while ret == D_BACK3 :
			    ret = self.promptTunnables(a)
			    return ret
		        break

    def promptConfigTune(self, a,texts="Select the Terminator 4 / Terminator 5 Configuration tuning"):
	choice_arr = [ ("Unified Wire","Installs all Chelsio drivers with FCoE Initiator.",1)]
	customTarget = []
	kversion = self.kernel_ver
        sort = sorted(self.supportMatrix.keys(),reverse=True)
        for ix in range(0, len(self.supportMatrix.keys())):
            if kversion.find(sort[ix]) != -1 :
                customTarget.extend(self.supportMatrix[sort[ix]])
                break
	print "CUST TGT :",customTarget
	if "iwarp" in customTarget:
	    choice_arr.append(("Low latency Networking","Installs only NIC/TOE/RDMA/WD drivers",0))
	    choice_arr.append(("High capacity RDMA","Installs only NIC/TOE/RDMA drivers",0))
	    choice_arr.append(("RDMA Performance","Installs only NIC/TOE/RDMA drivers",0))
	    choice_arr.append(("Memory Free","Installs only NIC/TOE/RDMA drivers",0))
	if "toe" in customTarget:
	    choice_arr.append(("High capacity TOE","Installs only NIC/TOE drivers",0))
	if "iscsi_pdu_target" in customTarget :
	    choice_arr.append(("iSCSI Performance","Installs only NIC/TOE/iSCSI-Initiator & Target drivers",0))
	if "udp_offload" in customTarget:
	    choice_arr.append(("UDP Seg. Offload & Pacing","Installs only UDP offload drivers",0))
	if "iwarp" in customTarget:
            choice_arr.append(("T5 Wire Direct Latency","Installs only NIC/TOE/RDMA/WD drivers",0))
	    if self.kvr.find("ppc64") == -1 :
                choice_arr.append(("T5 High Capacity WD","Installs only NIC/TOE/RDMA/WD drivers",0))
	if self.kvr.find("ppc64") == -1 :
	    choice_arr.append(("T5 Hash Filter", "Installs only NIC driver & Chelsio Utils.",0))
	if len(choice_arr) > 1:
	    (code,tag) = a.radiolist(
	         text=texts,
	         width=100,
		 list_height=8,
  	         choices=choice_arr,
		 cancel="Back")
	    ret = checkExit(code,a,1)
            if ret == None :
                ret = self.promptConfigTune(a)
		return ret
            elif ret == 1 :
	        return D_BACK4
                self.promptComponents(a)
            elif ret == 0 :
                if len(tag) == 0 :
	  	    return -1
                self.configTune = tag[:]
	else:
	    self.configTune = "Unified Wire"
	if self.configTune.find("Unified Wire") != -1 :
	    self.configTune = "Balanced Uwire"
	elif self.configTune.find("Low latency Networking") != -1 :
	    self.configTune = "Low latency Networking"
	elif self.configTune.find("High capacity TOE") != -1 :
	    self.configTune = "High capacity TOE"
	elif self.configTune.find("High capacity RDMA") != -1 :
	    self.configTune = "High capacity RDMA"
	elif self.configTune.find("UDP Seg. Offload & Pacing") != -1 :
            self.configTune = "UDP Seg. Offload & Pacing"
        elif self.configTune.find("T5 Wire Direct Latency") != -1 :
            self.configTune = "T5 No External Memory"
        elif self.configTune.find("T5 High Capacity WD") != -1 :
            self.configTune = "T5 High Capacity WD"
        elif self.configTune.find("T5 Hash Filter") != -1 :
            self.configTune = "T5 Hash Filter"
	elif self.configTune.find("RDMA Performance") != -1 :
	    self.configTune = "RDMA Performance"
	elif self.configTune.find("iSCSI Performance") != -1 :
	    self.configTune = "iSCSI Performance"
	elif self.configTune.find("Memory Free") != -1 :
	    self.configTune = "Memory Free"

	'''if self.configTune in ["High capacity RDMA","High capacity TOE"] :
	    c,r = getRowColumn()
            msg = "\n High Capacity Config Tuning Options are NOT SUPPORTED For\n Terminator 5 Adapters.\n\n Please refer to README for Supported Config Tuning Options."
            code = a.msgbox(msg,width=65,height=(int(r)-20),
                             title="Config Error",
                            ok_label="Ok")
            tret = checkExit(code,a,0)'''

    def promptOfaKernelYesNo(self,a):
        code = a.yesno(
            "Do you want to compile iw_cxgb4 (iwarp driver) against OFED's Kernel (ofa_kernel) using OFA_DIR option",
            width=74)
        if code == 0 :
            # checkExit(code)
            self.useOfa = True
            return True
        return False

    def promptGaugeGen(self,a,texts="Generating routines"):
        a.gauge_start(
            "Progress 1%",
            title=texts)

    def updateGaugeGen(self,a,percent,progress="Progress :"):
        if percent > 101 :
            percent = 99
        a.gauge_update(
            percent,
            "%s %d%%" % (progress,percent),
            update_text=1)

    def stopGaugeGen(self,a):
        a.gauge_stop()

    def promptNoOfaDevel(self,dialogObj):
        code = dialogObj.yesno(
            "OFED header required to built iwarp driver not found. Do you want to compile iwarp driver with kernel headers.",
            width=74)
        if code == 0 :
            # checkExit(code)
            self.useOfa = False
            return True
        return False

    def promptUnsupported(self,dialogObj,kversion,inst=0):
	code = None
	if inst == 0:
	    code = dialogObj.yesno(
                "The kernel version %s is not supported. Refer to README for supported kernel versions."\
	        " To compile drivers for a updated kernel, press Yes. To exit, press No.."%(kversion),
                width=74)
	if code == 0 or inst > 0 :
	    supportMatrix = [ ("2.6.32-279.el6","Red Hat Enterprise Linux Server release 6.3",0),
                              ("2.6.32-358.el6","Red Hat Enterprise Linux Server release 6.4",0),
                              ("2.6.32-431.el6","Red Hat Enterprise Linux Server release 6.5",0),
                              ("2.6.32-504.el6","Red Hat Enterprise Linux Server release 6.6",0),
                              ("2.6.32-573.el6","Red Hat Enterprise Linux Server release 6.7",0),
                              ("3.10.0-123.el7","Red Hat Enterprise Linux Server release 7",0),
                              ("3.10.0-229.el7","Red Hat Enterprise Linux Server release 7.1",0),
                              ("3.10.0-327.el7","Red Hat Enterprise Linux Server release 7.2",0),
                              ("2.6.32.12-0.7","SUSE Linux Enterprise Server 11 SP1",0), 
                              ("3.0.13-0.27","SUSE Linux Enterprise Server 11 SP2",0),
                              ("3.0.76-0.11","SUSE Linux Enterprise Server 11 SP3",0), 
                              ("3.0.101-63","SUSE Linux Enterprise Server 11 SP4",0), 
                              ("3.12.28-4","SUSE Linux Enterprise Server 12",0), 
                              ("3.12.49-11","SUSE Linux Enterprise Server 12 SP1",0), 
			      ("3.13.0-32","Ubuntu 14.04.1 LTS",0),
			      ("3.16.0-30","Ubuntu 14.04.2 LTS",0),
			      ("3.19.0-25","Ubuntu 14.04.3 LTS",0),
                              ("3.4","Linux kernel Release",0),
                              ("3.6","Linux kernel Release",0),
                              ("3.7","Linux kernel Release",0),
                              ("3.8","Linux kernel Release",0),
                              ("3.9","Linux kernel Release",0),
                              ("3.10","Linux kernel Release",0),
                              ("3.11","Linux kernel Release",0),
                              ("3.12","Linux kernel Release",0),
                              ("3.13","Linux kernel Release",0), 
                              ("3.14","Linux kernel Release",0), 
                              ("3.15","Linux kernel Release",0), 
                              ("3.16","Linux kernel Release",0),
                              ("3.17","Linux kernel Release",0),
                              ("3.18","Linux kernel Release",0),
                              ("4.1","Linux kernel Release",0) ]
	    if inst == 0:
	        (code,tag) = dialogObj.radiolist("Select appropriate kernel version",width=100,
		                list_height=21,choices = supportMatrix)
	    else:
	        (code,tag) = dialogObj.radiolist("Select appropriate kernel version (choose at least one)",width=100,
		                list_height=21,choices = supportMatrix)
	    ret = checkExit(code,dialogObj,1)
            if ret == None :
                 self.promptUnsupported(dialogObj,kversion)
		 return ret
            elif ret == 1 :
		os.system('clear')
                sys.exit(-1)
            elif ret == 0 :
                if len(tag) < 1 :
                    return -1
                self.UNAME_R = tag[:]
		self.kernel_ver = self.UNAME_R
		return 0
	else:
	    os.system('clear')
	    sys.exit(-1)

    def promptBypassError( self, dialogObj):
	if self.uninstall:
	    mode = "uninstallation"
	else:
	    mode = "installation"
	msg = "Bypass components can't be used with other components."
        msg += "Press <No> to exit. Press <yes> to continue %s without "%(mode)
        msg += "other components."
        code = dialogObj.yesno(msg,width=75)
        tret = checkExit(code,dialogObj,self.promptBypassError)
        self.components = ["bypass"]
	return tret

    def promptWDTOEError( self, dialogObj):
        if self.uninstall:
            mode = "uninstallation"
        else:
            mode = "installation"
        msg = "WD-TOE components can't be used with other components."
        msg += "Press <No> to exit. Press <yes> to continue %s without "%(mode)
        msg += "other components."
        code = dialogObj.yesno(msg,width=75)
        tret = checkExit(code,dialogObj,self.promptBypassError)
	if "wdtoe_wdudp" in self.components :
		self.components = ["wdtoe_wdudp"]
	else:
	        self.components = ["wdtoe"]
	return tret

    def promptNicError( self, dialogObj):
	if self.uninstall:
	    mode = "uninstallation"
	else:
	    mode = "installation"
	msg = "NIC components can't be used with other components."
        msg += "Press <No> to exit. Press <yes> to continue %s without "%(mode)
        msg += "other components."
        code = dialogObj.yesno(msg,width=75)
        tret = checkExit(code,dialogObj,self.promptBypassError)
        self.components = ["nic"]
	return tret
   
    def promptFcoePduError( self, dialogObj, drv):
	if self.uninstall:
            mode = "uninstallation"
        else:
            mode = "installation"
        msg = "Fcoe_pdu_offload_target components can't be used with %s component.\n\n"%(drv)
        msg += "Press <No> to exit. Press <yes> to continue %s without "%(mode)
        msg += "fcoe_pdu_offload_target component."
        code = dialogObj.yesno(msg,width=75)
        tret = checkExit(code,dialogObj,self.promptToeError)
        self.components.remove("fcoe_pdu_offload_target")
        return tret
 
    def promptToeError( self, dialogObj,drv):
	if self.uninstall:
	    mode = "uninstallation"
	else:
	    mode = "installation"
	msg = "toe_ipv4 components can't be used with %s component."%(drv)
        msg += " Press <No> to exit. Press <yes> to continue %s without "%(mode)
        msg += "toe_ipv4 component."
        code = dialogObj.yesno(msg,width=75)
        tret = checkExit(code,dialogObj,self.promptToeError)
        self.components.remove("toe_ipv4")
	return tret

    def promptFcoeError( self, dialogObj):
	if self.uninstall:
	    mode = "uninstallation"
	else:
	    mode = "installation"
	msg = "FCoE target & FCoE intiator components can't be choosen simultaneously."
        msg += "Press <No> to exit. Press <yes> to continue %s without "%(mode)
        msg += "FCoE target components."
        code = dialogObj.yesno(msg,width=75)
        tret = checkExit(code,dialogObj,self.promptToeError)
        self.components.remove("fcoe_full_offload_target")
	return tret

    def promptOFAError( self,dialogObj):
	if self.uninstall:
	    mode = "uninstallation"
	else:
	    mode = "installation"
	msg = "No OFED headers are found and compilation with kernel headers is refused."
        msg += "Press <No> to exit. Press <yes> to continue %s without "%(mode)
        msg += "iwarp & libs components."
        code = dialogObj.yesno(msg,width=75)
        checkExit(code,dialogObj,self.promptOFAError)
        if "all" in self.components:
            return self.components
        if "iwarp" in self.components and len(self.components) != 1 :
            self.components.remove("iwarp")
        if "libs" in self.components and len(self.components) != 1 :
            self.components.remove("libs")
        else :
            msg = "iWARP was the only component "
            msg += "or all the components were asked to be install "
            msg += "Hence aborting"
            a.infobox(msg,width=75)
            raise(exitException)
        
    def promptSummary(self,a,ret,install):
        c,r = getRowColumn()
        if ret and not install :
            msg = "Installation Failed.\n"
        elif ret and install :
            msg = "Uninstallation failed.\n"
        elif not ret and install :
            msg = "Uninstallation successful.\n"
        else :
            msg = "Installation completed successfully. "
            msg += "Please reboot the host for the changes to take effect. \n"
        msg += "To view log messages please refer install.log.\n"
	cmd = "cat install.log | grep make: -A 0  | wc -l"
        sts, rmlinecnt = commands.getstatusoutput(cmd)
        readFile = open("install.log")
        lines = readFile.readlines()
        readFile.close()
	lncount = len(lines)
	toRemove = []
	if lncount <= 15:
		lncountLow = lncount
	else:
		lncountLow = lncount -15
	for i in range(lncountLow,lncount):
             if lines[i].find('make: Nothing to be done') != -1:
                toRemove.append(i)
	for i in toRemove:
	     try :
	         del(lines[i])
	     except IndexError:
	         i=i-1
		 del(lines[i])
		 pass
	    
        if int(rmlinecnt) > 0 :
             w = open("install.log",'w')
             w.writelines(lines)
             w.close()
	if ( "all" in self.components or "iwarp" in self.components ) and \
                (self.uninstall == False):
             ofa_msg = "iWARP driver is built/compiled against"
             if self.ofa_kernel == None or self.ofa_kernel == '':
                  ofa_msg += " inbox kernel RDMA/OFED modules.\n"
             else:
                cmd = "rpm -qa | grep -w -m 1 kernel-ib-1.5 | awk -F\"-\" '{print $3}'"
                sts, ofa_version = commands.getstatusoutput(cmd)
                if ofa_version == '':
                    cmd = "rpm -qa | grep -w -m 1 compat-rdma-3.5 | awk -F\"-\" '{print $3}'"
                    sts, ofa_version = commands.getstatusoutput(cmd)
                str = " OFED " + ofa_version + " Modules.\n"
                ofa_msg += str
             sumHan = open("Summary","w")
             sumHan.write(ofa_msg)
             sumHan.close()
        cmd = 'cat install.log | grep -A 20 -B 1 "Action"  >> Summary'
        commands.getstatusoutput(cmd)
        code = a.textbox(filename='Summary',
                       width=(int(c)-5),
		       height=(int(r)-5),
                       exit_label="Ok"
                       )
        cmd = 'rm -f Summary'
        commands.getstatusoutput(cmd)
        code = a.yesno(msg,
                       width=(int(c)-5),
		       height=(int(r)-5),
                       yes_label="View log",
                       no_label="Exit")
        ret = checkExit(code,a)
        if ret == None :
           ret = self.promptSummary(a,ret,install)
	   return ret
        if ret == 0:
            if ( (r != None) and (c != None) ):
                a.textbox("install.log",width=(int(c)-5),height=(int(r)-5))
            else :
                a.textbox("install.log")
        else :
            return

    def promptOfedsummary(self,a):
	c,r = getRowColumn()
        mode = "installation"
        msg = "OFED Installation Failed, Hence Aborting... \nPlease refer %s/OFED/OFED_install.log for details"%(os.getcwd())
	code = a.msgbox(msg,width=84,height=(int(r)-20),
                             title="OFED Summary",
                            ok_label="Exit")
        raise(exitException)

    def promptNoIscsi(self,a):
	if self.uninstall:
	    mode = "uninstallation"
	else:
	    mode = "installation"
        msg = "The dependencies for Open Iscsi openssl-devel was not found."
        msg += "Press <No> to exit. Press <yes> to continue %s without "%(mode)
        msg += "Open iSCSI Components"
        code = a.yesno(msg,width=75)
        checkExit(code,a,self.promptNoIscsi)
	if "all" in self.components:
	    return self.component
        if "iscsi_pdu_initiator" in self.components and len(self.components) != 1 :
            self.components.remove("iscsi_pdu_initiator")
            return self.components
        else :
            msg = "iscsi_pdu_initiator was the only component "
            msg += "or all the components were asked to be install "
            msg += "Hence aborting"
            a.infobox(msg,width=75)
            raise(exitException)

    def promptNolibpcap(self,a):
        msg = "The dependencies for sniffer, libpcap was not found."
        msg += "Press <No> to exit. Press <yes> to ask installer not to build "
        msg += "and install Sniffer Components."
        code = a.yesno(msg,width=75)
        checkExit(code,a,self.promptNolibpcap)
	if "all" in self.components:
	    return self.component
        if "sniffer" in self.components and len(self.components) != 1 :
            self.components.remove("sniffer")
            return self.components
        else :
            msg = "Sniffer was the only component "
            msg += "or all the components were asked to be install "
            msg += "Hence aborting"
            a.infobox(msg,width=75)
            raise(exitException)
    
    def promptNotcpdump(self,a):
	if self.uninstall:
	    mode = "uninstallation"
	else:
	    mode = "installation"
        msg = "The dependencies for sniffer, tcpdump was not found."
        msg += "Press <No> to exit. Press <yes> to continue %s without "%(mode)
        msg += "Sniffer Components."
        code = a.yesno(msg,width=75)
        checkExit(code,a,self.promptNotcpdump)
	if "all" in self.components:
	    return self.component
        if "sniffer" in self.components and len(self.components) != 1 :
            self.components.remove("sniffer")
            return self.components
        else :
            msg = "sniffer was the only component "
            msg += "or all the components were asked to be install "
            msg += "Hence aborting"
            a.infobox(msg,width=75)
            raise(exitException)

    def promptNoLibs(self,a):
	if self.uninstall:
	    mode = "uninstallation"
	else:
	    mode = "installation"
        msg = "The dependency for iWARP library(libcxgb4) libibverbs-devel was not found."
        msg += "Press <No> to exit. Press <yes> to continue %s without"%(mode)
        msg += " iWARP library(libcxgb4), WD_UDP libs, sniffer and  Component."
        code = a.yesno(msg,width=75)
        ret =  checkExit(code,a)
	removeSniffer=False
	removeLibs=False
        if ret == 0 :
            if "libs" in self.components: # or 'iwarp' in self.components :
                self.components.remove("libs")
		removeLibs = True
            if "sniffer" in self.components: # or 'iwarp' in self.components :
                self.components.remove("sniffer")
		removeSniffer = True
            if self.components != [] or self.components != None :
		if removeSniffer:
		     self.components.append("sniffer")
		if removeLibs:
		     self.components.append("libs")
                return self.components
            else :
                msg = "libs was the only component "
                msg += "or all the components were asked to be install "
                msg += "Hence aborting"
                a.infobox(msg,width=75)
                raise(exitException)
        else :
            self.promptNoLibs(a)

    def promptNoLibrdmacm(self,a):
	if self.uninstall:
	    mode = "uninstallation"
	else:
	    mode = "installation"
	msg = "The dependency for iWARP library(libcxgb4) librdmacm-devel was not found."
        msg += "Press <No> to exit. Press <yes> to continue %s without"%(mode)
        msg += " iWARP library(libcxgb4), WD_UDP libs, sniffer and  Component."
        code = a.yesno(msg,width=75)
        ret =  checkExit(code,a)
        if ret == 0 :
            if "libs" in self.components: # or 'iwarp' in self.components :
                self.components.remove("libs")
            if "sniffer" in self.components: # or 'iwarp' in self.components :
                self.components.remove("sniffer")
            if self.components != [] or self.components != None :
                return self.components
            else :
                msg = "libs was the only component "
                msg += "or all the components were asked to be install "
                msg += "Hence aborting"
                a.infobox(msg,width=75)
                raise(exitException)
        else :
            self.promptNoLibs(a)


class genCmdLine:
    ofatargets = [ 'iwarp', 'sniffer' ]
    def __init__(self,
                 c,
                 components=None,
                 tunnables=None):
        self.components = components
        self.tunnables = tunnables
        self.percent = 0
        self.c = c
        self.cmdline = []

    def genMake(self,a):
        cmdline = []
        self.checkDepsRoutine(a,texts="Checking dependencies")
        self.c.promptGaugeGen(a)
        try :
            self.c.updateGaugeGen(a,20)
            #self.checkToe()
            #self.checkLib()
	    #self.checkipv6()
            self.c.updateGaugeGen(a,60)
            self.genCmdLine()
            self.c.updateGaugeGen(a,100)
            self.c.stopGaugeGen(a)
            return
        except ValueError :
            pass

    def genUninstall(self,a):
        cmdline = []
        self.c.promptGaugeGen(a)
        try :
            self.genUnCmdLine()
	    self.c.updateGaugeGen(a,100)
	    self.c.stopGaugeGen(a)
            return
        except ValueError :
            pass

    def checkDepsRoutine(self,a,texts=""):
        self.c.promptGaugeGen(a,texts=texts)
        self.c.updateGaugeGen(a,20)
        if "all" in self.components:
            self.c.updateGaugeGen(a,40)
            if self.checkDepsOiscsi() != True :
                self.c.stopGaugeGen(a)
                self.alertNoIscsi(a)
                self.c.promptGaugeGen(a,texts=texts)
                self.c.updateGaugeGen(a,40)
            self.c.updateGaugeGen(a,20)
            try :
                self.c.stopGaugeGen(a)
            except : 
                pass
        else :
            self.c.updateGaugeGen(a,40)
            if "iscsi_pdu_initiator" in self.components :
                if self.checkDepsOiscsi() != True :
		    self.c.stopGaugeGen(a)
                    self.alertNoIscsi(a)
		    self.c.promptGaugeGen(a,texts=texts)
		    self.c.updateGaugeGen(a,60)
            self.c.updateGaugeGen(a,60)
            self.c.updateGaugeGen(a,100)
            self.c.stopGaugeGen(a)

    def alertNoIscsi(self,a):
        os.system("clear")
        self.components = self.c.promptNoIscsi(a)

    def alertNolibpcap(self,a):
        os.system("clear")
        self.components = self.c.promptNolibpcap(a)

    def alertNotcpdump(self,a):
        os.system("clear")
        self.components = self.c.promptNotcpdump(a)
    
    def alertNoLibs(self,a):
        os.system("clear")
        k = self.c.promptNoLibs(a)

    def alertNoLibrdmacm(self,a):
        os.system("clear")
        k = self.c.promptNoLibrdmacm(a)
    
    def genCmdLine(self) :
        temp = "make"
        temp1 = []
	if "all" in self.components:
	    temp = "make"
	    self.cmdline.append(temp)
	else:
            for i in self.components :
                if ( self.c.ofa_kernel != ' ' ) and ( i in self.ofatargets ) and self.c.ofa_kernel :
                    temp1.append(i.strip('"')+"_install OFA_DIR=" + self.c.ofa_kernel)
                else :
                    temp1.append(i+"_install")
	        temp1[len(temp1)-1] = temp1[len(temp1)-1].replace("inst=1","")
                self.cmdline = 'make ' + ' '.join(temp1)
	if self.c.configTune == 'Balanced Uwire':
	    self.cmdline += ' CONF=UNIFIED_WIRE'
	elif self.c.configTune == 'Low latency Networking':
	    self.cmdline += ' CONF=LOW_LATENCY'
	elif self.c.configTune == 'High capacity TOE':
	    self.cmdline += ' CONF=HIGH_CAPACITY_TOE'
	elif self.c.configTune == 'High capacity RDMA':
	    self.cmdline += ' CONF=HIGH_CAPACITY_RDMA'
	elif self.c.configTune == 'UDP Seg. Offload & Pacing':
	    self.cmdline += ' CONF=UDP_OFFLOAD'
	elif self.c.configTune == 'T5 No External Memory':
            self.cmdline += ' CONF=T5_WIRE_DIRECT_LATENCY'
	elif self.c.configTune == 'T5 High Capacity WD' :
            self.cmdline += ' CONF=HIGH_CAPACITY_WD '
	elif self.c.configTune == "T5 Hash Filter" :
	    self.cmdline += ' CONF=T5_HASH_FILTER '
	elif self.c.configTune == "RDMA Performance" :
	    self.cmdline += ' CONF=RDMA_PERFORMANCE '
	elif self.c.configTune == "iSCSI Performance" :
	    self.cmdline += ' CONF=ISCSI_PERFORMANCE'
	elif self.c.configTune == "Memory Free" :
	    self.cmdline += ' CONF=MEMORY_FREE'
	if self.c.UNAME_R != None:
	    self.cmdline += ' UNAME_R=%s'%(self.c.UNAME_R)
	if self.c.benchtools:
	    self.cmdline += ' BENCHMARKS=1 '
	if self.c.ipv6_enable :
	    self.cmdline += ' ipv6_disable=0 '
	else :
	    self.cmdline += ' ipv6_disable=1 '

    def genInstallOfed(self,ofedPkg):
	#self.cmdline='tar mxf OFED%s.tgz  ; '%(os.sep + ofedPkg)
	if os.path.isdir("OFED/%s"%(ofedPkg)):
	    cmd = "rm -rf OFED/OFED_install.log"
	    commands.getstatusoutput(cmd)
	    cmd2 = "python scripts/uninstall.py ofed"
	    commands.getstatusoutput(cmd2)
	    self.cmdline = '( cd OFED/%s && ./install.pl -c ofed.conf >> ../OFED_install.log 2>&1 )'%(ofedPkg) 
	else:
	    handler.write("OFED Extraction Failed / OFED directory not present")
	
        
    def genUnCmdLine(self):
        temp = "make "
	if "all" in self.components or (len(self.components) == len(self.c.supportMatrix[self.c.kvr])-1) :
	    temp = "make uninstall "
	    self.cmdline = temp + 'CONF=T4_UN'
	    if self.c.UNAME_R != None:
	         self.cmdline += ' UNAME_R=%s'%(self.c.UNAME_R)
	    return
        for i in self.components :
            temp += i.strip('"')+"_uninstall "
        self.cmdline = temp
	self.cmdline += 'CONF=T4_UN'
	if self.c.UNAME_R != None:
	    self.cmdline += ' UNAME_R=%s'%(self.c.UNAME_R)

    def checkToe(self):
        if "toe" in self.components :
            if "nic" in self.components :
                self.components.remove("nic")

    def checkLib(self):
        if "iwarp" in self.components :
            if "libs" in self.components :
                self.components.remove("libs")
    
    def checkipv6(self):
        if "ipv6" in self.components :
            if "nic" in self.components :
                self.components.remove("nic")

    def checkOfaKernel(self,c):
        if c.ofa_kernel != None :
            if os.path.isfile(os.path.join(c.ofa_kernel,"Module.symvers")):
                return True
        return False

    def checkDepsOiscsi(self):
        path = os.path.join("/","usr","include","openssl","evp.h")
        if os.path.isfile(path) :
            return True
        else :
            return False
    
    def checkDepstcpdump(self):
        path = commands.getstatusoutput('which tcpdump')[1].strip()
        if os.path.isfile(path) :
            return True
        else :
            return False
    
    def checkDepslibpcap(self):
	if os.uname()[4] == "x86_64" :
	    path = os.path.join("/","usr","lib64","libpcap.so.1")
            if os.path.isfile(path):
                return True
            else :
	        path = os.path.join("/","usr","lib64","libpcap.so.0")
                if os.path.isfile(path):
                    return True
                else :
                    return False
	else:
	    path = os.path.join("/","usr","lib","libpcap.so.1")
            if os.path.isfile(path):
                return True
            else :
	        path = os.path.join("/","usr","lib","libpcap.so.0")
                if os.path.isfile(path):
                    return True
                else :
                    return False

    def checkDepslibs(self):
        if os.uname()[4] == "x86_64" :
            path = os.path.join("/","usr","lib64","libibverbs.so")
            if os.path.isfile(path):
                return True
            else :
                return False
        else :
            path = os.path.join("/","usr","lib","libibverbs.so")
            if os.path.isfile(path):
                return True
            else :
                return False
    def checkDepslibrdmacm(self):
	if os.uname()[4] == "x86_64" :
            path = os.path.join("/","usr","lib64","librdmacm.so")
            if os.path.isfile(path):
                return True
            else :
                return False
        else :
            path = os.path.join("/","usr","lib","librdmacm.so")
            if os.path.isfile(path):
                return True
            else :
                return False

    def checkDeps(self):
        k = self.cmdline[0]      
        if "iscsi_pdu_initiator" in k :
            ret = self.checkDepsOiscsi()
            if not ret :
                self.cmdline[0] = self.cmdline[0].replace(
                    "iscsi_pdu_initiator","")
                self.cmdline[1] = self.cmdline[1].replace(
                    "iscsi_pdu_initiator_install","")
        if "iwarp" in k or "libs" in k:
            ret = self.checkDepslibs()
            if not ret :
                self.cmdline[0] = self.cmdline[0].replace(
                    "libs","")
                self.cmdline[1] = self.cmdline[1].replace(
                    "libs_install",)

class make:
    def __init__(self,a,c):
        self.c = c
        self.a = a
        self.kpaths = None
        self.error = False
	self.gaugeThreadExit  = None
	self.gaugeThread = None
	self.ofedstat = 0

    def checkDeps(self):
        pass

    def runBuild(self,cmdline, inst=0):
        j = 0
	ti = 0.5
        if self.checkBuild(self.kpaths) :
            self.c.promptGaugeGen(
                self.a,texts="Building and installing Modules")
            self.c.updateGaugeGen(self.a,j+0,progress="Cleaning :")
            self.cleanSource()
	    self.gaugeThreadExit = True
	    if cmdline.find("all") != -1:
		ti = 2
            self.gaugeThread = threading.Thread(target = gaugeUpdaterThread, args = (self.c,self.a,"Installing",self,ti ))
            self.gaugeThread.start()
	    if self.c.configTune == 'Low latency Networking' \
	        or self.c.configTune == 'High capacity TOE' \
	        or self.c.configTune == 'High capacity RDMA' \
		or self.c.configTune == 'T5 No External Memory' \
		or self.c.configTune == 'T5 High Capacity WD' \
		or self.c.configTune == 'T5 Hash Filter' \
		or self.c.configTune == 'RDMA Performance' \
		or self.c.configTune == 'iSCSI Performance' \
		or self.c.configTune == 'Memory Free' :
		self.cleanUninstall()
            #j+= 20
            #self.c.updateGaugeGen(self.a,j,progress="Building")
##            for i in cmdline:
##                (cmd,staus,pid) = self.runCmd(i)
##                j += 10
##                self.c.updateGaugeGen(self.a,j,progress="Installing")
            (cmd,staus,pid) = self.runCmd(cmdline)
	    self.gaugeThreadExit = False
	    self.gaugeThread.join()
	    time.sleep(1)
            j = 100
            self.c.updateGaugeGen(self.a,j,progress="Done")
            self.c.stopGaugeGen(self.a)
        else :
            self.kpaths = self.c.promptKernelSource(self.a, inst)
            cmdline = self.changeCmdLine(cmdline,self.kpaths)
            self.runBuild(cmdline, inst=1)

    def runOfedextract (self, ofedPkg, inst=0):
	cmdline = "(cd OFED ; tar xf %s.tgz)"%(ofedPkg)
	print cmdline
	j=0
        self.c.promptGaugeGen(
            self.a,texts="Extracting OFED")
        self.c.updateGaugeGen(self.a,j+0,progress="Extracting OFED ")
        self.cleanSource()
        self.gaugeThreadExit = True
        self.gaugeThread = threading.Thread(target = gaugeUpdaterThread, args = (self.c,self.a,"Extracting OFED",self ))
        self.gaugeThread.start()
        (cmd,staus,pid) = self.runCmd(cmdline)
        self.gaugeThreadExit = False
        self.gaugeThread.join()
        time.sleep(1)
        j = 100
        self.c.updateGaugeGen(self.a,j,progress="Done")
        self.c.stopGaugeGen(self.a)
    
    def runOfedinstall(self,cmdline, inst=0):
	j=0
        self.c.promptGaugeGen(
            self.a,texts="Installing OFED")
        self.c.updateGaugeGen(self.a,j+0,progress="Installing OFED :")
	self.cleanSource()
        self.gaugeThreadExit = True
        self.gaugeThread = threading.Thread(target = gaugeUpdaterThread, args = (self.c,self.a,"Installing OFED",self ))
        self.gaugeThread.start()
        (cmd,staus,pid) = self.runCmd(cmdline)
        self.gaugeThreadExit = False
        self.gaugeThread.join()
        time.sleep(1)
        j = 100
        self.c.updateGaugeGen(self.a,j,progress="Done")
        self.c.stopGaugeGen(self.a)
	if staus != 0 :
                self.ofedstat = 1
                handler.write("OFED Installation Failed, Please refer OFED/OFED_install.log for furthur details")
	
    def runUninstall(self,cmdline, inst=0):
        j = 0
        if self.checkBuild(self.kpaths) :
            self.c.promptGaugeGen(
                self.a,texts="Uninstalling Modules")
            self.c.updateGaugeGen(self.a,j+0,progress="Cleaning :")
            self.cleanSource()
            self.gaugeThreadExit = True
            self.gaugeThread = threading.Thread(target = gaugeUpdaterThread, args = (self.c,self.a,"Uninstalling",self ))
            self.gaugeThread.start()
            (cmd,staus,pid) = self.runCmd(cmdline)
            self.gaugeThreadExit = False
            self.gaugeThread.join()
            time.sleep(1)
            j = 100
            self.c.updateGaugeGen(self.a,j,progress="Done")
            self.c.stopGaugeGen(self.a)
        else :
            self.kpaths = self.c.promptKernelSource(self.a, inst)
            cmdline = self.changeCmdLine(cmdline,self.kpaths)
            self.runUninstall(cmdline, inst=1)

    def changeCmdLine(self,cmdline,paths):
        cmdline += " KSRC="+paths[0]
        cmdline += " KOBJ="+paths[1]
        return cmdline

    def checkBuild(self,kpaths):
        if kpaths == None :
            kpaths = []
            kpaths.append(os.path.join(
                "/","lib","modules",os.uname()[2],"build"))
        return os.path.isfile(os.path.join(kpaths[0],"Module.symvers"))

    def runCmd(self,cmd):
        k = subprocess.Popen(
                cmd,
                stdout=handler,
                stderr=handler,
                shell=True,
                executable="/bin/bash",
                stdin=None)
        k.wait()
        ret = k.poll()
        k.poll()
        if ret != 0 :
            self.error = True
        return cmd,k.returncode,k.pid

    def cleanSource(self):
	cmdline = 'make clean'
	if self.c.UNAME_R != None:
	    cmdline += ' UNAME_R=%s'%(self.c.UNAME_R)
        (cmd,staus,pid) = self.runCmd(cmdline)

    def cleanUninstall(self):
	custom_target = ['fcoe_full_offload_initiator','iscsi_pdu_target', 'iscsi_pdu_initiator']
	for i in custom_target:
	    if self.c.UNAME_R != None:
		(cmd,status,pid) =  self.runCmd("make %s_uninstall UNAME_R=%s &> /dev/null"%(i,self.c.UNAME_R))
	    else:
		(cmd,status,pid) =  self.runCmd("make %s_uninstall &> /dev/null"%(i))

class setupConf:
    def __init__(self):
        pass

    def addModprobeConf(self,components,tunnables,modconfTune):
        a = ["libs","tools","vnic"]
        count = 0
        for i in a:
            if i in components :
                count += 1
        if ( count == len(components) ) :
            return
        if not os.path.exists("/etc/modprobe.d") :
            os.mkdir("/etc/modprobe.d")
        self.addToModprobeConf(components,tunnables,modconfTune)

    def fixConfig(self,components,configTune):
        target_config = None
        found=0
        config_files = {"Balanced Uwire"     : "build/src/network/firmware/t4-config.txt",
                "Low latency Networking"  : "build/src/network/firmware/low_latency_config/t4-config.txt",
                "High capacity TOE"  : "build/src/network/firmware/high_capacity_config/t4-config.txt",
                "High capacity RDMA" : "build/src/network/firmware/high_capacity_rdma/t4-config.txt",
		"UDP Seg. Offload & Pacing" : "build/src/network/firmware/udp_so_config/t4-config.txt",
		"T5 No External Memory" : "build/src/network/firmware/edc_only_config/t4-config.txt",
		"T5 High Capacity WD" : "build/src/network/firmware/high_capacity_wd/t4-config.txt",
		"T5 Hash Filter" : "build/src/network/firmware/hash_filter_config/t4-config.txt",
		"RDMA Performance" : "build/src/network/firmware/rdma_perf_config/t4-config.txt",
		"iSCSI Performance" : "build/src/network/firmware/iscsi_perf_config/t4-config.txt",
		"Memory Free" : "build/src/network/firmware/iscsi_perf_config/t4-config.txt"
                }
        confgOpts = ["Balanced Uwire", "Low latency Networking", "High capacity TOE" ,"High capacity RDMA",  
                     "UDP Seg. Offload & Pacing", "T5 No External Memory", "T5 High Capacity WD", "T5 Hash Filter", "RDMA Performance",
		     "iSCSI Performance", "Memory Free" ]
        for i in config_files.keys():
            if i == configTune:
                target_config = config_files[i]
                found=1
        if found == 1 and "fcoe_full_offload_target" not in components:
            cmd = "cp -f %s /lib/firmware/cxgb4/"%(target_config) 
            #commands.getoutput(cmd) #Prevent config files from getting copied with tools(22936).
        
                  
    def remModprobeConf(self):
	if  os.path.exists("/etc/modprobe.d/chelsio.conf") :
            os.remove("/etc/modprobe.d/chelsio.conf")

    def removeBlacklists(self):
        desc = open("/etc/modprobe.d/blacklist",'r').readlines()
        for i in desc :
            if "cxgb4" in i :
                # replace line in blacklist
                pass

    def searchModprobeConf(self,desc):
        for i in desc :
            if ( i.split(" ")[2] ) :
                k = i.split(" ")[2]
                if k == "cxgb4" or k == "t4_tom" :
                    return -1

    def isAllow(self):
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
	

    def addToModprobeConf(self,components,tunnables,modconfTune):
	self.remModprobeConf()
        handlers=open("/etc/modprobe.d/chelsio.conf",'w')
        msg = ""
        options,tx_coal = self.getOptions(tunnables)
	if modconfTune == "T5 Hash Filter" or modconfTune == "hash-filter-config" :
	     hashfilter = "use_ddr_filters=1"
	else :
	     hashfilter = ""
	if tx_coal == 1:
             msg = "install cxgb4 /sbin/modprobe cxgb4 %s tx_coal=1 --ignore-install "%(hashfilter) + str(self.isAllow()) + ' $CMDLINE_OPTS;'
	elif tx_coal == 2:
             msg = "install cxgb4 /sbin/modprobe cxgb4 %s tx_coal=2 --ignore-install "%(hashfilter) + str(self.isAllow()) + ' $CMDLINE_OPTS;'
	else:
	    msg = 'install cxgb4 /sbin/modprobe cxgb4 %s --ignore-install'%(hashfilter) + str(self.isAllow()) + ' $CMDLINE_OPTS;'
        msg += ' /sbin/t4_perftune.sh ' + options
	msg += ' > /dev/null ||. ; \n'
	handlers.write(msg)
        handlers.close()

    def removeAllPriorListing(self):
        import re
	file = None
	if os.path.isfile('/etc/modprobe.d/chelsio.conf'):
	     file = '/etc/modprobe.d/chelsio.conf'
	else :
	     return None
	handlers=open(file,'r')
        desc = handlers.read()
        handlers.close()
        k = re.findall("^(install[\t ]+cxgb4.+)",desc,re.MULTILINE)
        if k != None :
            for i in k :
                desc = desc.replace(i,"").strip('\n')
        return desc

    def getOptions(self,tunnables):
        desc = ""
	tx_coal = ""
	if ("Enable Binding IRQs to CPUs" in tunnables or "enable-affinity" in tunnables ) :
            desc += ' '
        else: 
            desc += "-C "
        if ("Retain IRQ balance daemon" in tunnables or "retain-irq-daemon" in tunnables ) :
            desc += '-D '
        if ("TX-Coalasce" in tunnables or "tx-coalasce" in tunnables ) :
            tx_coal = 2
        if ("no TX-Coalasce" in tunnables or "no-tx-coalasce" in tunnables ) :
            tx_coal = 1
        return desc,tx_coal

class exitException(Exception):
    pass

class cmds:
    customtarget = [ 'all','vnic','nic', 'bonding','fcoe_full_offload_initiator','fcoe_pdu_offload_target','toe','iwarp', \
                     'iscsi_pdu_target', 'udp_offload', 'iscsi_pdu_initiator', 'toe_ipv4', 'bypass', 'sniffer', \
                     'ba_tools', 'wdtoe', 'wdtoe_wdudp', 'rdma_block_device', 'tools' ]
    ofatargets = [ 'iwarp','sniffer']
    tuning = ['disable-affinity','enable-affinity','retain-irq-daemon','tx-coalasce']
    supportMatrix = {"2.6.18-128.el5" : ["bonding", "nic", "toe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer","udp_offload", "tools"], 
                     "2.6.18-164.el5" : ["bonding", "nic", "toe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer","udp_offload", "tools"], 
                     "2.6.18-194.el5" : ["bonding", "nic", "toe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer","udp_offload", "tools"], 
                     "2.6.18-238.el5" : ["bonding", "nic", "toe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "udp_offload", "tools"], 
                     "2.6.18-274.el5" : ["bonding", "nic", "toe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer","udp_offload", "tools"],
                     "2.6.18-308.el5" : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "udp_offload", "tools"],
                     "2.6.18-348.el5" : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "udp_offload", "tools"],
                     "2.6.18-371.el5" : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "udp_offload", "tools"],
                     "2.6.18-398.el5" : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "vnic", "iwarp", "iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "sniffer", "tools", "udp_offload"],
                     "2.6.32.12"  : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "vnic", "iwarp", "udp_offload", \
                                     "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                     "sniffer", "tools"],
                     "3.0.13"     : ["bonding", "nic", "toe", "wdtoe_wdudp", "bypass","iscsi_pdu_target", "udp_offload", \
                                     "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "vnic", "iwarp", \
                                     "sniffer", "tools"],
                     "3.0.76"     : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "udp_offload","iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "vnic", "iwarp", \
                                     "sniffer", "tools"],
                     "3.0.101"     : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "udp_offload","iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "vnic", "iwarp", \
                                     "sniffer", "tools"],
                     "3.12.28-4"  : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "udp_offload","iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "vnic", "iwarp", \
                                     "sniffer", "rdma_block_device", "tools"],
                     "3.12.49-11"  : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "udp_offload","iscsi_pdu_target", \
                                     "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "vnic", "iwarp", \
                                     "sniffer", "rdma_block_device", "tools"],
                     "2.6.32-71.el6"  : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools"],
                     "2.6.32-131.0.15.el6"  : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools"],
                     "2.6.32-220.el6"  : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools"],
                     "2.6.32-279.el6"  : ["bonding", "nic", "toe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools"],
                     "2.6.32-358.el6"  : ["bonding", "nic", "toe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools"],
                     "2.6.32-431.el6"  : ["bonding", "nic", "toe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools"],
                     "2.6.32-504.el6"  : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools"],
                     "2.6.32-573.el6"  : ["bonding", "nic", "toe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools"],
                     "3.10.0-123.el7.x86_64"  : ["bonding", "nic", "toe", "wdtoe_wdudp","bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools"],
                     "3.10.0-229.el7.x86_64"  : ["bonding", "nic", "toe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools"],
                     "3.10.0-229.el7.ppc64"  : ["nic", "toe", "iwarp", "iscsi_pdu_target", "iscsi_pdu_initiator", \
                                          "tools"],
                     "3.10.0-229.ael7b.ppc64le"  : ["nic", "toe", "iwarp", "iscsi_pdu_target", "iscsi_pdu_initiator", \
                                          "tools"],
                     "3.10.0-327.el7.x86_64"  : ["bonding", "nic", "toe", "wdtoe_wdudp", "bypass", "vnic", "iwarp", "udp_offload", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                      "sniffer", "tools"],
                     "2.6.35"      : ["bonding", "nic", "toe", "udp_offload","bypass", "fcoe_full_offload_initiator", "vnic", "iwarp", \
                                      "iscsi_pdu_target", "iscsi_pdu_initiator", "sniffer", \
                                      "udp_offload", "tools"],
                     "3.2.0-23"      : ["bonding", "nic", "toe", "vnic", "iscsi_pdu_target","iwarp", "bypass", \
                                        "udp_offload", "tools"],
                     "3.5.0-23"      : ["bonding", "nic", "toe", "wdtoe_wdudp", "iwarp", "bypass", "vnic", "udp_offload", \
                                        "tools"],
                     "3.13.0-32"     : ["bonding", "nic", "toe", "wdtoe_wdudp", "iwarp", "bypass", "vnic", "udp_offload", \
                                        "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                        "sniffer", "tools"],
                     "3.16.0-30"     : ["bonding", "nic", "toe", "wdtoe_wdudp", "iwarp", "bypass", "vnic", "udp_offload", \
                                        "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                        "sniffer", "tools"],
                     "3.19.0-25"     : ["bonding", "nic", "toe", "wdtoe_wdudp", "iwarp", "bypass", "vnic", "udp_offload", \
                                        "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", \
                                        "sniffer", "tools"],
                     "3.1"      : ["bonding", "nic", "toe", "wdtoe_wdudp","vnic", "iwarp", "bypass", \
                                   "fcoe_full_offload_initiator", "iscsi_pdu_target","iscsi_pdu_initiator", \
                                   "sniffer", "udp_offload", "tools"],
                     "3.4"      : ["bonding", "nic", "toe", "wdtoe_wdudp","vnic", "iwarp", "bypass", \
                                   "fcoe_full_offload_initiator", "iscsi_pdu_target","iscsi_pdu_initiator", \
                                   "sniffer", "udp_offload", "tools"],
                     "3.5"      : ["bonding", "nic", "toe", "wdtoe_wdudp","vnic", "iwarp", "bypass", \
                                   "fcoe_full_offload_initiator", "iscsi_pdu_target","iscsi_pdu_initiator", \
                                   "sniffer", "udp_offload", "tools"],
                     "3.6"	: ["bonding", "nic", "toe", "wdtoe_wdudp","toe_ipv4", "bypass", "vnic", "iwarp", \
                                   "udp_offload", "iscsi_pdu_target", "iscsi_pdu_initiator", "fcoe_full_offload_initiator", "fcoe_pdu_offload_target", \
                                   "sniffer", "tools"],
                     "3.7"      : ["bonding", "nic", "toe", "wdtoe_wdudp","vnic", "iwarp", "bypass", \
                                   "fcoe_full_offload_initiator", "sniffer", "udp_offload", \
                                   "iscsi_pdu_target", "iscsi_pdu_initiator", "tools"],
                     "3.8"      : ["bonding", "nic", "toe", "vnic", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "bypass", "udp_offload", "tools"],
                     "3.9"      : ["bonding", "nic", "toe", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "bypass", "udp_offload", "tools"],
                     "3.10"      : ["bonding", "nic", "toe", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "bypass", "udp_offload", "tools"],
                     "3.11"      : ["bonding", "nic", "toe", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "bypass", "udp_offload", "tools"],
                     "3.12"      : ["bonding", "nic", "toe", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "bypass", "udp_offload", "tools"],
                     "3.13"      : ["bonding", "nic", "toe", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "fcoe_full_offload_initiator", "bypass", "udp_offload", "tools"],
                     "3.16"      : ["bonding", "nic", "toe", "iwarp", "iscsi_pdu_initiator", "iscsi_pdu_target", "fcoe_full_offload_initiator", "bypass", "udp_offload", "tools"],
                     "3.17"      : ["bonding", "nic", "toe", "wdtoe_wdudp","toe_ipv4", "bypass", "vnic", "iwarp", "udp_offload", \
				    "rdma_block_device", "iscsi_pdu_initiator", "iscsi_pdu_target", "fcoe_full_offload_initiator", "sniffer", "tools"],
                     "3.18"      : ["bonding", "nic", "toe", "wdtoe_wdudp","toe_ipv4", "bypass", "vnic", "iwarp", "udp_offload", \
				    "rdma_block_device", "iscsi_pdu_initiator", "iscsi_pdu_target", "fcoe_full_offload_initiator", "sniffer", "tools"],
                     "4.1"      : ["bonding", "nic", "toe", "wdtoe_wdudp","toe_ipv4", "bypass", "vnic", "iwarp", "udp_offload", \
				    "rdma_block_device", "iscsi_pdu_initiator", "iscsi_pdu_target", "fcoe_full_offload_initiator", "sniffer", "tools"]

                                    }
  
    ofedsupportMatrix1 = dict.fromkeys(['2.6.18-274', '2.6.32-71', '2.6.32-131', '2.6.32.12', '2.6.35'], ['1.5.4.1'])
    ofedsupportMatrix1.update(dict.fromkeys(["2.6.32-358"],['3.12-1']))
    ofedsupportMatrix1.update(dict.fromkeys(["3.0.76", "2.6.32-431", "2.6.32-504", "3.10.0-123", "3.12.28-4"], ['3.18-1', '3.12-1']))
    ofedsupportMatrix1.update(dict.fromkeys(["3.10.0-229", "2.6.32-573", "3.18.25", "3.0.101-63", "3.18"],['3.18-1']))


    def __init__(self):
        self.target = None
        self.target_bak = []
        self.cmdline = []
        self.useofa = None
        self.ofa = None
        self.tunes = None
        self.parser = None
        self.uninstall = None
        self.ksrc = None
        self.kobj = None
	self.silent = False
	self.clusDeploy = False
	self.machineFile = None
	self.nodes = []
	self.configTune = None
	self.logDir = os.path.abspath('.') + os.sep + "logs"
	self.install_ofed = False
	self.ofedinstver = None
	self.installOfed = False
	self.genRpmpack = False
	self.ofedcpkgName = None
	self.ofedkver = None
	self.disable_ipv6_support = False
	self.benchtools = False
	self.ofed_install_opt = None
	self.clust_install_opt = ""
	self.CUNAME_R = None
	self.kernel_up = None

    def checkTargets(self):
        for i in self.target :
            if i not in self.customtarget :
                print "Target Error : No such target '"+i+"'\n"
                return False
        return True

    def checkTunnable(self):
        if self.tunes == None:
            return True 
        tempTarget = self.tunes.split()
        for i in tempTarget :
            if i not in self.tuning :
                return False
        return True
    
    def parseMachineFile(self):
	readFile =  open(self.machineFile,'r')
	lines = readFile.readlines()
	readFile.close()
	for line in lines:
	    if not line.startswith('#') and not line.strip() == '':
		self.nodes.append(line.strip())
	if len(self.nodes) == 0 :
	    print "Machinefile is empty, aborting the installer."
	    sys.exit(-1)
	for ix in range(0,len(self.nodes)):
	    node = self.nodes[ix]
	    if ( ix < len(self.nodes) - 1 ) and node in self.nodes[ix+1:]:
		print "Error : Duplicate entries found in machinefile."
		sys.exit(-1)

    def checkSshConf(self):
	cmd = "cat /etc/ssh/sshd_config | grep MaxStartups"
	sts,out = commands.getstatusoutput(cmd)
	if sts != 0:
	    return
	if out.startswith('#'):
	    return
	maxStartUp = out.split()[-1]
	if int(maxStartUp) < len(self.nodes):
	    print "Error : ssh is configured for a maximum of only %s session"%(maxStartUp)
	    print "        Increase the value of MaxStartups in /etc/ssh/sshd_config to %d and restart the installation"%(len(self.nodes))
	    sys.exit(1)

    def checkNodes(self):
	err=0
	for node in self.nodes:
	    cmd = "ping -c 5 " + node
	    sts, out = commands.getstatusoutput(cmd)
	    if sts != 0 :
		print "The %s machine is not reachable via ping, check the connectivity and restart the installation"%(node)
		err=1
	return err

    def checkSshConn(self):
	err=0
	for node in self.nodes:
	    cmd = "ssh -o PasswordAuthentication=no %s ls"%(node)
	    sts, out = commands.getstatusoutput(cmd)
	    if sts != 0 :
		print "The password-less ssh is not setup for %s machine, setup password-less ssh and restart the installation"%(node)
		err=1	
	return err	
    
    def getLogs(self):
	nodeThreadArr= []
        ix = 0
	for node in self.nodes:
            nodeThreadArr.append(threading.Thread(target = getLogsThread, args = (self,node )))
            nodeThreadArr[ix].start()
            ix+=1
        for thread in nodeThreadArr:
            thread.join()

    def parseLogs(self):
	print '\n---------------------------'
	print 'Deployment Result Summary'
	print '---------------------------'
	print ''
	failedNodes = []
	depsNodes = []
	for node in self.nodes:
	    sumFile = self.logDir + os.sep + node + os.sep + 'Summary'
	    depFile = self.logDir + os.sep + node + os.sep + 'deps.log'
	    depErrFile = self.logDir + os.sep + node + os.sep + 'deployerror.log'
	    if os.path.isfile(sumFile):
	       handler = open(sumFile,'r')
	       content = handler.readlines()
	       handler.close()
	       for line in content:
	          if line.find('Failed') != -1 :
		     failedNodes.append(node)
	    if os.path.isfile(depFile):
		depsNodes.append(node)
            if os.path.isfile(depErrFile) :
		handler = open(depErrFile,'r')
		content = handler.readlines()
		handler.close()
		for line in content:
		   if line.find('Error: while') and not node in failedNodes :
		      failedNodes.append(node)	
	if len(failedNodes) == 0 and len(depsNodes) == 0:
	    print "\nCluster Deployment is passed on  all the nodes."
	if len(failedNodes) != 0 :
	    print "\nCluster Deployment is failed on the following nodes:"
	    for node in failedNodes: print node
	    print "\nThe installation logs can be found in %s directory"%(self.logDir + os.sep + node + os.sep + "install.log")
	if len(depsNodes) != 0 :
	    print "\nCluster Deployment is failed due to dependency issues on the following nodes:"
	    for node in depsNodes: print node
	    print "\nThe dependencies logs can be found in %s file."%(self.logDir + os.sep + node + os.sep + "deps.log")
		

    def createLogsDir(self):
	if os.path.isdir(self.logDir):
	    cmd = 'rm -rf ' + self.logDir
	    sts, out = commands.getstatusoutput(cmd)
	    if sts != 0:
		print "Removing existing logs directories failed, remove the logs directory and restart the installation."
		sys.exit(1)
	os.mkdir(self.logDir)
	for node in self.nodes:
	    os.mkdir(self.logDir + os.sep + node)

    def starthmgDeploy(self):
	nodeThreadArr= []
	ix = 0
        for node in self.nodes:
            nodeThreadArr.append(threading.Thread(target = clusterhmgDeployerThread, args = (self,node )))
            nodeThreadArr[ix].start()
            ix+=1
        for thread in nodeThreadArr:
            thread.join()
        return 0
	
    def startDeploy(self):
	nodeThreadArr= []
	ix = 0
        rawPkgName="ChelsioUwire-2.12.0.3"
        pkgName="ChelsioUwire-2.12.0.3.tar.gz"
        pkgDir= os.path.abspath('../.')
	currDir = os.path.abspath('.')
        cmd = "ls " + pkgDir + os.sep + pkgName
        sts, out = commands.getstatusoutput(cmd)
        if sts != 0:
	    os.chdir(pkgDir)
	    cmd = "tar czf " + pkgName + '  ' + rawPkgName
	    sts, out = commands.getstatusoutput(cmd)
	    if sts != 0:
		print "Creating tar-ball of %s failed, aborting the installation"%(pkgDir+ os.sep + rawPkgName)
		return -1
	    os.chdir(currDir)
	for node in self.nodes:
	    nodeThreadArr.append(threading.Thread(target = clusterDeployerThread, args = (self,node )))
	    nodeThreadArr[ix].start()
	    ix+=1
	for thread in nodeThreadArr:
	    thread.join()
	return 0
	
    def parseArgs(self,args):
        from optparse import OptionParser, SUPPRESS_HELP, OptionGroup
        install = False
        uninstall = False
        parser = OptionParser(
            usage = "usage: %prog [options] arg",
            description='Installer for Chelsio Unified wire drivers')
	
	inGroup = OptionGroup(parser, "Install Options")
	unGroup = OptionGroup(parser, "Uninstall Options")
	cmnGroup = OptionGroup(parser, "Install/Uninstall global Options")
	clusGroup = OptionGroup(parser, "Cluster Deployment Options")
        inGroup.add_option("-c", "--custom", dest="target",
                          help="Targets to be installed. "+
                          "Targets can be one or many(':' separated) of nic, vnic, toe, wdtoe, wdtoe_wdudp, bonding, iwarp, "+
                          "bypass, iscsi_pdu_target, iscsi_pdu_initiator, tools, "+
                          "fcoe_full_offload_initiator, fcoe_pdu_offload_target, sniffer, udp_offload, all. ")
	inGroup.add_option("-O",dest="ofedv", action="store_true", default="False",help="Install OFED to your machine" )
	inGroup.add_option("--disable-ipv6", dest="disable_ipv6_support", action="store_true", \
				default="False", help="Disable IPv6 Offload" )
	inGroup.add_option("--benchmarks", dest="benchtools", action="store_true", \
				default="False", help="Install benchmark tools")	
        unGroup.add_option("-u", "--uninstall", dest="uninstall_targets",
                          help="uninstall the targets. "+
                          "Targets can be one or many(':' separated) of nic, vnic, toe, wdtoe, wdtoe_wdudp, toe_ipv4, bonding, iwarp, "+
                          "rdma_block_device, bypass, iscsi_pdu_target, iscsi_pdu_initiator,  tools, "+
                          "fcoe_full_offload_initiator, fcoe_pdu_offload_target, sniffer, udp_offload, all. ")
        inGroup.add_option("-t","--tune", dest="tuning",
                          help="Select the Performance Tuning."+
                          "Tuning can be one or many(':' separated) of 'enable-affinity', 'retain-irq-daemon', 'tx-coalasce'.")
        clusGroup.add_option("-C",dest="cluster",action="store_true",default="False",
                          help="Start deployment on Cluster nodes specified in machinefile.")
        clusGroup.add_option("-m","--machinefile", dest="machinefile",
                          help="Path to the machinefile which contains lists of hostname/ipaddress.")
        cmnGroup.add_option("-k","--ksrc", dest="KSRC",
                          help="Path to kernel source.")
        cmnGroup.add_option("-o","--kobj", dest="KOBJ",
                          help="Path to kernel object.")
        clusGroup.add_option("-s","--silent", dest="silent",action="store_true", help=SUPPRESS_HELP)
        clusGroup.add_option("-x","--firmConf", dest="confMode",help=SUPPRESS_HELP)

	parser.add_option_group(cmnGroup)
	parser.add_option_group(inGroup)
	parser.add_option_group(unGroup)
	parser.add_option_group(clusGroup)
        a = sys.argv[1:]
        (options, args) = parser.parse_args(sys.argv[1:])
        self.parser = parser
	if args != []:
	   parser.parse_args(['-h'])
	   sys.exit(-1)
	if a :
	    if '-O' in a :
		#self.buildofedInstall(None)
		#self.buildofedInstall(None)
		#print "Ofed"
		self.ofed_install_opt = "install-ofed"
		self.installOfed = True	
	    if '--disable-ipv6' in a :
		self.disable_ipv6_support = True
	    if '--benchmarks' in a :
		self.benchtools = True
	    else :
		self.benchtools = False
            if '-u' in a :
                self.uninstall = True
                uninstall = True
                self.target = options.uninstall_targets   
            if options.target in a :
                self.target = options.target
                install = True
                i = a.index(options.target)+1
                while ( i < (len(a)) and not a[i].startswith('-')) :
                    self.target += ':'+a[i]
                    i += 1
	    if '-s' in a :
		self.silent = True
	    if '-x' in a:
		self.configTune =  options.confMode
	    if '-m' in a :
		self.machineFile = options.machinefile
		if not os.path.isfile(self.machineFile):
		     print ''
                     print "Error : The machinefile %s doesn't exist or not a valid file. \n"%(os.path.join(os.getcwd(),self.machineFile))
                     sys.exit(-1)
	    if '-C' in a:
		self.clusDeploy = True
		self.silent = True
	    if '-T' in a:
                self.configTune = options.configtune.split(':')[0].strip(' ')
            for ix in range(0,len(a)):
                if "--custom" in a[ix].split('=')[0]:
                    install = True
                    self.target = a[ix].split('=')[1]
                elif "--uninstall" in a[ix].split('=')[0]:
                    uninstall = True
                    self.uninstall = True
                    self.target = a[ix].split('=')[1]
                elif "--ksrc" in a[ix].split('=')[0]:
                    self.ksrc = a[ix].split('=')[1]
                elif "--kobj" in a[ix].split('=')[0]:
                    self.kobj = a[ix].split('=')[1]
                elif "--tune" in a[ix].split('=')[0]:
                    self.tunes = a[ix].split('=')[1]
		elif "--machinefile" in a[ix].split('=')[0]:
		    self.machineFile = a[ix].split('=')[1]
		elif "--configtune" in a[ix].split('=')[0]:
		    self.configTune = a[ix].split('=')[1]
		else:
                    continue;
            if "-t" in a :
                self.tunes = options.tuning
	    else :
		self.tunes = "disable-affinity"
                
            if options.KSRC in a :
                self.ksrc = options.KSRC
                if os.path.isfile(self.ksrc + os.sep + 'Module.symvers') == False :
                    self.errPath()
                    
            if options.KOBJ in a :
                self.kobj = options.KOBJ
                if os.path.isfile(self.kobj + os.sep + 'Module.symvers') == False :
                    self.errPath()
                    
            if self.ksrc != None and self.kobj == None :
        	print "Error : When using KSRC=<path>, the KOBJ=<path> must also be defined. Aborting the installation. \n"
	        sys.exit(-1)
	        
	    if self.ksrc == None and self.kobj != None:
        	print "Error : When using KOBJ=<path>, the KSRC=<path> must also be defined. Aborting the installation. \n"
	        sys.exit(-1)
	        
            if install and uninstall:
        	print "Error : Both uninstallation and installation is not supported simultaneously. Aborting the installation. \n"
	        sys.exit(-1)

	    if self.clusDeploy:
		if self.machineFile == None:
                     print "Error : Machine file is not specified. \n"
                     sys.exit(-1)
	if self.configTune == None:
	    self.configTune = "unified-wire-fcoe-init"

	if self.tunes != None :
            self.tunes = self.tunes.split(":")
            self.tunes = ' '.join(self.tunes)
            
	if self.target != None :
            self.target = self.target.split(":")
        else :
            self.target = []
            self.target.append('all')
	mode = None
	if self.uninstall:
	    mode = "uninstalltion"
        else: 
	    mode = "installation" 
	# Don't proceed if user has selected bypass & any other component.
	tempArr= []
	if not self.uninstall and "bypass" in self.target and len(self.target) > 1 :
	    tempArr.extend(self.target)
	    tempArr.remove("bypass")
	    if len(tempArr) > 1 :
		self.errBypass(mode)
	    if "tools" not in tempArr:
		self.errBypass(mode)
	# Don't proceed if user has selected WDTOE & any other component.
	tempArr= []
        if not self.uninstall and "wdtoe" in self.target and len(self.target) > 1 :
            tempArr.extend(self.target)
            tempArr.remove("wdtoe")
            if len(tempArr) > 1 :
                self.errWdtoe(mode)
            elif "tools" not in tempArr:
                self.errWdtoe(mode)
	tempArr= []
	if not self.uninstall and "nic" in self.target and len(self.target) > 1 :
            tempArr.extend(self.target)
            tempArr.remove("nic")
            if len(tempArr) > 1 :
                self.errNic(mode)
            if "tools" not in tempArr:
                self.errNic(mode)
        # Don't procced if toe_ipv4 & toe both are choosen.
	if not self.uninstall:
            if "toe_ipv4" in self.target and "toe" in self.target :
  	        self.errToe(mode, "toe")
            if "toe_ipv4" in self.target and "ipv6" in self.target :
	        self.errToe(mode,"ipv6")
            if "toe_ipv4" in self.target and "bonding" in self.target :
                self.errToe(mode,"bonding")

        # Don't procced if fcoe_target & initiator both are choosen.
	if not self.uninstall and "fcoe_full_offload_target" in self.target\
	     and "fcoe_full_offload_initiator" in self.target:
	    self.errFcoe(mode)
	if not self.uninstall and "all" not in self.target and "tools" not in self.target:
            self.target.append("tools")
	self.target_bak.extend(self.target)

    def checksDeps(self):
	libibDeps = ['iwarp','libs','all','sniffer','rdma_block_device']
	sslDeps = ['all','iscsi_pdu_initiator']
	userIn = None
	ix = 0
	ret = None
	for ix in range(0,len(sslDeps)):
            if sslDeps[ix] in self.target and\
		not self.checkDepsOiscsi() :
		sys.stdout.flush()
		os.system('clear')
		printChelsioHeader()
		printWarningHeader()
                print "The openssl-devel is required to build iscsi_pdu_initiator"
                print "was not found. Please install the package or required"
                print "headers and retry the install. Please go through README"
                print "for all such dependencies."
		userIn = raw_input("Press 1 to exit(DEFAULT).\nPress 2 to remove iSCSI initiator from list of targets and continuing.\nInput:")
		os.system('clear')
		if userIn == '1' or userIn == "":
		    return False 
		elif userIn == '2':
		    ret = self.fixTargets(sslDeps)
		    if ret == -1:
		         self.errAbort(sslDeps[ix])
		    	 sys.exit(1)
		    break;
		else:
		    print "Invalid selection. Please choose a valid options."
		    return -1
	for ix in range(0,len(libibDeps)):
            if libibDeps[ix] in self.target:
		self.fixOfaPath()
		break;
        return True
    
    def fixOfaPath(self):
        ofaKernelPath = None
        for ofedp in [ 'kernel-ib-devel', 'compat-rdma-devel', 'mlnx-ofa_kernel-devel'] :
                cmd = 'rpm -qa | grep -i %s'%(ofedp)
                cmdOut = commands.getoutput(cmd)
                if cmdOut :
                        cmd = 'rpm -ql %s | grep -w Module.symvers'%(ofedp)
                        cmdOut = commands.getoutput(cmd)
                        self.ofa = cmdOut.split('Module')[0]
                        if ofedp == 'mlnx-ofa_kernel-devel' :
                                cmd = 'modinfo -F filename ib_core | grep extra'
                        else :
                                cmd = 'modinfo -F filename ib_core | grep updates'
                        cmdOut = commands.getoutput(cmd).strip()
                        if cmdOut == '' :
                                self.ofa=None
                        else : 
                                break
        else : 
                cmd = 'modinfo -F filename ib_core | grep updates'
                cmdOut = commands.getoutput(cmd)
                if cmdOut:
                        owner_rpm = None
                        ib_path = commands.getoutput("modinfo -F filename ib_core")
                        sts, owner_rpm = commands.getstatusoutput("rpm -qf " + ib_path)
                        if owner_rpm != None and (owner_rpm.find('ofed-kmp-default')  or owner_rpm.find('compat-rdma')) != -1 :
                            return 0
                        status = self.noOfaDevel()
                        if status :
                            return 0
                else:
                        #print 'Building with INBOX, as no OFED is present :',cmdOut
                        return 0
		#print "OFA : %s "%(self.ofa)
        return 0

    def noOfaDevel(self):
        print "OFED header required to build iwarp driver not found. Do you want to compile iwarp driver with kernel headers."
	ret = raw_input("Press 1 to compile driver with kernel headers(DEFAULT).\n.Press any key to exit.\nInput:")
        if ret == '1' :
            self.useOfa = False
            return True
        sys.exit(-1)

    def errAbort(self,compInErr):
	os.system('clear')
	printChelsioHeader()
        print "Error : %s was the only component choosen . Aborting the installation. \n"%(compInErr)
        sys.exit(-1)
        
    def errPath(self):
	mode = None
	if self.uninstall:
	    mode = "uninstalltion"
        else: 
	    mode = "installation" 
	os.system('clear')
	printChelsioHeader()
        print "Error : Wrong KSRC or KOBJ PATH provided. Aborting the %s.\n"%(mode)
        sys.exit(-1)
    
    def errBypass(self,mode):
	os.system('clear')
	printChelsioHeader()
        print "Error : Bypass component can't be selected with any other component. Aborting the %s. \n"%(mode)
        sys.exit(-1)

    def errWdtoe(self, mode):
	os.system('clear')
        printChelsioHeader()
        print "Error : WD-TOE component can't be selected with any other component. Aborting the %s. \n"%(mode)
        sys.exit(-1)

    def errNic(self,mode):
	os.system('clear')
	printChelsioHeader()
        print "Error : NIC component can't be selected with any other component. Aborting the %s. \n"%(mode)
        sys.exit(-1)

    def errUnsupported(self,kver):
	os.system('clear')
	printChelsioHeader()
        print "Error : The kernel version %s is not supported. Refer to README for supported kernel versions."%(kver)
	print "\nTo compile drivers for an updated kernel, press (Y). To exit, press (N)."
	while True:
		ch=raw_input("Input(Y/N):")
		ch=ch.strip()
		if ch == "Y" or ch == "y" :
			return True
		elif ch == "N" or ch == "n" :
			sys.exit(-1)
		else:
			print "Enter a valid Input(Y/N)\n"

    def errFcoe(self,mode):
	os.system('clear')
	printChelsioHeader()
        print "Error : FCoE target and initiator can't be choosen simultaneosuly. Aborting the %s. \n"%(mode)
        sys.exit(-1)

    def errToe(self,mode,drv):
	os.system('clear')
	printChelsioHeader()
        print "Error : toe_ipv4 component can't be selected with %s component. Aborting the %s. \n"%(drv,mode)
        sys.exit(-1)

    def errTune(self):
	os.system('clear')
	printChelsioHeader()
        print "Error : Wrong Tuning option provided. Run ./install.py -h/--help to check available options.\n"
        sys.exit(-1)

    def configTuneError(self):
        os.system('clear')
	printChelsioHeader()
        print "Error : Wrong Configuration Tuning option provided. Run ./install.py -h/--help to check available options.\n"
        sys.exit(-1)

    def fixTargets(self,compToRemove):
	if 'all' in self.target:
	     self.target = [ 'vnic','nic_offload','toe','bonding','iwarp','sniffer','fcoe_full_offload_initiator','iscsi_pdu_target',
                             'iscsi_pdu_initiator','libs','tools' ]
	else :
	     if len(self.target) == 1 :
		return -1
	for comp in compToRemove:
	    if comp != 'all':
		try :
		    self.target.remove(comp) 
		except:
		    pass
	return True

    def checkOfaKernel(self,c):
        if self.ofa != None :
            if os.path.isfile(os.path.join(self.ofa,"Module.symvers")):
                return True
        return False

    def checkDepsOiscsi(self):
        path = os.path.join("/","usr","include","openssl","evp.h")
        if os.path.isfile(path) :
            return True
        else :
            return False

    def genCmdline(self) :
        temp1 = []
	if self.genRpmpack :
	    self.cmdline = "make rdma_block_device_rpm iwarp_rpm toe_rpm tools_rpm rpmgen=1 "
	elif 'all' in self.target and (self.ofa == '' or self.ofa == None):
            self.cmdline = "make install"
	elif 'all' in self.target and self.ofa :
            self.cmdline = "make install" + " OFA_DIR="+self.ofa
	else:
            for i in self.target :
                if ( self.ofa != None ) and ( i in self.ofatargets ) :
                    temp1.append(i+"_install OFA_DIR="+self.ofa)
                else :
                    temp1.append(i+"_install")
	    self.cmdline = 'make ' + ' '.join(temp1)
	if self.ksrc != None:
            self.cmdline = self.cmdline + ' KSRC=' + self.ksrc
        if self.kobj != None:
            self.cmdline = self.cmdline + ' KOBJ=' + self.ksrc
        if self.configTune == "unified-wire-fcoe-init":
	    self.cmdline += ' CONF=UNIFIED_WIRE'
        elif self.configTune == "low-latency-networking":
	    self.cmdline += ' CONF=LOW_LATENCY'
        elif self.configTune == "high-capacity-toe":
	    self.cmdline += ' CONF=HIGH_CAPACITY_TOE'
        elif self.configTune == "high-capacity-rdma":
	    self.cmdline += ' CONF=HIGH_CAPACITY_RDMA'
        elif self.configTune == "udp-offload-config":
	    self.cmdline += ' CONF=UDP_OFFLOAD'
	elif self.configTune == "edc-only-config":
            self.cmdline += ' CONF=T5_WIRE_DIRECT_LATENCY'
	elif self.configTune == "high-capacity-wd" :
            self.cmdline += ' CONF=HIGH_CAPACITY_WD'
	elif self.configTune == "hash-filter-config" :
	    self.cmdline += ' CONF=T5_HASH_FILTER '
	elif self.configTune == "rdma-perf-config" :
	    self.cmdline += ' CONF=RDMA_PERFORMANCE '
	elif self.configTune == "iscsi-perf-config" :
            self.cmdline += ' CONF=ISCSI_PERFORMANCE '
	elif self.configTune == "memfree-config" :
            self.cmdline += ' CONF=MEMORY_FREE '
	if self.CUNAME_R != None :
            self.cmdline += '  UNAME_R=%s'%(self.CUNAME_R)
	if self.benchtools:
	    self.cmdline += ' BENCHMARKS=1 '
	if self.disable_ipv6_support :
	    self.cmdline += ' ipv6_disable=1 '
	else :
	    self.cmdline += ' ipv6_disable=0 '

    def genUnCmdLine(self):
	temp = []
	if "all" in self.target:
	    temp = "make uninstall"
	    self.cmdline = temp
	else:
            for i in self.target :
                temp.append(i.strip('"')+"_uninstall ")
            self.cmdline = 'make ' + ' '.join(temp)
	if self.ksrc != None:
            self.cmdline = self.cmdline + ' KSRC=' + self.ksrc
        if self.kobj != None:
            self.cmdline = self.cmdline + ' KOBJ=' + self.ksrc
	self.cmdline += ' CONF=T4_UN'

    def checkToe(self):
        if "toe" in self.target :
            if "nic" in self.target :
                self.target.remove("nic")

    def checkipv6(self):
        if "ipv6" in self.target :
            if "nic" in self.target :
                self.target.remove("nic")

    def checkAll(self):
        if self.target == None :
            ret = self.checkOfaKernel(c)
            if ret :
                self.cmdline.append("make OFA_DIR="+c.ofa_kernel)
                self.cmdline.append("make install OFA_DIR="+c.ofa_kernel)
            else :
                self.cmdline.append("make")
                self.cmdline.append("make install")
            return True
        else:
            return False 
           
    def checkBuild(self,kpaths=None):
        kpaths = []
        if kpaths == [] and self.ksrc == None :
            kpaths.append(os.path.join(
                "/","lib","modules",os.uname()[2],"build"))
        elif self.ksrc != None:
            kpaths.append(self.ksrc)
            kpaths.append(self.kobj)
        return os.path.isfile(os.path.join(kpaths[0],"Module.symvers"))

    def buildInstall(self):
        def runCmd(cmd):
            k = subprocess.Popen(
                cmd,
                stdout=handler,
                stderr=handler,
                shell=True,
                executable="/bin/bash",
                stdin=None)
            k.wait()
            ret = k.poll()
            k.poll()
            return cmd,k.returncode,k.pid
        cmd = "make distclean"
        runCmd(cmd)
        runCmd(self.cmdline)

    def buildofedInstall(self, ofedbuildver):
	if ofedbuildver == None :
		kver = self.kernel_up
		for ver in self.ofedsupportMatrix1.keys() :
	            if kver.find(ver) != -1 :
        	        ofedkver = ver
                	break
		else :
		    print "OFED NOT SUPPORTED WITH THIS PLATFORM. Proceeding without OFED installation...."
		    return
	        ofedcpkg="OFED-"+self.ofedsupportMatrix1[ofedkver][0]
	else :
		ofedkver = ofedbuildver
		ofedcpkg="OFED-"+ofedkver
	print ofedcpkg
	self.ofedcpkgName = ofedcpkg
        def runofedCmd(cmd):
            k = subprocess.Popen(
                cmd,
                stdout=handler,
                stderr=handler,
                shell=True,
                executable="/bin/bash",
                stdin=None)
            k.wait()
            ret = k.poll()
            k.poll()
            return cmd,k.returncode,k.pid
	cmd = "python scripts/uninstall.py ofed"
	commands.getstatusoutput(cmd)
        cmd = "(cd OFED && tar xf %s.tgz)"%(ofedcpkg)
	print "\n \n --> Extracting %s Package"%(ofedcpkg)
        cmd,retc,pi = runofedCmd(cmd)
	if retc != 0 :
	    print "\n --> Extracting %s Package...		FAILED"%(ofedcpkg)
	    sys.exit(1) 
	cmd = "(cd OFED/%s && ./install.pl -c ofed.conf > ../OFED_install.log)"%(ofedcpkg)
	print "\n --> Installing %s "%(ofedcpkg)
	print "\n Ofed install logs will be present in OFED/OFED_install.log file"
        cmd,retc,pi =runofedCmd(cmd)
	if retc != 0 :
            print "\n --> Installing %s...			FAILED "%(ofedcpkg)
	    sys.exit(1)
	print "\n Ofed Installation Completed, Proceeding with Driver Installation"
	time.sleep( 3 )

    def tune(self,modconfTune):
        s = setupConf()
        tune = None
        if self.tunes == None:
            return 
        else :
            tune = self.tunes.split()
        ret = s.addModprobeConf(self.target,tune,modconfTune)

    def fixConfig(self):
        target_config = None
        found=0
        config_files_cli = {"unified-wire-fcoe-init"   : "build/src/network/firmware/t4-config.txt",
                            "low-latency-networking"   : "build/src/network/firmware/low_latency_config/t4-config.txt",
                            "high-capacity-toe"        : "build/src/network/firmware/high_capacity_config/t4-config.txt",
                            "high-capacity-rdma"       : "build/src/network/firmware/high_capacity_rdma/t4-config.txt",
                            "udp_offload_config"       : "build/src/network/firmware/udp_so_config/t4-config.txt",
                            "edc-only-config"          : "build/src/network/firmware/edc_only_config/t4-config.txt",
                            "high-capacity-wd"         : "build/src/network/firmware/high_capacity_wd/t4-config.txt",
                            "hash-filter-config"       : "build/src/network/firmware/high_filter_config/t4-config.txt",
			    "rdma-perf-config"	       : "build/src/network/firmware/rdma_perf_config/t4-config.txt",
			    "iscsi-perf-config"        : "build/src/network/firmware/iscsi_perf_config/t4-config.txt",
			    "memfree-config"           : "build/src/network/firmware/memfree_config/t4-config.txt"
                            }
        for i in config_files_cli.keys():
            if i == self.configTune:
                target_config = config_files_cli[i]
                found=1
        if found == 1 and "fcoe_full_offload_target" not in self.target:
            cmd = "cp -f %s /lib/firmware/cxgb4/"%(target_config)
            #commands.getoutput(cmd) #Prevent config files from getting copied with tools(22936).

    def checkConfigTune(self):
        confgOpts = ["unified-wire-fcoe-init", "low-latency-networking", "high-capacity-toe", "high-capacity-rdma", \
                     "udp-offload-config", "edc-only-config", "high-capacity-wd", "hash-filter-config", "rdma-perf-config", "iscsi-perf-config", "memfree-config" ]
        found=0
        if self.configTune != None:
            if self.configTune not in confgOpts:
                self.configTuneError()

    def fixCustomTarget(self, support, choice):
	toremove = []
	for ix in range(0, len(choice)):
	    if choice[ix] not in support:
		toremove.append(ix)
	toremove.sort(cmp=None, key=None, reverse=True)
        for ix in toremove:
            del(choice[ix])
        return choice

    def askFirmConfig(self,arg=0):
	choice = None
	os.system("clear")
        printChelsioHeader()
	menu ={}
        data = ''
	customTarget = []
	if not self.kernel_up :
             kversion = platform.release()
             sort = sorted(self.supportMatrix.keys(),reverse=True)
             for ix in range(0, len(self.supportMatrix.keys())):
                 if kversion.find(sort[ix]) != -1 :
                     customTarget = self.supportMatrix[sort[ix]]
                     break
        else :
             customTarget = self.supportMatrix[self.kernel_up]
        ix = 1
        if self.clusDeploy :
            data += \
                '''Press %d, Unified Wire, NIC;TOE;RDMA'''%(ix)
        else :
            data += \
                '''Press %d, Unified Wire, all the Chelsio drivers'''%(ix)
        if data != '':
            data = data + '\n'
        menu[ix] = 'unified-wire-fcoe-init'
        ix += 1
	if self.clusDeploy or "iwarp" in customTarget:
            data += \
                '''Press %d, Low Latency Networks, NIC;TOE;RDMA;WD'''%(ix)
            menu[ix] = 'low-latency-networking'
            ix += 1
            if data != '':
                data = data + '\n'
            data += \
                '''Press %d, High Capacity RDMA, NIC;TOE;RDMA'''%(ix)
            menu[ix] = 'high-capacity-rdma'
            ix += 1
            if data != '':
                data = data + '\n'
            data += \
                '''Press %d, RDMA Performance, NIC;TOE;RDMA'''%(ix)
            menu[ix] = 'rdma-perf-config'
            ix += 1
            if data != '':
                data = data + '\n'
            data += \
                '''Press %d, Memory Free, NIC;TOE;RDMA'''%(ix)
            menu[ix] = 'memfree-config'
            ix += 1
            if data != '':
                data = data + '\n'
	if not self.clusDeploy and "toe" in customTarget:
            data += \
                '''Press %d, High Capacity TOE, NIC;TOE'''%(ix)
            menu[ix] = 'high-capacity-toe'
            ix += 1
            if data != '':
                data = data + '\n'
	if not self.clusDeploy and "iscsi_pdu_target" in customTarget:
            data += \
                '''Press %d, iSCSI Performance, NIC;TOE;iSCSI'''%(ix)
            menu[ix] = 'iscsi-perf-config'
            ix += 1
            if data != '':
                data = data + '\n'
	if not self.clusDeploy and "udp_offload" in customTarget:
            data += \
                '''Press %d, UDP Segmentation Offload & Pacing, UDP segmenation offload capable NIC;TOE'''%(ix)
	    menu[ix] = 'udp-offload-config'
            ix += 1
            if data != '':
                data = data + '\n'
        if not self.clusDeploy and "iwarp" in customTarget:
            data += \
                '''Press %d, T5 Wire Direct Latency, NIC;TOE;RDMA;WD'''%(ix)
            menu[ix] = 'edc-only-config'
            ix += 1
            if data != '':
                data = data + '\n'
            data += \
                '''Press %d, T5 High Capacity WD, NIC;RDMA;WD'''%(ix)
            menu[ix] = 'high-capacity-wd'
            ix += 1
            if data != '':
                data = data + '\n'
	if not self.clusDeploy :
	    data += \
	        '''Press %d, T5 Hash Filter Configuration, NIC'''%(ix)
            menu[ix] = 'hash-filter-config'
            ix += 1
            if data != '':
	        data = data + '\n'
	if len(data) > 1:
            data += \
                '''Press %d, EXIT, '''%(ix)
            menu[ix] = 'exit'
            width=100
            rows = [row.strip().split(',')  for row in data.splitlines()]
            labels = ('Choice',' T4/T5 Configuration',' Supported Protocols/Drivers')
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
	self.configTune = menu[int(choice)]
	if self.configTune == "exit":
	    sys.exit(1)
	
    def removeUnsupported(self):
	kversion = self.kernel_up
	if self.configTune == "low-latency-networking" or self.configTune == "edc-only-config"  \
           or self.configTune == "high-capacity-wd": 
	    toremove = [ "vnic", "wdtoe","bonding","toe_ipv4", "libs", "bypass", "nic", "wdtoe_wdudp", "fcoe_pdu_offload_target"]
            '''if kversion.find('2.6.35') != -1 or kversion.find("3.2.0-23") != -1 or  kversion.find("3.5.0-23") != -1 :
                toremove.remove("toe")'''
	else :
	    toremove = [ "toe_ipv4", "libs", "bypass", "nic", "wdtoe", "wdtoe_wdudp", "fcoe_pdu_offload_target"]
	for i in toremove:
	    if i in self.target:
		self.target.remove(i)

    def rpmClusterDeploy(self) :
	choice = None
        os.system("clear")
        printChelsioHeader()
        menu ={}
        data = ''
        ix = 1
        data += \
            '''Press %d, RPM Homogeneous Cluster Deployment, For Clusters with same OS'''%(ix)
        if data != '':
            data = data + '\n'
        menu[ix] = 'homgen-cluster'
        ix += 1
        data += \
            '''Press %d, Normal Cluster Deployment, For Clusters with different OS'''%(ix)
        if data != '':
            data = data + '\n'
        menu[ix] = 'hetero-cluster'
        ix += 1

        if len(data) > 1:
            data += \
                '''Press %d, EXIT, '''%(ix)
            menu[ix] = 'exit'
            width=100
            rows = [row.strip().split(',')  for row in data.splitlines()]
            labels = ('Choice',' Cluster Configuration',' Details')
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
        self.clust_install_opt = menu[int(choice)]
        if self.clust_install_opt == "exit":
            sys.exit(1)
	if self.clust_install_opt == 'homgen-cluster' :
		cmd = "make rpmclean"
		sts, out = commands.getstatusoutput(cmd)
		self.genRpmpack = True
		if not self.uninstall:
			kversion = self.kernel_up
	                for ver in self.ofedsupportMatrix1.keys() :
        	            if kversion.find(ver) != -1 :
                	        self.ofedkver = ver
                        	break
			if self.ofedkver != None :
				if self.ofed_install_opt != "install-ofed" : 
			        	self.installOfedcmd()
				self.setofedinstall()
			self.genCmdline()
			print "\n\t --> Generating RPMS for Cluster Deployment..."
			self.buildInstall()
			#print "rpm clus"
			if self.install_ofed :
				self.installOfed = True
				if self.copyOfedtoRpm() == False :
				    sys.exit(1)
			else :
				#print "Inside inbox"
				self.installOfed = False
				if self.copyInboxRpm() == False :
				    sys.exit(1)
			print "\n\t --> Generating RPMS for Cluster Deployment...  Done"
		cmd = "cp -rf RPM-Manager ChelsioUwire-2.12.0.3-RPM-Installer"
		sts, out = commands.getstatusoutput(cmd)
		if sts != 0 :
		    print "RPM copy failed for Cluster Installation"
		    sys.exit(1)
		
		cmd = "tar czf ChelsioUwire-2.12.0.3-RPM-Installer.tar.gz ChelsioUwire-2.12.0.3-RPM-Installer"
		sts, out = commands.getstatusoutput(cmd)
		if sts != 0 :
                    print "RPM archive creation failed for Cluster Installation"
                    sys.exit(1)
	elif self.clust_install_opt == "hetero-cluster" :
		if not self.uninstall:
                        kversion = self.kernel_up
                        for ver in self.ofedsupportMatrix1.keys() :
                            if kversion.find(ver) != -1 :
                                self.ofedkver = ver
                                break
                        #if self.ofedkver != None :
                        if self.ofed_install_opt != "install-ofed" :
                            self.installOfedcmd()
                        if self.ofed_install_opt == "install-ofed":
                            #self.install_ofed = True
                            self.installOfed = True
                        else :
                            #self.install_ofed = False
                            self.installOfed = False
	else :
	   return

    def copyOfedtoRpm(self):
	def runcopyCmd(cmd):
            k = subprocess.Popen(
                cmd,
                stdout=handler,
                stderr=handler,
                shell=True,
                executable="/bin/bash",
                stdin=None)
            k.wait()
            ret = k.poll()
            k.poll()
            return cmd,k.returncode,k.pid
	self.installOfed = True
        cmd = 'cp -rf OFED/%s/RPMS/*/x86_64/* RPM-Manager/OFED-RPMS/. '%(self.ofedcpkgName)
	print "Copying Ofed RPMS"
	cmd,retc,pi = runcopyCmd(cmd)
	if retc !=0 :
	    print "Ofed RPMS Copy Failed"
	    return False
        cmd = "cp -rf rpmbuild/RPMS/x86_64/* RPM-Manager/DRIVER-RPMS/ofed/."
	cmd,retc,pi = runcopyCmd(cmd)
	if retc !=0 :
	    print "Ofed Driver RPMS Copy Failed"
	    return False
	return True

    def copyInboxRpm(self):
	def runcopyCmd(cmd):
            k = subprocess.Popen(
                cmd,
                stdout=handler,
                stderr=handler,
                shell=True,
                executable="/bin/bash",
                stdin=None)
            k.wait()
            ret = k.poll()
            k.poll()
            return cmd,k.returncode,k.pid
	archDir = None
	archDir = os.uname()[4].strip()
	cmd = "cp -rf rpmbuild/RPMS/"+ archDir +"/* RPM-Manager/DRIVER-RPMS/inbox/."
	cmd,retc,pi = runcopyCmd(cmd)
	if retc !=0 :
            print "Inbox Driver RPMS Copy Failed"
            return False
	return True
	
    def installOfedcmd(self):
	choice = None
        os.system("clear")
        printChelsioHeader()
        menu ={}
        data = ''
        customTarget = []
        kversion = self.kernel_up
        sort = sorted(self.supportMatrix.keys(),reverse=True)
        for ix in range(0, len(self.supportMatrix.keys())):
            if kversion.find(sort[ix]) != -1 :
                customTarget.extend(self.supportMatrix[sort[ix]])
                break
        for ver in self.ofedsupportMatrix1.keys() :
            if kversion.find(ver) != -1 :
                self.ofedkver = ver
                break
	if self.ofedkver == None:
		installOfedMat = ""
	else:
		installOfedMat = self.ofedsupportMatrix1[self.ofedkver][0]
        ix = 1
        data += \
            '''Press %d, Install OFED, Compiles and Installs OFED %s'''%(ix,installOfedMat)
        if data != '':
            data = data + '\n'
        menu[ix] = 'install-ofed'
	'''if self.clust_install_opt != "hetero-cluster" :
	    ix += 1
   	    data += \
	        'Press %d, Choose OFED Version, Lists all Supported OFED Versions'%(ix)
	    if data != '':
	        data = data + '\n'
	    menu[ix] = 'choose-ofed' '''
        ix += 1
        data += \
            '''Press %d, Skip OFED, Skips Ofed install'''%(ix)
	if data != '':
            data = data + '\n'
        menu[ix] = 'skip-ofed'
        ix += 1
	
	if len(data) > 1:
            data += \
                '''Press %d, EXIT, '''%(ix)
            menu[ix] = 'exit'
            width=100
            rows = [row.strip().split(',')  for row in data.splitlines()]
            labels = ('Choice',' OFED Configuration',' Details')
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
	self.ofed_install_opt = menu[int(choice)]
        if self.ofed_install_opt == "exit":
            sys.exit(1)
    
    def changeOfedverCmd(self):
	ofed_ver = self.ofedsupportMatrix1[self.ofedkver]
        ofedVersionList = ["1.5.4.1","3.12-1", "3.18-1"]
	choice = None
        os.system("clear")
        printChelsioHeader()
        menu ={}
        data = ''
        customTarget = []
        kversion = self.kernel_up
        sort = sorted(self.supportMatrix.keys(),reverse=True)
        for ix in range(0, len(self.supportMatrix.keys())):
            if kversion.find(sort[ix]) != -1 :
                customTarget.extend(self.supportMatrix[sort[ix]])
                break
        ix = 1
        for i in ofedVersionList:
                for k in self.ofedsupportMatrix1[self.ofedkver]:
                        if i == k :
				data += \
			            '''Press %d, OFED-%s, Compiles and Installs OFED-%s'''%(ix,i,i)
				if data != '':
			            data = data + '\n'
			        menu[ix] = '%s'%(i)
				ix += 1
	if len(data) > 1:
            data += \
                '''Press %d, EXIT, '''%(ix)
            menu[ix] = 'exit'
            width=100
            rows = [row.strip().split(',')  for row in data.splitlines()]
            labels = ('Choice',' Supported OFED Versions',' Details')
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
        self.ofed_version_opt = menu[int(choice)]
        if self.ofed_version_opt == "exit":
            sys.exit(1)
	else :
	    for i in ofedVersionList :
		if self.ofed_version_opt == i :
		    self.ofedinstver = i
		    break
		
    def setofedinstall(self):
	customTarget = []
        kversion = self.kernel_up
        sort = sorted(self.supportMatrix.keys(),reverse=True)
        for ix in range(0, len(self.supportMatrix.keys())):
            if kversion.find(sort[ix]) != -1 :
                customTarget.extend(self.supportMatrix[sort[ix]])
                break
        if self.ofed_install_opt == "install-ofed":
	    self.install_ofed = True
	    self.buildofedInstall(None)
	elif self.ofed_install_opt == "choose-ofed":
	    self.install_ofed = True
	    self.changeOfedverCmd()
	    self.buildofedInstall(self.ofedinstver)
	elif self.ofed_install_opt == "skip-ofed":
	    self.install_ofed = False
	    
    def fixConfTargets(self):
	customTarget = []
        kversion = self.kernel_up
        sort = sorted(self.supportMatrix.keys(),reverse=True)
        for ix in range(0, len(self.supportMatrix.keys())):
            if kversion.find(sort[ix]) != -1 :
                customTarget.extend(self.supportMatrix[sort[ix]])
                break
        if self.configTune == "unified-wire-fcoe-init":
	    if "all" in self.target:
                self.target = customTarget 
		self.removeUnsupported()
	    else :
		self.target = self.fixCustomTarget(customTarget, self.target)
	    if "fcoe_full_offload_target" in self.target:
	        self.target.remove("fcoe_full_offload_target")
	    if "udp_offload" in self.target:
		self.target.remove("udp_offload")
        elif self.configTune == "low-latency-networking" or \
            self.configTune == "high-capacity-rdma" :
	    toRemove = []
	    if self.configTune in ["high-capacity-rdma"] :
		confSupport = ["nic", "nic_offload", "toe", "toe_ipv4","iwarp", "rdma_block_device", "bonding","sniffer","libs","tools"]
	    else:
		confSupport = ["nic", "nic_offload", "toe", "toe_ipv4","wdtoe", "rdma_block_device", "wdtoe_wdudp","iwarp","bonding","sniffer","libs","tools"]
	    if "all" in self.target:
                self.target = customTarget
		self.removeUnsupported()
            else:
                 self.target = self.fixCustomTarget(customTarget, self.target)	
	    for i in range(0, len(self.target)):
		if self.target[i] not in confSupport:
		     toRemove.append(i)
	    toRemove.sort(reverse=True)
	    for i in toRemove:
		del(self.target[i])
	elif self.configTune == "rdma-perf-config" or \
	     self.configTune == "memfree-config":
            toRemove = []
	    if self.configTune == "rdma-perf-config" :
               confSupport = ["nic", "nic_offload", "toe", "toe_ipv4","iwarp", "rdma_block_device", "libs","tools"]
	    else :
               confSupport = ["nic", "nic_offload", "toe", "toe_ipv4","iwarp", "libs","tools"]
            if "all" in self.target:
                self.target = customTarget
                self.removeUnsupported()
            else:
                 self.target = self.fixCustomTarget(customTarget, self.target)
            for i in range(0, len(self.target)):
                if self.target[i] not in confSupport:
                     toRemove.append(i)
            toRemove.sort(reverse=True)
            for i in toRemove:
                del(self.target[i])
        elif self.configTune == "edc-only-config" or self.configTune == "high-capacity-wd" : 
            toRemove = []
            confSupport = ["nic", "nic_offload", "toe", "wdtoe","wdtoe_wdudp","iwarp", "rdma_block_device", "libs","tools"]
            if "all" in self.target:
                self.target = customTarget
                self.removeUnsupported()
            else:
                 self.target = self.fixCustomTarget(customTarget, self.target)
            for i in range(0, len(self.target)):
                if self.target[i] not in confSupport:
                     toRemove.append(i)
            toRemove.sort(reverse=True)
            for i in toRemove:
                del(self.target[i])
        elif self.configTune == "high-capacity-toe":
	    toRemove = []
            confSupport = ["nic", "nic_offload","toe","toe_ipv4","bonding","tools"]
	    if "all" in self.target:
                self.target = customTarget
		self.removeUnsupported()
            else:
                 self.target = self.fixCustomTarget(customTarget, self.target)	
	    for i in range(0, len(self.target)):
		if self.target[i] not in confSupport:
		     toRemove.append(i)
	    toRemove.sort(reverse=True)
	    for i in toRemove:
		del(self.target[i])
	elif self.configTune == "iscsi-perf-config" :
	    toRemove = []
            confSupport = ["nic", "nic_offload","toe","bonding","iscsi_pdu_target","iscsi_pdu_initiator", "tools"]
            if "all" in self.target:
                self.target = customTarget
                self.removeUnsupported()
            else:
                 self.target = self.fixCustomTarget(customTarget, self.target)
            for i in range(0, len(self.target)):
                if self.target[i] not in confSupport:
                     toRemove.append(i)
            toRemove.sort(reverse=True)
            for i in toRemove:
                del(self.target[i])
	elif self.configTune == "udp-offload-config":
            toRemove = []
            confSupport = ["udp_offload","tools"]
            if "all" in self.target:
                self.target = customTarget
                self.removeUnsupported()
            else:
                 self.target = self.fixCustomTarget(customTarget, self.target)
            for i in range(0, len(self.target)):
                if self.target[i] not in confSupport:
                     toRemove.append(i)
            toRemove.sort(reverse=True)
            for i in toRemove:
                del(self.target[i])
	elif self.configTune == "hash-filter-config":
            toRemove = []
            confSupport = ["nic_offload","tools"]
            self.customtarget.insert(1,"nic_offload")
            if "all" in self.target:
                self.target = self.customtarget
                self.removeUnsupported()
            else:
                 self.target = self.fixCustomTarget(customTarget, self.target)
            for i in range(0, len(self.target)):
                if self.target[i] not in confSupport:
                     toRemove.append(i)
            toRemove.sort(reverse=True)
            for i in toRemove:
                del(self.target[i])
        else:
            print "Wrong config Tune option."
            sys.exit(-1)
    	
    def compareCheckFailed(self,comp,arg=0):
	choice = None
	customTarget = []
	chktarget=[]
	os.system("clear")
	printChelsioHeader()
	if arg == 1 :
	    print "Provide a valid input."
	kversion = self.kernel_up
        sort = sorted(self.supportMatrix.keys(),reverse=True)
        for ix in range(0, len(self.supportMatrix.keys())):
            if kversion.find(sort[ix]) != -1 :
                customTarget.extend(self.supportMatrix[sort[ix]])
                break
	chktarget.extend(self.target_bak)
	chktarget.remove("tools")
	if comp not in customTarget:
	    print "The %s component is not supported on %s kernel."%(comp,kversion)
	else:
	    if self.configTune == "edc-only-config":
		conftoprint = "T5_WIRE_DIRECT_LATENCY"
	    else:
		conftoprint = self.configTune
	    print "The %s component is not compatible with %s configuration tuning."%(comp,conftoprint)
	print "Press 1 to exit the installation."
	if len(chktarget) > 1 :
		print "Press 2 to continue with the installation skipping the %s component"%(comp)
	choice = raw_input("Input:")	
	if choice == '1':
	    sys.exit(1)
	elif choice == '2' and len(chktarget) > 1 :
	    os.system('clear')
	    return
	else:
	    self.compareCheckFailed(comp,arg=1)

    def compareTarget(self):
	if "all" in self.target_bak:
	    return
	for i in self.target_bak:
	    if i not in self.target:
		self.compareCheckFailed(i)
    
    def checkUpdatekernel(self):
        kversion = platform.release()
        sort = sorted(self.supportMatrix.keys(),reverse=True)
        for ix in range(0, len(self.supportMatrix.keys())):
            if kversion.find(sort[ix]) != -1 :
                self.kernel_up = sort[ix]
                return True
        return False
              
    def checkKernelVers(self):
        pas=False
        ix=0
        menu ={}
        choice = None
        kversion = platform.release()
        if not self.checkUpdatekernel() :
            if self.errUnsupported(kversion) :
                supportMatrix = [ ["2.6.32-279.el6","Red Hat Enterprise Linux Server release 6.3"],
                              ["2.6.32-358.el6","Red Hat Enterprise Linux Server release 6.4"],
                              ["2.6.32-431.el6","Red Hat Enterprise Linux Server release 6.5"],
                              ["2.6.32-504.el6","Red Hat Enterprise Linux Server release 6.6"],
                              ["3.10.0-123.el7","Red Hat Enterprise Linux Server release 7"],
                              ["3.10.0-229.el7","Red Hat Enterprise Linux Server release 7.1"],
                              ["3.10.0-327.el7","Red Hat Enterprise Linux Server release 7.2"],
                              ["2.6.32.12-0.7","SUSE Linux Enterprise Server 11 SP1"],
                              ["3.0.13-0.27","SUSE Linux Enterprise Server 11 SP2"],
                              ["3.0.76-0.11","SUSE Linux Enterprise Server 11 SP3"],
                              ["3.0.101-63","SUSE Linux Enterprise Server 11 SP4"],
                              ["3.12.28-4","SUSE Linux Enterprise Server 12"], 
                              ["3.12.49-11","SUSE Linux Enterprise Server 12 SP1"], 
			      ["3.13.0-32","Ubuntu 14.04.1 LTS"],
			      ["3.16.0-30","Ubuntu 14.04.2 LTS"],
			      ["3.19.0-25","Ubuntu 14.04.3 LTS"],
                              ["3.4","Linux kernel Release"],
                              ["3.6","Linux kernel Release"],
                              ["3.7","Linux kernel Release"],
                              ["3.8","Linux kernel Release"],             
                              ["3.9","Linux kernel Release"],
                              ["3.10","Linux kernel Release"],
                              ["3.11","Linux kernel Release"],
                              ["3.12","Linux kernel Release"],
                              ["3.13","Linux kernel Release"],
                              ["3.14","Linux kernel Release"],
                              ["3.15","Linux kernel Release"],
                              ["3.16","Linux kernel Release"],
                              ["3.17","Linux kernel Release"],
                              ["3.18","Linux kernel Release"],
                              ["4.1","Linux kernel Release"],
                              ["exit",""] ]
            width=100
            os.system("clear")
            printChelsioHeader()
            print "Please select an appropriate kernel version"
            labels = ('Choice',' Kernel Version',' Distro')
            for im in range(0, len(supportMatrix)):
                supportMatrix[im].insert(0,"Press %d"%(im+1))
		menu[im+1] = supportMatrix[im][1]
            print '\n' + indent([labels]+supportMatrix, hasHeader=True, hasrowSep=False, separateRows=True,
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
            self.CUNAME_R=menu[int(choice)].strip()
            self.kernel_up = self.CUNAME_R 
            if self.CUNAME_R == "exit" :
                sys.exit(1)

    def getUninstallTarget(self):
	if "all" not in self.target:
	    return
	if "all" in self.target and self.uninstall:
	    return 
	self.target = []
	kversion = self.kernel_up
        sort = sorted(self.supportMatrix.keys(),reverse=True)
        for ix in range(0, len(self.supportMatrix.keys())):
            if kversion.find(sort[ix]) != -1 :
                customTarget.extend(self.supportMatrix[sort[ix]])
                break
	if "bypass" in self.target:
	    self.target.append("ba_tools")
	toremove = [ "toe_ipv4", "bypass" ]
	for i in toremove:
	    if i in self.target:
		self.target.remove(i)


def writeLog(handler,text):
    if isinstance(text, list) :
        for i in text :
            handler.write(i+",")
    else :
        handler.write(text+",")

def checkExit(code,a,back=0):
    if code in (a.DIALOG_ESC,) or code == -5:
	#print "ESC"
        code = a.yesno("Do you want to exit")
        if code == 0 or code == -5:
            os.system('clear')
            sys.exit(-1)
        else :
            return None
    elif code in (a.DIALOG_CANCEL,) :
	#print "CANCEL",back,code
        if back == 1 :
            return 1
        code = a.yesno("Do you want to exit")
        if code == 0 or code == -5:
            os.system('clear')
            sys.exit(-1)
        return None
    return 0

def askExit(a):
    msg = "Sure you want to exit"
    code = a.yesno(msg)
    if ( code == a.DIALOG_OK or code == -5) :
        os.system('clear')
        sys.exit(-1)
    return False

def cmdSilent():

    def uninstall(c):
        c.buildInstall()
	readLog()
    
    def eula(arg=0):
        os.system("clear")
	printChelsioHeader()
        if arg == 1 :
            print "Provide a Valid Input"
        a = raw_input("Do you Accept the terms and conditions :\nPress 1 to Read through the EULA(DEFAULT). \nPress 2 to Accept the EULA. \nPress 3 to Disagree with the EULA. \nInput:")
        if a == "" or a.lower() == '1' :
            os.system("less EULA")
            eula(arg=1)
        elif a.lower() == '3' :
            print "\nEULA Disagreed, Exiting."
            sys.exit(-1)
        elif a.lower() == '2' :
            os.system('clear')
            return a.lower()
        else :
            print "Provide a valid input"
            eula(arg=1)
    
    def readLog():
	cmd = "cat install.log | grep make: -A 0  | wc -l"
        sts, rmlinecnt = commands.getstatusoutput(cmd)
        readFile = open("install.log")
        lines = readFile.readlines()
        readFile.close()
	toremove = []
	for ix in range(0, len(lines)):
	    if lines[ix].find('make:') != -1:
		toremove.append(ix)
	toremove.sort(cmp=None, key=None, reverse=True)
	for ix in toremove:
	    del(lines[ix])
	    rmlinecnt = 1
        if int(rmlinecnt) > 0 :
             w = open("install.log",'w')
             w.writelines(lines)
             w.close()
	cmd = 'cat install.log | grep -A 20 -B 1 "Action"  > Summary'
	commands.getstatusoutput(cmd)

    try :        
	gdialog = False
        c = cmds()
        prints = sys.stdout.write
        c.parseArgs(sys.argv[1:])
	if not c.checkUpdatekernel()  :
            os.system('clear')
            printChelsioClsDepHeader()
            print "Error: Silent installation is not supported in Updated Kernel"
	if c.clusDeploy:
	    printChelsioClsDepHeader()
	    c.parseMachineFile()
	    c.checkSshConf()
	    #eula()
	    printChelsioClsDepHeader()
            if not c.uninstall :
	        c.askFirmConfig()
	    os.system('clear')
	    printChelsioClsDepHeader()
	    c.rpmClusterDeploy()
	    os.system('clear')
	    printChelsioClsDepHeader()
	    print "Starting Cluster Deployment. Kindly wait it may take some time."
	    print "Deployment will start on following nodes : ",
	    sys.stdout.flush()
	    for node in c.nodes : print node+ ' ',
	    print "\nChecking nodes connectivity ....",
	    sys.stdout.flush()
	    if c.checkNodes() != 0 :
	        print " Failed"
	    	sys.exit(1)
	    print " Passed"
	    print "Checking password-less ssh across nodes ....",
	    sys.stdout.flush()
	    if c.checkSshConn() != 0 :
		sys.exit(1)
	    print "Passed"
	    print "Creating Logs directories ....",
	    c.createLogsDir()
	    print "Passed"
	    print "Logs for installation can be found in %s directory."%(c.logDir + os.sep + "NODE_HOSTNAME")
	    print "Starting deployment on nodes ....",
	    sys.stdout.flush()
            if c.genRpmpack :
                if c.starthmgDeploy() != 0 :
		    print " Failed"
                    sys.exit(1)
            else :
	        if c.startDeploy() != 0:
	            print " Failed"
     		    sys.exit(1)
	    print " PASSED"
	    print "Getting installation logs from nodes ....",
	    sys.stdout.flush()
	    c.getLogs()
	    print " PASSED"
	    c.parseLogs()
	else:	
	    if ( c.uninstall != True ) :
		if c.installOfed :
			c.buildofedInstall(None)
                c.genCmdline()
                c.buildInstall()
                c.tunes='disable-affinity'
                c.tune(c.configTune)
		readLog()
            else :
                c.genUnCmdLine()
                uninstall(c)
		readLog()
		
    except KeyboardInterrupt:
        print "\nAborting the install process"
	sys.exit(-1)

def cmdMain():
    def uninstall(c):
        prints("Un-Installing           : ")
        sys.stdout.flush()
        c.buildInstall()
        print "Done"
        readLog()

    def eula(arg=0):
        os.system("clear")
	printChelsioHeader()
        if arg == 1 :
            print "Provide a Valid Input"
        a = raw_input("Do you Accept the terms and conditions :\nPress 1 to Read through the EULA(DEFAULT). \nPress 2 to Accept the EULA. \nPress 3 to Disagree with the EULA. \nInput:")
        if a == "" or a.lower() == '1' :
            os.system("less EULA")
            eula(arg=1)
        elif a.lower() == '3' :
            print "\nEULA Disagreed, Exiting."
            sys.exit(-1)
        elif a.lower() == '2' :
            os.system('clear')
            return a.lower()
        else :
            print "Provide a valid input"
            eula(arg=1)
    
    def readLog():
        rmlinecnt = 0
	os.system('clear')
	printChelsioHeader()
        readFile = open("install.log")
        lines = readFile.readlines()
        readFile.close()
	toremove = []
	for ix in range(0, len(lines)):
	    if lines[ix].find('make:') != -1:
		toremove.append(ix)
	toremove.sort(cmp=None, key=None, reverse=True)
	for i in toremove:
	    del(lines[i])
	    rmlinecnt = 1
        if int(rmlinecnt) > 0 :
             w = open("install.log",'w')
             w.writelines(lines)
             w.close()
	cmd = 'cat install.log | grep -A 20 -B 1 "Action"  >> Summary'
	commands.getstatusoutput(cmd)
	print '--------'
	print 'Summary'
	print '--------'
	handler = open('Summary','r')
	for line in handler:
	    print line,
	handler.close()
	cmd = 'rm -f Summary'
	commands.getstatusoutput(cmd)
        a = raw_input("\nPress 1 to view the log. Press any other key to exit(Default).\nInput: ")
        if a.lower() == '1' :
            os.system("less install.log")
        else :
            sys.exit(0)

    try :        
        print "Please install dialog to view user interface."    
	gdialog = False
        c = cmds()
        prints = sys.stdout.write
        c.parseArgs(sys.argv[1:])
	c.checkKernelVers()
	c.checkConfigTune()
        if not c.checkTargets():
	    sys.exit(-1)
	os.system('clear')
        #eula()
	if ( c.uninstall != True ) :
       	    os.system('clear')
	    c.askFirmConfig()
	    kversion = c.kernel_up
	    for ver in c.ofedsupportMatrix1.keys() :
                if kversion.find(ver) != -1 :
                    c.ofedkver = ver
                    break
	    if c.ofedkver != None and not ( c.configTune in ["iscsi-perf-config", "hash-filter-config", "high-capacity-toe", "udp-offload-config"] ) :
		    if c.ofed_install_opt != "install-ofed" :
	                c.installOfedcmd()
		    c.setofedinstall()
	    c.fixConfTargets()
	    c.compareTarget()
	    c.getUninstallTarget()
	else:
	    c.getUninstallTarget()
	os.system('clear')
	printChelsioHeader()
        print "*****************"
        print "Installer Summary"
        print "*****************"    
        print "Targets provided        : "+" ".join(c.target)
        prints ("Checking Build          : ")
        if c.checkBuild():
            print "Done"
        else:
            print "Failed"
        prints("Checking Targets        : ")
        ret = c.checkTargets()
        if ret:
            print "Done"
        else:
            print "Failed"
        prints ("Checking Tunnables      : ")
        retTun = None
        retTun = c.checkTunnable()
        if retTun:
            print "Done"
        else:
            print "Failed"
        if retTun == False :
            c.errTune()
        if ret :
            # ret = c.checkAll()
            # print ret
            if ( c.uninstall != True ) :
                ret =  -1
		while ret == -1:
		    ret = c.checksDeps()
                prints("Checking Dependencies   : ")
		print "Done"
                c.genCmdline()
            else :
                c.genUnCmdLine()
                uninstall(c)
		readLog()
                sys.exit(0)
            if ret :
                prints("Building and Installing : ")
                sys.stdout.flush()
                c.buildInstall()
                print "Done"
                c.tune(c.configTune)
                c.fixConfig()
                readLog()
            else :
                #print str(ret)+"\n"
                sys.exit(0)
        else :
            c.parser.print_help()
            sys.exit(1)
    except KeyboardInterrupt:
        print "\nAborting the install process"
        sys.exit(-1)

def cmdDialog():
    import dialog
    s = None
    c = None
    while True :
        try:
	    handler = open("install.log","w")
            a = dialog.Dialog()
            a.add_persistent_args(["--colors","--backtitle", "\Zb\Z7Chelsio Unified Installer v 2.0            press ESC or Ctl+C to exit\Zn"],)
            c = prompt()
	    c.checkKernelSupport(a)
            #ret = c.promptLicense(a)
	    #while ret == -1:
            #	ret = c.promptLicense(a)
            ret = c.promptUninstall(a)
	    while ret == D_BACK :
		    ret = c.promptUninstall(a)
		    #print "Insideloop",ret;
	    #print "Outside loop",ret;
	    if c.installofed == True :
		ofedversion = c.ofed_fversion
		print ofedversion
		ofedpkg = "OFED-"+ofedversion
		print ofedpkg
		r=genCmdLine(c)
		#r.genInstallOfed(ofedpkg)
		#print r.cmdline
		s=make(a,c)
		s.runOfedextract(ofedpkg)
		r.genInstallOfed(ofedpkg)
                #print r.cmdline
		s.runOfedinstall(r.cmdline)
		if s.ofedstat != 0 :
                    c.promptOfedsummary(a)
                    sys.exit(1)
		c.promptOFAKernel(a)
	    if 'all'  in c.components:
		c.components = c.components.split()
	    for ix in range(0,len(c.components)):
		c.components[ix] = c.components[ix].strip('"')
            if not c.uninstall and "all" not in c.components and "tools" not in c.components:
                c.components.append("tools")
            r = genCmdLine(
                c,
                components=c.components,
                tunnables=c.tunnables)
            if c.uninstall :
                r.genUninstall(a)
                print r.cmdline
                writeLog(handler,r.cmdline)
                s = make(a,c)
                a.add_persistent_args(["--backtitle", "Chelsio Unified Installer v 2.0"])
                s.runUninstall(r.cmdline)
		if "nic" in c.components or "all" in c.components \
		    or "nic_offload" in c.components:
		    setConfObj = setupConf()
                    setConfObj.remModprobeConf()
            else :
                r.genMake(a)
                writeLog(handler,r.cmdline)
                s = make(a,c)
                a.add_persistent_args(["--backtitle", "Chelsio Unified Installer v 2.0"])
                print r.cmdline
                s.runBuild(r.cmdline)
		tuneObj = runtune(c.tunnables)
		setConfObj = setupConf()
                setConfObj.addModprobeConf(c.components,c.tunnables,c.configTune)
                setConfObj.fixConfig(c.components,c.configTune)
            c.promptSummary(a,s.error,c.uninstall)
            del c
            del r
            del a
            handler.close()
            break
        except KeyboardInterrupt :
            handler.close()
	    if s != None and s.gaugeThreadExit != None:
                s.gaugeThreadExit = False
	        s.gaugeThread.join()
		time.sleep(1)
            ret = askExit(a)
	    if ret == False :
		handler = open("install.log","a")
        except exitException :
            del c
            del r
            del a
            handler.close()
            sys.exit(-1)

def gaugeUpdaterThread(promptObj, dialogObj, text, makeObj, ti=None):
    import time
    if ti == None:
	ti = 0.5
    try:
        i = None
        for i in range(0,90):
            if makeObj.gaugeThreadExit :
               promptObj.updateGaugeGen(dialogObj,i,progress=text)
               time.sleep(ti)	
        sys.exit(1)
    except KeyboardInterrupt :
         sys.exit(1)

def clusterDeployerThread(cmdObj,node):
    rawPkgName="ChelsioUwire-2.12.0.3"
    pkgName="ChelsioUwire-2.12.0.3.tar.gz"
    pkgDir= os.path.abspath('../.')
    absPkgPath= pkgDir + os.sep + rawPkgName
    shscript= os.path.abspath('.') + os.sep + "scripts" + os.sep + "cp_untar_install.sh"
    if cmdObj.uninstall:
	cmd = "sh %s %s %s %s %s %s %s %s"%(shscript,node,"no",absPkgPath,rawPkgName, cmdObj.logDir + os.sep + node, cmdObj.configTune, "no")
    else:
	if cmdObj.installOfed:
		cmd = "sh %s %s %s %s %s %s %s %s"%(shscript,node,"yes",absPkgPath,rawPkgName,cmdObj.logDir + os.sep + node, cmdObj.configTune, "yes")
	else:
		cmd = "sh %s %s %s %s %s %s %s %s"%(shscript,node,"yes",absPkgPath,rawPkgName,cmdObj.logDir + os.sep + node, cmdObj.configTune, "no")
    sts,out = commands.getstatusoutput(cmd)

def clusterhmgDeployerThread(cmdObj,node):
    if cmdObj.configTune == "unified-wire-fcoe-init":
	confTune = 'UNIFIED_WIRE'
    elif cmdObj.configTune == "low-latency-networking":
        confTune = 'LOW_LATENCY'
    elif cmdObj.configTune == "high-capacity-toe":
        confTune = 'HIGH_CAPACITY_TOE'
    elif cmdObj.configTune == "high-capacity-rdma":
        confTune = 'HIGH_CAPACITY_RDMA'
    elif cmdObj.configTune == "udp-offload-config":
        confTune = 'UDP_OFFLOAD'
    elif cmdObj.configTune == "edc-only-config":
        confTune = 'T5_WIRE_DIRECT_LATENCY'
    elif cmdObj.configTune == "high-capacity-wd":
        confTune = 'HIGH_CAPACITY_WD'
    elif cmdObj.configTune == "hash-filter-config" :
        confTune = 'T5_HASH_FILTER'
    elif cmdObj.configTune == "rdma-perf-config" :
        confTune = 'RDMA_PERFORMANCE'
    elif cmdObj.configTune == "iscsi-perf-config" :
        confTune = 'ISCSI_PERFORMANCE'
    elif cmdObj.configTune == "memfree-config" :
        confTune = 'MEMORY_FREE'

    rawPkgName="ChelsioUwire-2.12.0.3-RPM-Installer"
    pkgName="ChelsioUwire-2.12.0.3-RPM-Installer.tar.gz"
    pkgDir= os.path.abspath('.')
    absPkgPath= pkgDir + os.sep + rawPkgName
    shscript= os.path.abspath('.') + os.sep + "scripts" + os.sep + "cp_rpm_cluster_install.sh"
    if cmdObj.uninstall:
	if cmdObj.installOfed :
		print "uninstall OFED"
	        cmd = "sh %s %s %s %s %s %s %s %s"%(shscript,node,"no",absPkgPath,rawPkgName, cmdObj.logDir + os.sep + node, confTune, "yes")
	else :
		cmd = "sh %s %s %s %s %s %s %s %s"%(shscript,node,"no",absPkgPath,rawPkgName, cmdObj.logDir + os.sep + node, confTune, "no")
    else:
        if cmdObj.installOfed:
                cmd = "sh %s %s %s %s %s %s %s %s"%(shscript,node,"yes",absPkgPath,rawPkgName,cmdObj.logDir + os.sep + node, confTune, "yes")
        else:
                cmd = "sh %s %s %s %s %s %s %s %s"%(shscript,node,"yes",absPkgPath,rawPkgName,cmdObj.logDir + os.sep + node, confTune, "no")
    sts,out = commands.getstatusoutput(cmd)

def getLogsThread(cmdObj,node):
    if cmdObj.genRpmpack :
	rawPkgName="ChelsioUwire-2.12.0.3-RPM-Installer"
	pkgName="ChelsioUwire-2.12.0.3-RPM-Installer.tar.gz"
	pkgDir = os.path.abspath('.')
    else: 
        rawPkgName="ChelsioUwire-2.12.0.3"
        pkgName="ChelsioUwire-2.12.0.3.tar.gz"
        pkgDir= os.path.abspath('../.')
    absPkgPath= pkgDir + os.sep + rawPkgName
    shscript= os.path.abspath('.') + os.sep + "scripts" + os.sep + "get_logs.sh"
    if cmdObj.uninstall:
	cmd = "sh %s %s %s %s %s "%(shscript,node,absPkgPath,rawPkgName, cmdObj.logDir + os.sep + node)
    else:
	cmd = "sh %s %s %s %s %s "%(shscript,node,absPkgPath,rawPkgName,cmdObj.logDir + os.sep + node)
    sts,out = commands.getstatusoutput(cmd)
    if sts != 0 :
	print 'Getting Logs failed on %s machine'%(node)

def tri(a):
    a.yesno(a.textbox("README.txt"))

def getRowColumn():
    import commands as c
    ret = c.getstatusoutput('/bin/stty -a')
    r = None
    c = None
    if ret[0] == 0 :
        j = ret[1].split(";")
        for i in j :
            k = i.strip()
            if k.find('rows') == 0 :
                r = k.split(" ")[1]
            elif k.find('columns') == 0 :
                c = k.split(" ")[1]
    return c,r

def printChelsioHeader():
    print "-------------------------------"
    print "Chelsio Unified Installer v2.0 "
    print "-------------------------------"
    sys.stdout.flush
	
def printChelsioClsDepHeader():
    print "----------------------------------------------"
    print "Chelsio Cluster Deployment Installer v2.0 "
    print "----------------------------------------------"
    sys.stdout.flush

def printWarningHeader():
    print "--------"
    print "WARNING"
    print "--------"
    sys.stdout.flush

def indent(rows, hasHeader=False, headerChar='-', hasrowSep=True, delim=' | ', justify='left',
           separateRows=True, prefix='', postfix='', wrapfunc=lambda x:x):
        def rowWrapper(row):
                newRows = [wrapfunc(item).split('\n') for item in row]
                return [[substr or '' for substr in item] for item in map(None,*newRows)]
        logicalRows = [rowWrapper(row) for row in rows]
        columns = map(None,*reduce(operator.add,logicalRows))
        maxWidths = [max([len(str(item)) for item in column]) for column in columns]
        rowSeparator = headerChar * (len(prefix) + len(postfix) + sum(maxWidths) + \
                             len(delim)*(len(maxWidths)-1))
        justify = {'center':str.center, 'right':str.rjust, 'left':str.ljust}[justify.lower()]
        output=cStringIO.StringIO()
        print >> output, rowSeparator
        for physicalRows in logicalRows:
                for row in physicalRows:
                        print >> output, \
                        prefix \
                        + delim.join([justify(str(item),width) for (item,width) in zip(row,maxWidths)]) \
                        + postfix
			if hasrowSep :
				print >> output, rowSeparator
	if not hasrowSep : 
	        print >> output, rowSeparator
        return output.getvalue()


def wrap_always(text, width):
        return '\n'.join([ text[width*i:width*(i+1)] \
                for i in xrange(int(math.ceil(1.*len(text)/width))) ])

def installDialog():
    printChelsioHeader()
    print "Installing dialog on machine."
    pwd = os.path.abspath('.')
    supportPath = pwd + os.sep + "support"
    dialogZip = pwd + os.sep + "support/dialog-src.tar.gz"
    cmd = ' tar xzf ' + dialogZip
    commands.getstatusoutput(cmd)
    os.chdir('dialog-src')
    if platform.release().split(".")[0] < 3 :
        cmd = 'patch -p1 < resize.patch';
        status, output = commands.getstatusoutput(cmd)
    if platform.architecture()[0] == '64bit':
        cmd = './configure --prefix=/usr --libdir=/usr/lib64/ && make && make install'
    elif platform.architecture()[0] == '32bit':
        cmd = './configure --prefix=/usr --libdir=/usr/lib/ && make && make install'
    else :
        print 'unknown architecture'
        os.chdir(pwd)
        return -1
    status, output = commands.getstatusoutput(cmd)
    if int(status) > 0 :
        os.chdir(pwd)
        fd = os.open('dialog.log',os.O_CREAT|os.O_WRONLY)
        os.write(fd,output)
        print "Dialog installation failed. Please check dialog.log file for the errors"
        os.close(fd)
        cmd = 'rm -rf dialog-src'
        commands.getstatusoutput(cmd)
        sys.exit(1)
    os.chdir(pwd)
    cmd = 'rm -rf dialog-src'
    commands.getstatusoutput(cmd)
    return status 

def main():
    cmdObj = cmds()
    cmdObj.parseArgs(sys.argv[1:])
    try:
	if cmdObj.silent:
	    cmdSilent()
        elif len(sys.argv) > 1:
            cmdMain()
        elif checkDialog() == False :
            while (1):
                os.system('clear')
                printChelsioHeader()
                a = raw_input("Dialog required for installer is not present on the machine.\nPress 'y' to install dialog on machine(DEFAULT).\nPress 'n' to exit and use CLI(check \"install.py -h\" for more info).\n\nInput[y]:")
                if a.lower() == 'n' :
                    sys.exit(0)
                    #cmdMain()
                    #break;
                elif a.lower() == 'y' or a == "" :
                    os.system('clear')
                    status = installDialog()
                    sys.stdout.write("Done\n")
                    if status != 0:
                        cmdMain()
                    elif checkDialog():
                        cmdDialog()
                        break;
                    else:
                        print 'Dialog Installation succeeded still checkdialog failed'
                        cmdMain()
                        break;
                else :
                    print "provide a valid input"
        else :
            cmdDialog()
    except KeyboardInterrupt :
        print '\nAborting Installer.\n'
        sys.exit(-1)

def checkDialog():
    import dialog
    try :
        a = dialog.Dialog()
    except :
        return False
    return True

if __name__ == '__main__' :
    main()
