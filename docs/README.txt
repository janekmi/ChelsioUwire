                    ****************************************
                                   README

                    ****************************************

                       Chelsio T5/T4 Family Unified Wire
                                   for Linux


                             Version : 2.12.0.3
                             Date    : 04/27/2016



Overview
================================================================================

Chelsio Unified Wire software for Linux is an easy to use utility developed to 
provide installation of 64-bit Linux based drivers and tools for Chelsio's T5 
and T4 Unified Wire Adapters. The Chelsio Unified Wire Package provides an 
interactive installer to install various drivers and utilities.  
It consists of the following components:

a. Network (NIC/TOE)
b. Virtual Function Network (vNIC) 
c. iWARP (RDMA)
d. RDMA Block Device Driver (RBD)
e. WD-UDP
f. iSCSI PDU Offload Target  
g. iSCSI PDU Offload Initiator 
h. Data Center Bridging (DCB)
i. FCoE PDU Offload Target
j. FCoE Full Offload Initiator 
k. Offload Bonding driver
l. Offload Multi-Adapter Failover(MAFO) 
m. UDP Segmentation Offload and Pacing
n. Offload IPv6 driver
o. Bypass driver
p. Classification and Filtering feature
q. Traffic Management feature (TM)
r. Unified Wire Manager (UM)
s. Unified Boot Software
t. Lustre File System
u. Utility Tools (cop,cxgbtool,t4_perftune,benchmark tools,sniffer & tracer)
v. libs (iWARP and WD-UDP libraries)



================================================================================
  CONTENTS
================================================================================

- 1. Requirements
- 2. Supported Operating Systems
- 3. Supported Cards
- 4. How To Use
- 5. Support Documentation
- 6. Customer Support



1. Requirements
================================================================================

1.1. Network (NIC/TOE)
======================

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.



1.2. Virtual Function Network (vNIC) 
====================================

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and an SR-IOV enabled system with 
  supported platforms mentioned in section 2.



1.3. iWARP (RDMA) 
=================

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2. 
  
- If you are planning to upgrade OFED on one member of the cluster, the upgrade 
  needs to be installed on all the members.
  
- If you want to install OFED with NFS-RDMA support, please see "Setting up 
  NFS-RDMA" in iWARP (RDMA) chapter in the User's Guide.


  
1.4. RDMA Block Device Driver (RBD)
===================================

- Chelsio T5 40/10/1Gb adapter and system with supported platforms mentioned in 
  section 2.

  
  
1.5. WD-UDP
============

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.

  
    
1.6. iSCSI PDU Offload Target  
=============================

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.
  
- iSCSI PDU offload target driver (chiscsi_t4.ko) requires NIC(cxgb4), 
  TOE(t4_tom & toecore) and iSCSI non-offload(chiscsi_base.ko) modules to work.
  Whereas the iSCSI non-offload target driver requires only NIC module.
 

  
1.7. iSCSI PDU Offload Initiator  
================================

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.
  
- The iSCSI PDU Offload Initiator driver (cxgb4i) runs on top of 
  NIC module(cxgb4) and open-iscsi-2.0-872/873 only, on a T5/T4 card.
 
- If you're planning to install iSCSI PDU Offload Initiator, please install 
  openssl-devel package.


  
1.8. Data Center Bridging (DCB)   
===============================

- Chelsio T5/T4 10Gb adapter and system with supported platforms 
  mentioned in section 2.
  
    
  
1.9. FCoE PDU offload Target   
============================

- Chelsio T5 40/10Gb adapter and system with supported platforms 
  mentioned in section 2.
  
  
  
1.10. FCoE full offload Initiator   
=================================

- Chelsio T5/T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.



1.11. Offload Bonding driver  
===========================

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.
  
  
  
1.12. Offload Multi-Adapter Failover  
====================================

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.
  
  
  
1.13. UDP Segmentation Offload and Pacing driver  
================================================

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.



1.14. Offload IPv6 driver  
=========================

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.
  
  
  
1.15. Bypass driver  
===================

- Chelsio T4 10/1Gb and system with supported platforms mentioned in section 2. 

  
  
1.16. Classification and Filtering
==================================

- Chelsio T5 40/10/1Gb or T4 10/1Gb and system with supported platforms mentioned 
  in section 2.
  
  
  
1.17. Traffic Management
========================

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.
  
  
  
1.18. Unified Wire Manager
==========================

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.
  
  
  
1.19. Unified Boot Software
===========================

- Chelsio T5 40/10/1Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.
- DOS bootable USB flash drive or Floppy Disk.



1.20. Lustre File System
========================

- Chelsio T5 10Gb or T4 10/1Gb adapter and system with supported platforms 
  mentioned in section 2.
- Lustre-2.6.0

  
  
2. Supported Operating Systems
================================================================================

The Chelsio Unified Wire software has been developed to run on 64-bit Linux 
based platforms. Following is the list of Drivers/Software and supported Linux
distributions.

2.1. x86_64 Architecture
========================

|########################|#####################################################|
|   Linux Distribution   |                Driver/Software                      |
|########################|#####################################################|
|RHEL 7.2,               |NIC/TOE*,vNIC*,iWARP*,RBD*,WD-UDP,iSCSI Target*,     |
|3.10.0-327.el7          |iSCSI Initiator*,DCB*,FCoE Initiator*,Bonding*,MAFO*,|
|                        |UDP-SO*,IPv6*,Bypass*,Sniffer & Tracer,Filtering*,   |
|                        |TM*,uBoot(PXE,FCoE,iSCSI)*                           |
|------------------------|-----------------------------------------------------|
|RHEL 7.1,               |NIC/TOE,vNIC,iWARP,RBD*,WD-UDP,iSCSI Target,         |
|3.10.0-229.el7          |iSCSI Initiator,DCB,FCoE Initiator,Bonding,MAFO,     |
|                        |UDP-SO,IPv6,Bypass,Sniffer & Tracer,Filtering,TM,    |
|                        |uBoot(PXE,FCoE,iSCSI)                                |
|------------------------|-----------------------------------------------------|
|RHEL 6.7,               |NIC/TOE*,vNIC*,iWARP*,WD-UDP*,iSCSI Target*,         |
|2.6.32-573.el6          |iSCSI Initiator*,DCB*,FCoE Initiator*,Bonding*,MAFO*,|  
|                        |UDP-SO*,IPv6*,Bypass*,Sniffer & Tracer*,Filtering*,  |
|                        |TM*,uBoot(PXE,FCoE,iSCSI)*                           |        
|------------------------|-----------------------------------------------------|
|RHEL 6.6,               |NIC/TOE*,vNIC*,iWARP*,WD-UDP*,iSCSI Target*,         |
|2.6.32-504.el6          |iSCSI Initiator*,DCB*,FCoE Initiator*,Bonding*,MAFO*,|
|                        |UDP-SO*,IPv6*,Bypass*,Sniffer & Tracer*,Filtering*,  |
|                        |TM*,UM,uBoot(PXE,FCoE,iSCSI)                         |
|------------------------|-----------------------------------------------------|
|RHEL 6.5,               |NIC/TOE*,vNIC*,iWARP*,WD-UDP*,iSCSI Target*,         |
|2.6.32-431.el6          |iSCSI Initiator*,DCB*,FCoE Initiator*,Bonding*,MAFO* |
|                        |UDP-SO*,IPv6*,Bypass*,Sniffer & Tracer*,Filtering*,  |
|                        |TM*,Lustre*                                          |
|------------------------|-----------------------------------------------------|
|SLES 12 SP1,            |NIC/TOE*,vNIC*,iWARP*,RBD*,WD-UDP*,iSCSI Target*,    | 
|3.12.49-11-default      |iSCSI Initiator*,DCB*,FCoE Initiator*,Bonding*,MAFO* | 
|                        |UDP-SO*,IPv6*,Bypass*,Sniffer & Tracer*,Filtering*,  |
|                        |TM*,uBoot(PXE,FCoE,iSCSI)*                           |
|------------------------|-----------------------------------------------------|
|SLES 12,                |NIC/TOE*,vNIC*,iWARP*,RBD*,WD-UDP*,iSCSI Target*,    | 
|3.12.28-4-default       |iSCSI Initiator*,DCB*,FCoE Initiator*,Bonding*,MAFO* | 
|                        |UDP-SO*,IPv6*,Bypass*,Sniffer & Tracer*,Filtering*,  |
|                        |TM*,uBoot(PXE,FCoE,iSCSI)                            |
|------------------------|-----------------------------------------------------|
|SLES 11 SP4,            |NIC/TOE*,vNIC*,iWARP*,WD-UDP*,iSCSI Target*,         |
|3.0.101-63-default      |iSCSI Initiator*,DCB*,FCoE Initiator*,Bonding*,MAFO*,| 
|                        |UDP-SO*,IPv6*,Bypass*,Sniffer & Tracer*,Filtering*,  |
|                        |TM*,uBoot(PXE,FCoE,iSCSI)*                           |
|------------------------|-----------------------------------------------------|
|SLES 11 SP3,            |NIC/TOE,vNIC,iWARP,WD-UDP,iSCSI Target,              |
|3.0.76-0.11-default     |iSCSI Initiator,DCB*,FCoE Initiator,Bonding,MAFO,    | 
|                        |UDP-SO,IPv6,Bypass,Sniffer & Tracer,Filtering,TM,UM  |
|------------------------|-----------------------------------------------------|
|Ubuntu 14.04.3,         |NIC/TOE*,vNIC*,iWARP*,WD-UDP*,iSCSI Target*,         |
|3.19.0-25-generic       |iSCSI Initiator*,DCB*,FCoE Initiator*,Bonding*,MAFO*,|  
|                        |UDP-SO*,IPv6*,Bypass*,Sniffer & Tracer*,Filtering*,  |
|                        |TM*                                                  | 
|------------------------|-----------------------------------------------------|
|Ubuntu 14.04.2,         |NIC/TOE*,vNIC*,iWARP*,WD-UDP*,iSCSI Target*,         | 
|3.16.0-30-generic       |iSCSI Initiator*,DCB*,FCoE Initiator*,Bonding*,MAFO*,|
|                        |UDP-SO*,IPv6*,Bypass*,Sniffer & Tracer*,Filtering*,  |
|                        |TM*                                                  |
|------------------------|-----------------------------------------------------|
|Kernel.org linux-4.1    |NIC/TOE*,vNIC*,iWARP*,RBD*,WD-UDP*,iSCSI Target*,    | 
|                        |iSCSI Initiator*,DCB*,FCoE Initiator*,Bonding*,MAFO*,|
|                        |UDP-SO*,IPv6*,Bypass*,Sniffer & Tracer*,UDP-SO*,     |
|                        |Filtering*,TM*                                       |
|------------------------|-----------------------------------------------------|
|Kernel.org linux-3.18   |NIC/TOE*,vNIC*,iWARP*,RBD*,WD-UDP*,iSCSI Target*,    | 
|                        |iSCSI Initiator*,DCB*,FCoE Initiator*,Bonding*,MAFO*,|
|                        |UDP-SO*,IPv6*,Bypass*,Sniffer & Tracer*,Filtering*,  |
|                        |TM*                                                  |
|------------------------|-----------------------------------------------------|
|Kernel.org linux-3.17   |NIC/TOE,vNIC,iWARP,RBD,WD-UDP,iSCSI Target,          | 
|                        |iSCSI Initiator,DCB,FCoE Initiator,Bonding,MAFO,     |
|                        |UDP-SO,IPv6,Bypass,Sniffer & Tracer,Filtering,TM     |
|------------------------|-----------------------------------------------------|
|Kernel.org linux-3.6    |NIC/TOE*,vNIC*,iWARP*,WD-UDP*,iSCSI Target*,         |
|                        |iSCSI Initiator*,DCB*,FCoE Target^*,FCoE Initiator*, |
|                        |Bonding*,MAFO*,UDP-SO*,IPv6*,Bypass*,                |
|                        |Sniffer & Tracer*,Filtering*,TM*                     |
|------------------------------------------------------------------------------|

*Limited QA performed.
^Kernel.org linux-3.6.11 on RHEL 6.x distribution. 

NOTE:Other kernel versions have not been tested and are not guaranteed to work.


2.2. POWERPC64 Architecture
===========================

|########################|#####################################################|
|   Linux Distribution   |                Driver/Software                      |
|########################|#####################################################|
|RHEL 7.1 BE (POWER7),   |NIC/TOE,iWARP,iSCSI Target,iSCSI Initiator,IPv6      |
|3.10.0-229.el7.ppc64    |                                                     |
|------------------------|-----------------------------------------------------|
|RHEL 7.1 LE (POWER8)    |NIC/TOE,iWARP,iSCSI Target,iSCSI Initiator,IPv6      |
|3.10.0-229.ael7b.ppc64le|                                                     |
|------------------------------------------------------------------------------|

NOTE:Other kernel versions have not been tested and are not guaranteed to work.



3. Supported Hardware
================================================================================

3.1.Chelsio Drivers/Software and supported T5/T4 adapters
=========================================================

|########################|#####################################################|
| Chelsio T5/T4 Adapter  |                 Driver/Software                     |
|########################|#####################################################|
|------------------------|-----------------------------------------------------|
|T580-OCP-SO             |NIC,uBoot(PXE)                                       |
|------------------------|-----------------------------------------------------|
|T520-OCP-SO             |NIC,uBoot(PXE)                                       |
|------------------------|-----------------------------------------------------|
|T520-BT                 |NIC/TOE,vNIC,iWARP,RBD,WD-UDP,iSCSI Target,          |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,IPv6,    |
|                        |Sniffer & Tracer,UDP-SO,Filtering,TM,UM,             |
|                        |uBoot(PXE,FCoE,iSCSI),Lustre                         |
|------------------------|-----------------------------------------------------|
|T580-CR                 |NIC/TOE,vNIC,iWARP,RBD,WD-UDP,iSCSI Target,          |
|                        |iSCSI Initiator,DCB,FCoE Target,Bonding,MAFO,IPv6,   |
|                        |Sniffer & Tracer,UDP-SO,Filtering,TM,UM,             |
|                        |uBoot(PXE,FCoE,iSCSI),Lustre                         | 
|------------------------|-----------------------------------------------------|
|T580-SO-CR              |NIC,Filtering,uBoot(PXE)                             |
|------------------------|-----------------------------------------------------|
|T580-LP-CR              |NIC/TOE,vNIC,iWARP,RBD,WD-UDP,iSCSI Target,          |
|                        |iSCSI Initiator,DCB,FCoE Target,Bonding,MAFO,IPv6,   |
|                        |Sniffer & Tracer,UDP-SO,Filtering,TM,UM,             |
|                        |uBoot(PXE,FCoE,iSCSI),Lustre                         |
|------------------------|-----------------------------------------------------|
|T520-LL-CR              |NIC/TOE,vNIC,iWARP,RBD,WD-UDP,iSCSI Target,          |
|                        |iSCSI Initiator,DCB,FCoE Target,FCoE Initiator,      |
|                        |Bonding,MAFO,IPv6,Sniffer & Tracer,UDP-SO,Filtering, |
|                        |TM,UM,uBoot(PXE,FCoE,iSCSI),Lustre                   |
|------------------------|-----------------------------------------------------|
|T520-SO-CR              |NIC,uBoot(PXE)                                       |
|------------------------|-----------------------------------------------------|
|T520-CR                 |NIC/TOE,vNIC,iWARP,RBD,WD-UDP,iSCSI Target,          |
|                        |iSCSI Initiator,DCB,FCoE Target,FCoE Initiator,      |
|                        |Bonding,MAFO,IPv6,Sniffer & Tracer,UDP-SO,Filtering, |
|                        |TM,UM,uBoot(PXE,FCoE,iSCSI),Lustre                   |
|------------------------|-----------------------------------------------------|
|T540-CR                 |NIC/TOE,vNIC,iWARP,RBD,WD-UDP,iSCSI Target,          |
|                        |iSCSI Initiator,UDP-SO,Bonding,MAFO,IPv6,            |
|                        |Sniffer & Tracer,Filtering,uBoot(PXE,FCoE,iSCSI),    |
|                        |Lustre                                               |
|------------------------|-----------------------------------------------------|
|T420-CR                 |NIC/TOE,vNIC,iWARP,WD-UDP,iSCSI Target,              |
|                        |iSCSI Initiator,DCB,Bonding,MAFO,IPv6,               |
|                        |Sniffer & Tracer,UDP-SO,Filtering,TM,UM,             |
|                        |uBoot(PXE,FCoE,iSCSI),Lustre                         |
|------------------------|-----------------------------------------------------|
|T440-CR                 |NIC/TOE,vNIC,iWARP,WD-UDP,iSCSI Target,              |
|                        |iSCSI Initiator,Bonding,MAFO,IPv6,Sniffer & Tracer,  |
|                        |UDP-SO,Filtering,TM,UM,uBoot(PXE,FCoE,iSCSI),Lustre  |
|------------------------|-----------------------------------------------------|
|T422-CR                 |NIC/TOE,vNIC,iWARP,WD-UDP,iSCSI Target,              |
|                        |iSCSI Initiator,Bonding,MAFO,IPv6,Sniffer & Tracer,  |
|                        |UDP-SO,Filtering,TM,UM,uBoot(PXE,FCoE,iSCSI),Lustre  |
|------------------------|-----------------------------------------------------|
|T420-SO-CR              |NIC/TOE,vNIC,Bonding,MAFO,IPv6,Filtering,UM,         |
|                        |uBoot(PXE)                                           |
|------------------------|-----------------------------------------------------|
|T404-BT                 |NIC/TOE,vNIC,iWARP,WD-UDP,iSCSI Target,              |
|                        |iSCSI Initiator,Bonding,MAFO                         |
|                        |IPv6,Sniffer & Tracer,UDP-SO,Filtering,TM,UM,        |
|                        |uBoot(PXE,FCoE,iSCSI)                                |
|------------------------|-----------------------------------------------------|
|T420-BCH                |NIC/TOE,iSCSI Target,iSCSI Initiator,                |
|                        |Bonding,MAFO,IPv6,Sniffer & Tracer,UDP-SO,Filtering, |
|                        |TM,UM,uBoot(PXE,FCoE,iSCSI)                          |
|------------------------|-----------------------------------------------------|
|T440-LP-CR              |NIC/TOE,vNIC,iWARP,WD-UDP,iSCSI Target,              |
|                        |iSCSI Initiator,Bonding,MAFO,IPv6,                   |
|                        |Sniffer & Tracer, UDP-SO,Filtering,TM,UM,            |
|                        |uBoot(PXE,FCoE,iSCSI)                                |
|------------------------|-----------------------------------------------------|
|T420-BT                 |NIC/TOE,vNIC,iSCSI Target,iSCSI Initiator,Bonding,   |
|                        |MAFO,IPv6,Sniffer & Tracer,UDP-SO,Filtering,TM,UM,   |
|                        |uBoot(PXE,FCoE,iSCSI)                                |
|------------------------|-----------------------------------------------------|
|T420-LL-CR              |NIC/TOE,vNIC,iWARP,WD-UDP,iSCSI Target,              |
|                        |iSCSI Initiator,DCB,Bonding,MAFO,IPv6,               |
|                        |Sniffer & Tracer,UDP-SO,Filtering,TM,UM,             |
|                        |uBoot(PXE,FCoE,iSCSI),Lustre                         |
|------------------------|-----------------------------------------------------|
|T420-CX                 |NIC/TOE,vNIC,iWARP,WD-UDP,iSCSI Target,              |
|                        |iSCSI Initiator,Bonding,MAFO,IPv6,Sniffer & Tracer,  |
|                        |UDP-SO,Filtering,TM,UM                               |
|------------------------|-----------------------------------------------------|
|B420-SR                 |Bypass                                               | 
|------------------------|-----------------------------------------------------|
|B404-BT                 |Bypass                                               | 
|------------------------------------------------------------------------------|



3.2. Unified Wire Manager (UM)
=============================

Supported T3 adapters
---------------------

- S302E
- S302E-C
- S310E-CR
- S310E-CR-C
- S310E-CXA
- S310E-SR+
- S310E-SR
- S310E-BT
- S320E-CR
- S320E-LP-CR
- S320E-CXA
- S320EM-BS
- S320EM-BCH
- N320E-G2-CR
- N320E
- N320E-CXA
- N320E-BT
- N310E
- N310E-CXA 



3.3. Unified Boot Software
==========================

3.3.1. Supported hardware platforms 
-----------------------------------

- DELL PowerEdge T710
- DELL PowerEdge 2950
- DELL PowerEdge T110
- Dell T5600
- IBM X3650 M2
- IBM X3650 M4*
- HP ProLiant DL385G2
- Supermicro X7DWE
- Supermicro X8DTE-F
- Supermicro X8STE
- Supermicro X8DT6
- Supermicro X9SRL-F
- Supermicro X9SRE-3F 
- ASUS P5KPL
- ASUS P8Z68

* If system BIOS version is lower than 1.5 and both Legacy and uEFI are enabled,
  please upgrade to 1.5 or higher. Otherwise the system will hang during POST.



3.3.2. Supported Switches
--------------------------

- Cisco Nexus 5010 with 5.1(3)N1(1a) firmware
- Arista DCS-7124S-F
- Mellanox SX_PPC_M460EX 

NOTE:Other platforms/switches have not been tested and are not guaranteed to 
     work.



4. How to Use
================================================================================

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.1. Chelsio Unified Wire
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

4.1.1. Installing Chelsio Unified Wire 
======================================

There are two main methods to install the Chelsio Unified Wire package: from 
source and from RPM. If you decide to use source, you can install the package 
using CLI or GUI mode. If you decide to use RPM, you can install the package 
using Menu or CLI mode. 

The following table describes the various "configuration tuning options" 
available during installation and drivers/software installed with each option by
default:

|#######################################|######################################|
|   T5/T4 Configuration Tuning Option   |     Driver/Software installed        |
|#######################################|######################################|
|Unified Wire                           |NIC/TOE,vNIC,iWARP,RBD,WD-UDP,        |
|                                       |iSCSI Target,iSCSI Initiator,IPv6,    |
|                                       |Sniffer & Tracer,FCoE Target,         | 
|                                       |FCoE Initiator,DCB,Lustre,Bonding,    |
|                                       |MAFO,UM(Agent,Client,WebGUI),         |
|                                       |Filtering,TM                          |
|---------------------------------------|--------------------------------------|
|Low latency Networking                 |NIC/TOE,iWARP,RBD,WD-UDP,IPv6,        |
|                                       |Sniffer & Tracer, Bonding,MAFO,       |
|                                       |UM(Agent,Client,WebGUI),Filtering,TM  |
|---------------------------------------|--------------------------------------|
|High capacity RDMA                     |NIC/TOE,iWARP,RBD,WD-UDP,Bonding,     |
|                                       |MAFO,IPv6,Sniffer & Tracer,           |
|                                       |UM(Agent,Client,WebGUI),Filtering,TM  |
|---------------------------------------|--------------------------------------|
|RDMA Performance                       |NIC/TOE,iWARP,RBD,                    |  
|                                       |UM(Agent,Client,WebGUI)               |
|---------------------------------------|--------------------------------------|
|High capacity TOE                      |NIC/TOE,Bonding,MAFO,IPv6,            |
|                                       |UM(Agent,Client,WebGUI),Filtering,TM  |
|---------------------------------------|--------------------------------------|
|iSCSI Performance*                     |NIC/TOE,iSCSI Target,iSCSI Initiator, |
|                                       |DCB,Bonding,UM(Agent,Client,WebGUI)   |
|---------------------------------------|--------------------------------------|
|UDP Seg.Offload & Pacing               |NIC/TOE,IPv6,USO,Bonding,             |
|                                       |UM(Agent,Client,WebGUI),Filtering,TM  |
|---------------------------------------|--------------------------------------|
|T5 Wire Direct Latency*                |NIC/TOE,iWARP,RBD,WD-UDP,             |
|                                       |UM(Agent,Client,WebGUI)               |
|---------------------------------------|--------------------------------------|
|High Capacity WD                       |NIC/TOE,WD-UDP,                       |
|                                       |UM(Agent,Client,WebGUI)               |
|---------------------------------------|--------------------------------------|
|T5 Hash Filter*                        |NIC,Filtering,UM(Agent,Client,WebGUI) |
|---------------------------------------|--------------------------------------|
|T5 Memory Free*^                       |NIC/TOE,iWARP,UM(Agent,Client,WebGUI) |
|------------------------------------------------------------------------------|

*Supported only on T5 adapters.
^Beta Release. Should be used only with SO adapters.


Follow the steps mentioned below for installation using CLI. For GUI or Menu 
based installation, refer the User's Guide.

a. From source
--------------

i.  Download the tarball ChelsioUwire-x.xx.x.x.tar.gz

ii. Untar the tarball
    
  [root@host~]# tar zxvfm ChelsioUwire-x.xx.x.x.tar.gz
  
iii. Change your current working directory to Chelsio Unified Wire package 
     directory. Build the source:

  [root@host~]# make
  
iv. Install the drivers, tools and libraries:
    
  [root@host~]# make install
  
v. The default configuration tuning option is Unified Wire.
   The configuration tuning can be selected using the following commands:

  [root@host~]# make CONF=<T5/T4 configuration>
  [root@host~]# make CONF=<T5/T4 configuration> install

NOTE: To view the different configuration tuning options, view help by 
      typing [root@host~]# make help

vi. Reboot your machine for changes to take effect.

IMPORTANT:Steps (iv) and (v) mentioned above will NOT install Bypass,FCoE PDU 
          Offload Target,DCB drivers and benchmark tools. They will have to be 
          installed manually. 
          Please refer to section "Installing individual drivers" for 
          instructions on installing them.


		  
Installation on updated kernels
----------------------------------------

If the kernel version on your Linux distribution is updated, please execute the 
following command to install the Unified Wire package:

   [root@host~]# make UNAME_R=<kernel_version>

Where kernel_version is the nearest supported kernel version. 

For example, if you want to install the package on a RHEL 6 distribution updated
to 2.6.32-431.20.3.el6 kernel, run the following commands:

   [root@host~]# make UNAME_R=2.6.32-431.el6
   [root@host~]# make UNAME_R=2.6.32-431.el6 install

To view the list of the supported kernel versions, run the following command:

   [root@host~]# make list_kernels

Reboot your machine for changes to take effect.



iWARP driver installation on Cluster nodes
------------------------------------------

IMPORTANT: Please make sure that you have enabled password less authentication 
           with ssh on the peer nodes for this feature to work.

Chelsio's Unified Wire package allows installing iWARP drivers on multiple 
Cluster nodes with a single command. Follow the procedure mentioned below:

i. Create a file (machinefilename) containing the IP addresses or hostnames of 
   the nodes in the cluster. You can view the sample file, sample_machinefile, 
   provided in the package to view the format in which the nodes have to be 
   listed.

ii. Now, execute the following command:

   [root@host~]# ./install.py -C  -m <machinefilename>
   
iii. Select the required T5/T4 configuration tuning option. The tuning options 
     may vary depending on the Linux distribution.

iv. Select the required Cluster Configuration.

v. If you already have the required version of OFED software installed, you can 
   skip this step. 

   To install OFED-3.18-1 choose the "Install-OFED option". To skip this step, 
   "select Skip-OFED".
   
vi. The selected components will now be installed.

The above command will install iWARP (iw_cxgb4) and TOE (t4_tom) drivers on all 
the nodes listed in the <machinefilename> file



b. From RPM (tarball) 
----------------------

NOTE: 
- IPv6 should be enabled in the machine to use the RPM Packages.
- Drivers installed from RPM Packages do not have DCB support.

i. Download the tarball specific to your operating system and architecture.

ii. Untar the tarball
    
E.g. For RHEL 6.6, untar using the following command:
    
   [root@host~]# tar zxvfm ChelsioUwire-x.xx.x.x-RHEL6.6_x86_64.tar.gz

iii. Change your current working directory to Chelsio Unified Wire package 
     directory. Run the following command:
    
   [root@host~]# ./install.py -i <nic_toe/all/bypass/udpso/wd>

nic_toe  :NIC and TOE drivers only
all      :all Chelsio drivers built against inbox OFED
bypass   :bypass drivers and tools
udpso    :UDP segmentation offload capable NIC and TOE drivers only
wd       :Wire Direct drivers and libraries only 

NOTE: The Installation options may vary depending on the Linux distribution.
   
iv. The default configuration tuning option is Unified Wire.
    The configuration tuning can be selected using the following command:

   [root@host~]# ./install.py -i <Installation mode> -c <T5/T4 configuration>

NOTE: To view the different configuration tuning options, view the help by 
      typing 

  [root@host~]# ./install.py -h
 
v. To install OFED and Chelsio Drivers built against OFED, run the above command
   with -o option.

   [root@host~]# ./install.py -i <Installation mode> -c <T5/T4 configuration> -o

vi. Reboot your machine for changes to take effect.

NOTE:If the installation aborts with the message "Resolve the errors/dependencies
     manually and restart the installation", please go through the 
     install.log to resolve errors/dependencies and then start the installation 
     again.
	 
	 
	 
iWARP driver installation on cluster nodes
-------------------------------------------

IMPORTANT:Please make sure that you have enabled password less authentication 
          with ssh on the peer nodes for this feature to work.

i. Create a file (machinefilename) containing the IP addresses or hostnames of 
   the nodes in the cluster. You can view the sample file, sample_machinefile, 
   provided in the package to view the format in which the nodes have to be 
   listed.

ii. Navigate to ChelsioUwire directory and execute the following command:

   [root@host~]# ./install.py -C  -m <machinefilename> -i <nic_toe/all/bypass/udpso/wd> -c <T5/T4 configuration> -o

Here, -o parameter will install OFED and Chelsio drivers built against OFED

The above command will install iWARP (iw_cxgb4) and TOE (t4_tom) drivers on all 
the nodes listed in the <machinefilename> file

iii. Reboot your machine for changes to take effect.


   
4.1.2. Installing individual drivers 
==================================== 

You can also choose to install drivers individually. Provided here are steps to 
build and install NIC, TOE, iWARP, RDMA Block Device, Bonding, Bypass, UDP 
Segmentation Offload, FCoE PDU Offload target, DCB drivers and benchmarking tools.
To know about other drivers, view help by running "make help".

i. To build and install NIC driver without offload support:

   [root@host~]# make nic
   [root@host~]# make nic_install

ii. To build and install NIC driver with offload support and Offload drivers:

   [root@host~]# make toe
   [root@host~]# make toe_install

iii. To build and install Offload drivers without IPv6 support:

   [root@host~]# make toe_ipv4
   [root@host~]# make toe_ipv4_install

iv. To build and install iWARP driver against outbox OFED:

   [root@host~]# make iwarp 
   [root@host~]# make iwarp_install
   
v. To build and install RDMA Block Device driver:
   
   [root@host~]# make rdma_block_device
   [root@host~]# make rdma_block_device_install

vi. To build and install bonding driver and Offload drivers:
   
   [root@host~]# make bonding
   [root@host~]# make bonding_install

vii. To build and install all drivers without IPv6 support:

   [root@host~]# make ipv6_disable=1
   [root@host~]# make ipv6_disable=1 install

viii. The above step will not install Bypass driver. Run the following commands to
     build and install Bypass driver:

   [root@host~]# make bypass
   [root@host~]# make bypass_install

ix. To build and install all drivers with DCB support:

   [root@host~]# make dcbx=1
   [root@host~]# make dcbx=1 install

x. The offload drivers support UDP Segmentation Offload with limited number 
    of connections (1024 connections).To build and install UDP Offload drivers 
    which support large number of offload connections (approx 10K), 

   [root@host~]# make udp_offload
   [root@host~]# make udp_offload_install

xi. To build and install FCoE Target driver: 

   [root@host~]# make fcoe_pdu_offload_target
   [root@host~]# make fcoe_pdu_offload_target_install

xii. The default T5/T4 configuration tuning option is Unified Wire. 
    The configuration tuning can be selected using the following commands:

   [root@host~]# make CONF=<T5/T4 configuration> <Build Target>
   [root@host~]# make CONF=<T5/T4 configuration> <Install Target>

xiii. To build and install drivers along with benchmarks: 

   [root@host~]# make BENCHMARKS=1
   [root@host~]# make BENCHMARKS=1 install

xiv. Unified Wire Manager will be installed by default. To skip the 
      installation: 

   [root@host~]# make INSTALL_UM=0 install
   
xv. The drivers will be installed as RPMs or Debian packages (for ubuntu). To 
     skip this and install drivers:
   
   [root@host~]# make SKIP_RPM=1 install


NOTE:To view the different configuration tuning options, view the help by 
     typing [root@host~]# make help

NOTE:If IPv6 is disabled in the machine, the drivers will be built and installed 
     without IPv6 Offload support by default.
 

 
4.1.3. Firmware Update
======================

The T5 (v1.15.37.0) and T4 (v1.15.37.0) firmwares are installed on the system, 
typically in /lib/firmware/cxgb4, and the driver will auto-load the firmwares if
an update is required. The kernel must be configured to enable userspace 
firmware loading support:

Device Drivers -> Generic Driver Options -> Userspace firmware loading support

The firmware version can be verified using ethtool:

   [root@host~]# ethtool -i <iface>


 
4.1.4. Uninstalling Chelsio Unified Wire
========================================

There are two methods to uninstall the Chelsio Unified Wire package: from source 
and from RPM. If you decide to use source, you can uninstall the package using 
CLI or GUI mode. 

Follow the steps mentioned below for uninstallation using CLI. For GUI based 
uninstallation, refer the User's Guide. 

a. From source
--------------

Navigate to the ChelsioUwire-x.xx.x.x directory. Uninstall the source using the 
following command:

   [root@host~]# make uninstall
  
NOTE:Uninstalling Unified Wire package will not uninstall Unified Wire Manager. 
     Refer the section, "Uninstalling individual drivers/software" to remove the 
     software manually.
	 
	 
	
iWARP driver uninstallation on Cluster nodes
----------------------------------------------

To uninstall iWARP drivers on multiple Cluster nodes with a single command, 
run the following command:

    [root@host~]# ./install.py -C -m <machinefilename> -u all

The above command will remove Chelsio iWARP (iw_cxgb4) and TOE (t4_tom) drivers 
from all the nodes listed in the machinefilename file.

  
  
b. From RPM (tar-ball)
----------------------

Go to the ChelsioUwire-x.xx.x.x directory. Run the following command:

   [root@host~]# ./uninstall.py <inbox/ofed>
  
Here,
inbox  : for removing all Chelsio drivers.
ofed   : for removing OFED and Chelsio drivers.


NOTE:The uninstallation options may vary depending on Linux distribution. View 
     help by running the following command for more information:

   [root@host~]# ./uninstall.py -h

NOTE:Uninstalling Unified Wire package will not uninstall Unified Wire Manager. 
     Refer the "Unified Wire Manager (UM)" section to remove the software 
     manually. 
	 
	 
	 
iWARP driver uninstallation on Cluster nodes
-----------------------------------------------

To uninstall iWARP drivers on multiple Cluster nodes with a single command, run 
the following:

   [root@host~]# ./install.py -C -m <machinefilename> -u

The above command will remove Chelsio iWARP (iw_cxgb4) and TOE (t4_tom) drivers 
from all the nodes listed in the machinefilename file.
  


4.1.5. Uninstalling individual drivers/software 
================================================

You can also choose to uninstall drivers/software individually. Provided here 
are steps to uninstall NIC, TOE, iWARP, RDMA Block Device, Bypass, UDP 
Segmentation Offload, FCoE PDU Offload target drivers and Unified Wire Manager(UM). 
To know about other drivers, view help by running "make help".

i. To uninstall NIC driver:

   [root@host~]# make nic_uninstall

ii. To uninstall drivers with offload support:

   [root@host~]# make toe_uninstall

iii. To uninstall iWARP driver:

   [root@host~]# make iwarp_uninstall

iv. To uninstall RDMA Block Device driver:   

   [root@host~]# make rdma_block_device_uninstall

v. To uninstall Bypass driver:

   [root@host~]# make bypass_uninstall

vi. To uninstall UDP Segmentation Offload driver:

   [root@host~]# make udp_offload_uninstall
 
vii. To uninstall FCoE Target driver:

   [root@host~]# make fcoe_pdu_offload_target_uninstall

viii. To uninstall Unified Wire Manager (UM)

   [root@host~]# make uninstall UM_UNINST=1   
OR
   [root@host~]# make tools_uninstall UM_UNINST=1   



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.2. Network (NIC/TOE)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

4.2.1. Loading/Unloading the driver
===================================

a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.

The driver must be loaded by the root user. Any attempt to load the driver as
a regular user will fail.
   
i. To load the driver in NIC mode(without offload support)
   
   [root@host~]# modprobe cxgb4

ii. To load driver in TOE mode(with offload support)

   [root@host~]# modprobe t4_tom
   
NOTE:Offload support needs to be enabled upon each reboot of the system. This 
     can be done manually as shown above.

In VMDirect Path environment, it is recommended to load the offload driver using
the following command:

   [root@host~]# modprobe t4_tom vmdirectio=1


   
b. Unloading the driver
------------------------

- To unload the driver in NIC mode(without offload support):

   [root@host~]# rmmod cxgb4


- A reboot is required to unload the driver in TOE(with Offload support). To 
  avoid rebooting, follow the steps mentioned below:

i. Load t4_tom driver with unsupported_allow_unload parameter. 

   [root@host~]# modprobe t4_tom unsupported_allow_unload=1

ii. Stop all the offloaded traffic, servers and connections. Check for the 
    reference count.

   [root@host~]# cat /sys/module/t4_tom/refcnt 

If the reference count is 0, the driver can be directly unloaded. Skip to step 
(iii). 

If the count is non-zero, load a COP policy which disables offload using the 
following procedure:

a. Create a policy file which will disable offload

   [root@host~]# cat policy_file
   all => !offload

b. Compile and apply the output policy file

   [root@host~]# cop –o no-offload.cop policy_file
   [root@host~]# cxgbtool ethX policy no-offload.cop

iii. Unload the driver: 

   [root@host~]# rmmod t4_tom
   [root@host~]# rmmod toecore
   [root@host~]# rmmod cxgb4



4.2.2. Instantiate Virtual Functions
=====================================
   
To instantiate the Virtual functions, load the cxgb4 driver with 'num_vf'
parameter with a non-zero value.  For example: 

   [root@host~]# modprobe cxgb4 num_vf=1,0,0,0

Each number instantiates the specified number of Virtual Functions for the 
corresponding Physical Function. The Virtual Functions can be assigned to 
Virtual Machines(Guest OS).

A maximum of 64 Virtual Functions can be instantiated with 16 Virtual Functions 
per Physical Function. Loading the cxgb4 driver with "num_vf" parameter loads 
the cxgb4vf driver by default. Hence unload the cxgb4vf driver (on the host) 
before assigning Virtual Functions to the Virtual Machines(Guest OS), using the 
following command:

   [root@host~]# rmmod cxgb4vf



4.2.3. Enabling Busy waiting
============================

Busy waiting/polling is a technique where a process repeatedly checks to see if 
an event has occurred, by spinning in a tight loop. By making use of similar 
technique, Linux kernel provides the ability for the socket layer code to poll 
directly on an Ethernet device's Rx queue. This eliminates the cost of  
interrupts and context switching, and with proper tuning allows to achieve 
latency performance similar to that of hardware.

Chelsio's NIC and TOE drivers support this feature and can be enabled on Chelsio
supported devices to attain improved latency.

To make use of BUSY_POLL feature, follow the steps mentioned below: 

i. Enable BUSY_POLL support in kernel config file by setting 
   "CONFIG_NET_RX_BUSY_POLL=y"
  
ii. Enable BUSY_POLL globally in the system by setting the values of following 
    sysctl parameters depending on the number of connections:

   sysctl -w net.core.busy_read=<value>
   sysctl -w net.core.busy_poll=<value> 
   
Set the values of the above parameters to 50 for 100 or less connections; and 
100 for more than 100 connections.

NOTE: BUSY_POLL can also be enabled on a per-connection basis by making use of
      SO_BUSY_POLL socket option in the socket application code.Refer socket 
      man-page for further details.
	  


4.2.4. Performance Tuning
=========================

To tune your system for better network performance, refer the 
"Performance Tuning" section of the Network (NIC/TOE) chapter in the User's Guide.

NOTE: For more information on additional configuration options, please refer 
      User's Guide.

	  
	  
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.3. Virtual Function Network (vNIC) 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

4.3.1. Instantiate Virtual Functions
===================================

To instantiate Chelsio Virtual Functions, please refer the Network (NIC/TOE) 
section 4.2.2



4.3.2. Loading/Unloading the Driver
==================================

a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.

The vNIC (cxgb4vf) driver must be loaded on the Guest OS by the root user. Any 
attempt to load the driver as a regular user will fail.

To load the driver execute the following command:

   [root@host~]# modprobe cxgb4vf
  

  
b. Unloading the Driver
-----------------------

To unload the driver execute the following command:

   [root@host~]# rmmod cxgb4vf

NOTE: For more information on additional configuration options, please refer 
      User's Guide.

        
   
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.4. iWARP (RDMA) 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Loading/Unloading the Driver
============================
  
a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.

The driver must be loaded by the root user. Any attempt to load the driver as
a regular user will fail.

To load the iWARP driver we need to load the NIC driver & core RDMA drivers first:
  
   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe iw_cxgb4
   [root@host~]# modprobe rdma_ucm

   

b. Unloading the driver
-----------------------

To unload the iWARP driver, run the following command:

   [root@host~]# rmmod iw_cxgb4


IMPORTANT:openmpi-1.4.3 can cause IMB benchmark stalls due to a shared memory 
          BTL issue. This issue is fixed in openmpi-1.4.5 and later releases.
          Hence, it is recommended that you download and install the latest
          stable release from Open MPI's official website,
          http://www.open-mpi.org
		  
NOTE: For more information on additional configuration options, please refer 
      User's Guide.
	  
	  
	  
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.5. RDMA Block Device Driver 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

4.5.1. Loading/Unloading the Driver
===================================
  
a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
with unified wire drivers. 

The driver must be loaded by the root user. Any attempt to load the driver as a 
regular user will fail.

- Run the following commands to load the RDMA block device driver on the target 
  machine:

   [root@host~]# modprobe iw_cxgb4
   [root@host~]# modprobe rdma_ucm
   [root@host~]# modprobe rbdt

- Run the following commands to load the RDMA block device driver on the initiator
  machine:

   [root@host~]# modprobe iw_cxgb4
   [root@host~]# modprobe rdma_ucm
   [root@host~]# modprobe rbdi



b. Unloading the driver
-----------------------

- Run the following commands to unload the RDMA block device driver on the target 
  machine:

   [root@host~]# rmmod rbdt
   [root@host~]# rmmod rdma_ucm
   [root@host~]# rmmod iw_cxgb4
 	
- Run the following commands to unload the RDMA block device driver on the 
  initiator machine:

   [root@host~]# rmmod rbdi
   [root@host~]# rmmod rdma_ucm
   [root@host~]# rmmod iw_cxgb4
   
   
4.5.2. Configuration
====================

a. Adding a Target
------------------

On the initiator machine, run the following command to add a target:

   [root@host~]# rbdctl -n -a <target_ip> -d <target_block_device> -p <target_port_number>

   
b. Removing a Target
--------------------

Run the following command to remove a target from the initiator machine:

   [root@host~]# rbdctl -r -d <initiator_device>

   
c. Listing Targets
------------------

Run the following command on the initiator, to list all the targets available:

   [root@host~]# rbdctl -l



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.6. WD-UDP
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

4.6.1. Loading/Unloading the Driver
===================================

a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.

InfiniBand modules from the OFED package should be loaded before proceeding. 
Load the cxgb4, iw_cxgb4 and rdma_ucm drivers:

   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe iw_cxgb4
   [root@host~]# modprobe rdma_ucm



b. Unloading the driver
-----------------------

To unload the iWARP driver, run the following command:

   [root@host~]# rmmod iw_cxgb4
  

  
4.6.2. Configuring WD-UDP 
=========================

Preload "libcxgb4_sock" using one of the methods mentioned below when starting 
your application:

Preloading using wdload script
------------------------------

   [root@host~]# PROT=UDP wdload <pathto>/your_application

The above command will generate an end point file, libcxgb4_sock.conf  at /etc/.
Parameters like interface name and port number can be changed in this file.

NOTE: If you encounter error while using wdload on kernels built on RHEL 5.x 
distribution, then run the above command as:

   [root@host~]# NUMA=0 PROT=UDP wdload <pathto>/your_application

Preloading manually
-------------------

Create a configuration file that defines which UDP endpoints should be 
accelerated, their vlan and priority if any, as well as which T5/T4 
interface/port should be used. The file /etc/libcxgb4_sock.conf contains these 
endpoint entries. Create this file on all systems using libcxgb4_sock. Here is 
the syntax:

   Syntax:
   endpoint { attributes } ...
   where attributes include:
           interface = interface-name
           port = udp-port-number

E.g:

   endpoint {interface=eth2 port=8888}
   endpoint {interface=eth3 port=9999}

The above file defines 2 accelerated endpoints, port 8888 which will use 
eth2, and port 9999 which will use eth3.

Now, preload libcxgb4_sock using the following command:

    [root@host~]# CXGB4_SOCK_CFG=<path to config file> LD_PRELOAD=libcxgb4_sock.so <pathto>/your_application

The following example shows how to run Netperf with WD-UDP:

server:

   [root@host~]# PROT=UDP wdload netserver -p <port_num>

client:
 
   [root@host~]# PROT=UDP wdload netperf -H <hostIp> -p <port_num> -t UDP_RR 

NOTE: i. In WD-UDP only one application can be run per T5/T4 device per UDP 
         port number.
         For running 2 concurrent netperf UDP_RR tests, each must use a 
         unique UDP port number or T5/T4 device.
 
         E.g.:
         endpoint {interface=eth2 port=8888}
         endpoint {interface=eth2 port=9000}

        The above file defines 2 accelerated endpoints, port 8888 and port 9000 
        both will be used by eth2 only.
   
     ii. In order to offload IPv6 UDP sockets, please select "low latency 
         networking" as T5/T4 configuration tuning option during installation.
   
     iii. Jumbo frames of 9000B are supported only on kernel 2.6.32 and above.


NOTE: For more information on additional configuration options, please refer 
      User's Guide.
     
     
     
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.7. iSCSI PDU Offload Target
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Loading/Unloading the Driver
============================

a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.

To load the module for RHEL distributions, run modprobe as follows:

   [root@host~]# modprobe chiscsi_t4

For SLES distributions:

   [root@host~]# modprobe chiscsi_t4 --allow-unsupported 


   
b. Unloading the driver
-----------------------

Use the following command to unload the module:

   [root@host~]# rmmod chiscsi_t4

NOTE:i. While using rpm-tar-ball for installation
        a. Uninstallation will result into chiscsi.conf file renamed into
        chiscsi.conf.rpmsave.
        b. It is advised to take a backup of chiscsi.conf file before you do an
        uninstallation and installation of new/same unified wire package.
        As re-installing/upgrading unified-wire package may lead to loss of
        chiscsi.conf file.

    ii. Installation/uninstallation using source-tar-ball will neither remove 
        the conf file nor rename it. It will always be intact.
        However it is recommended to always take a backup of your configuration 
        file for both methods of installation. 

NOTE: For more information on additional configuration options, please refer 
      User's Guide.   
      
	  
	  
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.8. iSCSI PDU Offload Initiator 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   
Loading/Unloading the Driver
============================

a. Loading the driver
----------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.

The driver must be loaded by the root user. Any attempt to loading the driver as
a regular user will fail.

Load cxgb4i driver using the following command:

   [root@host~]# modprobe cxgb4i
  
The cxgb4i module registers a new transport class "cxgb4i".  

On SLES distributions, load the driver with the '--allow' option:

   [root@host~]# modprobe cxgb4i --allow

If loading of cxgb4i displays "unkown symbols found" error in dmesg, follow the 
steps mentioned below: 

i. Kill iSCSI daemon "iscsid"
ii. View all the loaded iSCSI modules

   [root@host~]# lsmod | grep iscsi

iii. Now, unload them using the following command:

   [root@host~]# rmmod <modulename>

iv. Finally reload the cxgb4i driver


   
b. Unloading the driver
--------------------------

   [root@host~]# rmmod cxgb4i
   [root@host~]# rmmod libcxgbi

NOTE: For more information on additional configuration options, please refer 
      User's Guide.


  
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.9. DCB 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Data Center Bridging (DCB) refers to a set of bridge specification standards, 
aimed to create a converged Ethernet network infrastructure shared by all 
storage, data networking and traffic management services. An improvement to the 
existing specification, DCB uses priority-based flow control to provide 
hardware-based bandwith allocation and enhances transport reliability.  

NOTE: In this release, ETS bandwidth management will not work when Unified Wire 
      traffic is run with IEEE DCBx enabled.


	  
Loading/Unloading the Driver
============================

Before proceeding, please ensure that Unified Wire Installer is installed with 
DCB support as mentioned in "Installing individual drivers" section.

a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.

Network (cxgb4;t4_tom for full offload support) and FCoE Initiator (csiostor) 
drivers must be loaded in order to enable DCB feature. Also, the drivers must be
loaded by the root user. Any attempt to load the drivers as a regular user will 
fail. Run the following commands:

   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe t4_tom
   [root@host~]# modprobe csiostor

Once the storage and networking traffic are started simultaneously, they will 
honor DCB settings defined on the switch.



b. Unloading the driver
-----------------------

To disable DCB feature, unload FCoE Initiator and Network drivers:

   [root@host~]# rmmod csiostor
   [root@host~]# rmmod cxgb4

NOTE: If "t4_tom" is loaded, please reboot the system to unload the drivers.

NOTE: For more information on additional configuration options, please refer 
      User's Guide.
	  
	  
c. Running NIC & iSCSI Traffic together with DCBx
-------------------------------------------------

NOTE: Please refer "iSCSI PDU Offload Initiator" section to configure iSCSI 
Initiator.

Use the following procedure to run NIC and iSCSI traffic together with DCBx 
enabled.

i. Identify the VLAN priority configured for NIC and iSCSI class of traffic on 
   the switch.
ii. Create VLAN interfaces for running NIC and iSCSI traffic, and configure 
    corresponding VLAN priority.
	
Example:

Switch is configured with a VLAN priority of 2 and 5 for NIC and iSCSI class of 
traffic respectively. NIC traffic is run on VLAN10 and iSCSI traffic is run on 
VLAN20.

Assign proper VLAN priorities on the interface (here eth5), using the following 
commands on the host machine:

[root@host~]# vconfig set_egress_map eth5.10 0 2 
[root@host~]# vconfig set_egress_map eth5.20 5 5



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.10. FCoE PDU Offload Target 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Loading/Unloading the Driver
============================

a. Loading the driver
---------------------

IMPORTANT:
- Please ensure that all inbox drivers are unloaded before proceeding with 
  unified wire drivers.
- Any existing version of SCST driver will be replaced by version 3.0.0-pre2 
  during installation.

FCoE PDU Offload Target driver (chfcoe) is dependent on Network (cxgb4) and 
SCST (scst) drivers. SCST driver will be installed by default during Unified 
Wire Installation. 

The driver must be loaded by the root user. Any attempt to load the driver as a 
regular user will fail. It is recommended that MTU of minimum 2180 is set on all
the Chelsio interfaces on which you are planning to run FCoE PDU Offload Target.

NOTE : If older versions of cxgb4 and scst drivers are loaded, please unload 
       them before proceeding.

- To load the driver in FCF mode, run the following command:

   [root@host~]# modprobe chfcoe
  
- To load the driver in VN2VN mode, run the following command:

   [root@host~]# modprobe chfcoe chfcoe_fip_mode=1

- To load the driver in VN2VN mode with VLAN support, run the following command:

   [root@host~]# modprobe chfcoe chfcoe_fip_mode=1 chfcoe_vlanid=<vlan_id>
   
Alternatively, you can edit /etc/modprobe.d/chfcoe.conf for specifying VN2VN and
VLAN options.



b. Unloading the driver
------------------------

  To unload the driver, run the following command: 

  [root@host~]# modprobe –r chfcoe

NOTE: For more information on additional configuration options, please refer 
      User's Guide.
    
	
	
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.11. FCoE Full Offload Initiator 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

4.11.1. Loading/Unloading the Driver
====================================

a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.

The driver must be loaded by the root user. Any attempt to load the driver as a
regular user will fail.
   
To load the driver, execute the following command:

   [root@host~]# modprobe csiostor
   
To load the driver on any SLES distribution, execute the following command: 

   [root@host~]# modprobe csiostor --allow



b. Unloading the driver
------------------------

To unload the driver, execute the following command:

   [root@host~]# modprobe -r  csiostor

NOTE:If multipath services are running, unload of FCoE driver is not possible. 
     Stop the multipath service and then unload the driver.



4.11.2. Configuring the switch and Troubleshooting
==================================================

Please refer "Software Configuration and Fine-tuning" section in User's Guide

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.12. Offload Bonding driver
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

4.12.1. Loading/Unloading the Driver
====================================
  
a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.
   
The driver must be loaded by the root user. Any attempt to loading the driver as
a regular user will fail.

   To load the Bonding driver (with offload support), run the following command:
   
   [root@host~]# modprobe bonding

   
   
b. Unloading the driver
-----------------------

   To unload the bonding driver.

   [root@host~]# rmmod bonding

   

4.12.2. Offloading TCP traffic over a bonded interface
======================================================

The Chelsio Offload Bonding driver supports all the bonding modes in NIC Mode. 
In offload mode (t4_tom loaded) however, only the balance-rr (mode=0),
active-backup (mode=1),balance-xor (mode=2) and 802.3ad (mode=4) modes are 
supported.   

To offload TCP traffic over a bonded interface, use the following method:

i. Load the network driver with TOE support.
   
   [root@host~]# modprobe t4_tom

ii. Create a bonded interface 

   [root@host~]# modprobe bonding mode=1 miimon=100

iii. Bring up the bonded interface and enslave the interfaces to the bond

   [root@host~]# ifconfig bond0 up
   [root@host~]# ifenslave bond0 ethX ethY
   
NOTE: "ethX" and "ethY" are interfaces of the same adapter.

iv. Assign IPv4/IPv6 address to the bonded interface

   [root@host~]# ifconfig bond0 X.X.X.X/Y
   [root@host~]# ifconfig bond0 inet6 add <128-bit IPv6 Address> up   
      
v. Disable FRTO on the PEER: 

   [root@host~]# sysctl -w net.ipv4.tcp_frto=0


All TCP traffic will be offloaded over the bonded interface now.

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.13. Offload Multi-Adapter Failover (MAFO)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Multi-Adapter fail-over feature will work for link down events caused by:
- Cable unplug on bonded interface
- Bringing corresponding switch port down

NOTE: The feature will not work if the bonded interfaces are administratively 
      taken down. 
	  
IMPORTANT:
- Portions of this software are covered under US Patent "Failover and migration 
  for full-offload network interface devices : US 8346919 B1"
- Use of the covered technology is strictly limited to Chelsio ASIC-based 
  solutions.

   
4.13.1. Loading/Unloading the Driver
====================================

a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.

The driver must be loaded by the root user. Any attempt to load the driver as a 
regular user will fail.

To load the driver (with offload support), run the following command:

   [root@host~]# modprobe bonding 

   

b. Unloading the driver
-----------------------

To unload the driver, run the following command:

   [root@host~]# rmmod bonding 


   
4.13.2. Offloading TCP traffic over a bonded interface
======================================================

The Chelsio MAFO driver supports only the active-backup (mode=1) mode.   

To offload TCP traffic over a bonded interface, use the following method:

i. Load the network driver with TOE support.
   
   [root@host~]# modprobe t4_tom

ii. Create a bonded interface 

   [root@host~]# modprobe bonding mode=1 miimon=100

iii. Bring up the bonded interface and enslave the interfaces to the bond

   [root@host~]# ifconfig bond0 up
   [root@host~]# ifenslave bond0 ethX ethY
   
NOTE: "ethX" and "ethY" are interfaces of different adapters.

iv. Assign IPv4/IPv6 address to the bonded interface

   [root@host~]# ifconfig bond0 X.X.X.X/Y
   [root@host~]# ifconfig bond0 inet6 add <128-bit IPv6 Address> up  

v. Disable FRTO on the PEER: 

   [root@host~]# sysctl -w net.ipv4.tcp_frto=0   

All TCP traffic will be offloaded over the bonded interface now and fail-over
will happen in case of link-down event.
	 
NOTE: For more information on additional configuration options, please refer 
      User's Guide.


	 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.14. UDP Segmentation Offload and Pacing
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Loading/Unloading the Driver
============================

a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.

The driver must be loaded by the root user. Any attempt to load the driver as
a regular user will fail.

Run the following commands to load the driver:

   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe t4_tom

Though normally associated with the Chelsio TCP Offload engine, the t4_tom 
module is required in order to allow for the proper redirection of UDP socket 
calls.
 
 
 
b. Unloading the driver
-----------------------

Reboot the system to unload the driver. To unload without rebooting, refer 
"Unloading the driver" in Network (NIC/TOE) section.

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.15. Offload IPv6 driver
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Loading/Unloading the Driver
============================

IPv6 must be enabled in your system (enabled by default) to use the Offload IPv6
feature.Also, Unified Wire package must be installed with IPv6 support 
(see section 4.1 for more information).

a. Loading NIC & TOE drivers
------------------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.
		  
After installing Unified Wire package and rebooting the host, load the NIC 
(cxgb4) and TOE (t4_tom) drivers. The drivers must be loaded by root user. Any 
attempt to load the drivers as a regular user will fail.

   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe t4_tom

All the IPv6 traffic will be offloaded now.
 
 

b. Unloading NIC & TOE drivers
------------------------------

i. To unload the NIC driver:

   [root@host~]# rmmod cxgb4

ii. To unload the TOE driver:

Please reboot the system to unload the TOE driver. To unload without rebooting, 
refer "Unloading the driver" in Network (NIC/TOE) section.

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.16. Bypass Driver
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Before proceeding, please ensure that drivers are installed with Bypass support 
as mentioned in "Installing individual drivers" section.

Loading/Unloading the Driver
============================

a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.
		  
The driver must be loaded by the root user. Any attempt to load the driver as
a regular user will fail.

Run the following command to load the Bypass driver:

   [root@host~]# modprobe cxgb4



b. Unloading the driver
-----------------------

Run the following command to unload the Bypass driver:

   [root@host~]# rmmod cxgb4

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.17. WD Sniffing and Tracing
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

The objective of these utilities (wd_sniffer and wd_tcpdump_trace) is to provide
sniffing and tracing capabilities by making use of T5/T4's hardware features. 

Sniffer- Involves targeting specific multicast traffic and sending it directly 
         to user space. 
Tracer - All tapped traffic is forwarded to user space and also pushed back on 
         the wire via the internal loop back mechanism 

In either mode the targeted traffic bypasses the kernel TCP/IP stack and is 
delivered directly to user space by means of a RX queue which is defined by the 
register MPS_TRC_RSS_CONTROL.

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.18. Classification and Filtering
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Classification and Filtering feature enhances network security by controlling 
incoming traffic as they pass through network interface based on source and 
destination addresses, protocol, source and receiving ports, or the value of 
some status bits in the packet. 

4.18.1. Usage
=============

a. Creating Filter Rules
-------------------------

Network driver (cxgb4) must be installed before setting the filter rule. 

i. If you haven't done already, run the Unified Wire Installer with the 
   appropriate T5/T4 configuration tuning option to install the Network Driver.

ii. Next, run the following command to load the network driver:

   [root@host~]# modprobe cxgb4

iii. Now, create filter rules using cxgbtool:

   [root@host~]# cxgbtool ethx filter <index> action [pass/drop/switch]

Where, 
ethX   : Chelsio interface
index  : positive integer set as filter id
action : Ingress packet disposition
pass   : Ingress packets will be passed through set ingress queues
switch : Ingress packets will be routed to an output port with optional header 
         rewrite. 
drop   : Ingress packets will be dropped.

NOTE: In case of multiple filter rules, the rule with the lowest filter index 
      takes higher priority.
	  
	  

b. Listing Filter Rules
-----------------------

To list previously set filters, run the following command:

   [root@host~]# cxgbtool ethX filter show
	

	
c. Removing Filter Rules
------------------------

To remove a filter, run the following command with the corresponding filter rule
index

   [root@host~]# cxgbtool ethX filter index <delete|clear>

NOTE:For more information on additional parameters, refer to cxgbtool manual by 
     running the "man cxgbtool" command. 
	 
	 
	 
4.18.2. Hash/DDR Filters
========================

The default (Unified Wire) configuration tuning option allows you to create 
LE-TCAM filters, which has a limit of 496 filter rules. If you wish to create 
more, select "T5 Hash Filter" configuration tuning option during installation 
which allows you to create HASH/DDR filters with a capacity of ~0.5 million 
filter rules.

NOTE: Creating Hash/DDR Filters is currently supported only on T5 adapters.

a. Creating Filter Rules
------------------------

Network driver (cxgb4) must be installed and loaded before setting the filter 
rule. 

i. If you haven’t done already, run the Unified Wire Installer with the 
   "T5 Hash Filter" configuration tuning option to install the Network Driver.
   
ii. Load the network driver with DDR filters support :

   [root@host~]# modprobe cxgb4 use_ddr_filters=1

iii. Now, create filter rules using cxgbtool:

   [root@host~]# cxgbtool ethX filter <index> action [pass/drop/switch] fip <source IP> lip <destination IP> fport <source port> lport <destination port> hitcnts 1 cap maskless

Where, 
ethX               : Chelsio interface.
index              : Filter index. The user must provide a positive integer, 
                     which will be replaced by an automatically computed index, 
                     based on the hash (4-tuple). The index will be displayed 
                     after the filter rule is created successfully.
action             : Ingress packet disposition.
pass               : Ingress packets will be passed through set ingress queues.
switch             : Ingress packets will be routed to an output port with. 
                     optional header rewrite. 
drop               : Ingress packets will be dropped.
source IP/port     : Source IP/port of incoming packet.
destination IP/port: Destination IP/port of incoming packet.

NOTE: "source IP","destination IP","source port" and "destination port" are 
      mandatory parameters since Hash filters don't support masks and hence, 
      4-tuple must be supplied always for Hash filter. "cap maskless" parameter 
      should be appended in order to create Hash/DDR filter rules. Otherwise the
      above command will create LE-TCAM filter rules. 

	 
  
b. Listing Filter Rules
-----------------------

- To list the Hash/DDR filters set, run the following command:

   [root@host~]# cat /sys/kernel/debug/cxgb4/<bus-id>/hash_filters     

- To list both LE-TCAM and Hash/DDR filters set, run the following command:

   [root@host~]# cxgbtool ethX filter show

   
c. Removing Filter Rules
------------------------

To remove a filter, run the following command with cap maskless parameter and 
corresponding filter rule index:

   [root@host~]# cxgbtool ethX filter index <delete|clear> cap maskless

NOTE: Filter rule index can be determined by referring the "hash_filters" 
      file located in /sys/kernel/debug/cxgb4/<bus-id>/

NOTE: For more information on additional parameters, refer cxgbtool manual by
      running the man cxgbtool command.


d. Hit Counters
---------------

For LE-TCAM filters, hit counters will work simply by adding hitcnts 1 parameter 
to the filter rule. However, for Hash/DDR filters, you will have to make use of 
tracing feature and RSS queues. Here’s a step-by-step guide to enable hit 
counters for Hash/DDR filter rules:

i. Enable tracing on T5 adapter.

   [root@host~]# cxgbtool ethX reg 0x09800=0x13

ii. Setup a trace filter

   [root@host~]# echo tx1 snaplen=40 > /sys/kernel/debug/cxgb4/<bus_id>/trace0

NOTE: Use "snaplen=60" in case of IPv6.
             
iii. Configure the RSS Queue to receive traced packets. Determine the "RspQ ID" of 
   the queue by looking at "Trace" QType in 
   /sys/kernel/debug/cxgb4/<bus-id>/sge_qinfo file

   [root@host~]# cxgbtool ethX reg 0x0a00c=<Trace Queue0-RspQ ID>

The above step will trace all the packets transmitting from port1(tx1) to trace 
filter 0.



Multi-tracing
---------------

To enable hit counters for multiple Chelsio ports in Tx/Rx direction enable 
Multi-tracing. Using this we can configure 4 different RSS Queues separately 
corresponding to 4 trace-filters.

i. Enable Tracing as well as MultiRSSFilter

   [root@host~]# cxgbtool ethX reg 0x09800=0x33

ii. Setup a trace filter

   [root@host~]# echo tx0 snaplen=40 > /sys/kernel/debug/cxgb4/<bus_id>/trace0
   
iii. Configure the RSS Queue corresponding to trace0 filter configured above.
     Determine the "RspQ ID" of the queues by looking at "Trace" QType in 
     /sys/kernel/debug/cxgb4/<bus-id>/sge_qinfo file.

   [root@host~]# cxgbtool ethX reg 0x09808=<Trace-Queue0-RspQ ID>

iv. Similarly for other direction and for multiple ports run the follow commands:

   [root@host~]# echo rx0 snaplen=40 > /sys/kernel/debug/cxgb4/<bus-id>/trace1
   [root@host~]# echo tx1 snaplen=40 > /sys/kernel/debug/cxgb4/<bus-id>/trace2
   [root@host~]# echo rx1 snaplen=40 > /sys/kernel/debug/cxgb4/<bus-id>/trace3
   [root@host~]# cxgbtool ethX reg 0x09ff4=<Trace-Queue0-RspQ ID>
   [root@host~]# cxgbtool ethX reg 0x09ffc=<Trace-Queue0-RspQ ID>
   [root@host~]# cxgbtool ethX reg 0x0a004=<Trace-Queue0-RspQ ID>

NOTE: Use "snaplen=60" in case of IPv6.

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.19. Traffic Management
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Traffic Management capabilities built-in to Chelsio T5/T4 CNAs can shape transmit 
data traffic through the use of sophisticated queuing and scheduling algorithms 
built-in to the T5/T4 ASIC hardware which provides fine-grained software control 
over latency and bandwidth parameters such as packet rate and byte rate.

4.19.1. Loading/Unloading the Driver
====================================

a. Loading the driver
---------------------

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers.
		  
Traffic Management can be performed on non-offloaded connections as well as on 
offloaded connections.

The drivers must be loaded by the root user. Any attempt to load the drivers as 
a regular user will fail.Run the following commands to load the TOE driver:

   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe t4_tom
   
   
   
b. Unloading the driver
-----------------------

Reboot the system to unload the driver. To unload without rebooting, refer 
"Unloading the driver" in Network (NIC/TOE) section.



4.19.2. Usage
=============

a. Traffic Management of Non-Offloaded Connections 
--------------------------------------------------

The following example demonstrates the method to rate limit all TCP connections 
on class 0 to a rate of 300 Mbps for Non-offload connections:

i. Load the network driver and bring up the interface

   [root@host~]# modprobe cxgb4
   [root@host~]# ifconfig eth0 up
  
ii. Bind connections with destination IP address 192.168.5.3 to NIC TX queue 3 

   [root@host~]# tc qdisc add dev eth0 root handle 1: multiq
   [root@host~]# tc filter add dev eth0 parent 1: protocol ip prio 1 u32  match ip dst 192.168.5.3 action skbedit queue_mapping 3

iii. Bind the NIC TX queue to class 0 

   [root@host~]# cxgbtool eth0 sched-queue 3 0 

iv. Set the appropriate rule for class 0 

   [root@host~]# cxgbtool eth0 sched-class params  type packet  level cl-rl mode class  rate-unit bits  rate-mode absolute channel 0  class 0 max-rate 300000  pkt-size 1460



b. Traffic Management of Offloaded Connections 
----------------------------------------------

The following example demonstrates the method to rate limit all TCP connections 
on class 0 to a rate of 300 Mbps for offloaded connections:

i. Load the TOE driver and bring up the interface:

   [root@host~]# modprobe t4_tom
   [root@host~]# ifconfig eth0 up

ii. Create a new policy file (say new_policy_file) and add the following line to 
    associate connections with the given scheduling class:

   src host 102.1.1.1 => offload class 0

iii. Compile the policy file using COP 

   [root@host~]# cop -d -o <output_policy_file> <new_policy_file> 

iv. Apply the COP policy: 

   [root@host~]# cxgbtool eth0 policy <output_policy_file>
   
v. Set the appropriate rule for class 0 

   [root@host~]# cxgbtool ethX sched-class params  type packet  level cl-rl mode class  rate-unit bits  rate-mode absolute channel 0  class 0 max-rate 300000  pkt-size 1460


   
c. Traffic Management of Offloaded Connections with Modified Application
------------------------------------------------------------------------

The following example demonstrates the method to rate limit all TCP connections 
on class 0 to a rate of 300 Mbps for for offloaded connections with modified 
application.

i. Load the TOE driver and bring up the interface

   [root@host~]# modprobe t4_tom
   [root@host~]# ifconfig eth0 up

ii. Modify the application as mentioned in the Configuring Traffic Management 
    section in the User's Guide.
   
iii. Set the appropriate rule for class 0 

   [root@host~]# cxgbtool ethX sched-class params  type packet level cl-rl mode class  rate-unit bits  rate-mode absolute channel 0  class 0 max-rate 300000  pkt-size 1460 

NOTE:For more information on additional parameters, refer cop manual by running 
     the "man cxgbtool" command. 

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.20. Unified Wire Manager
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

4.20.1. Installation
====================

Chelsio Unified Wire has been designed to install Unified Wire Manager (UM) by 
default. All the three UM components, i.e. Management Agent, Client and Station,
will be installed on selecting any of the Terminator 4/Terminator 5 
configuration tuning options during installation. Hence, no separate 
installation is required. 



4.20.2. Management Station Configuration
========================================

a. Running Management Station on RHEL 6.x
-----------------------------------------

i. Start/Restart Apache httpd daemon:

   [root@host~]# service httpd start/restart

ii. Start/Restart the Management Station:

   [root@host~]# /etc/init.d/chelsio-mgmtstd start/restart



b. Running Management Station on SLES11SP3
---------------------------------------------

i. On SLES11SP3, Management Station needs to be configured before running. Hence,
   execute the following commands and provide valid inputs.

   [root@host~]# cd /etc/apache2
   [root@host~]# openssl genrsa -des3 -out server.key 1024
   [root@host~]# openssl req -new -key server.key -out server.csr
   [root@host~]# cp server.key server.key.org
   [root@host~]# openssl rsa -in server.key.org -out server.key
   [root@host~]# openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
   [root@host~]# cp server.crt ./ssl.crt
   [root@host~]# cp server.key ./ssl.key

ii. Start/Restart Apache services

   [root@host~]# rcapache2 start/restart

iii. Start/Restart the Management Station:

   [root@host~]# /etc/init.d/chelsio-mgmtstd start/restart



4.20.3. Un-Installation
=======================

Use the following query command to determine the name of  the agent/client RPM

   [root@host~]# rpm -qa | grep uwire


Now,Uninstall the RPM using the following syntax:

   [root@host~]# rpm -e <pkg name>



4.20.4. Verifying Agent/Client status
=====================================

i. Use following command to check whether Agent is running.

   [root@host~]# /etc/init.d/Chelsio-uwire_mgmtd  status
 
ii. Use the following query command to determine if Management Client is 
    installed:

   [root@host~]# chelsio_uwcli -V

The above query should confirm that Management Client is installed by displaying
a similar result:

Unified Manager client CLI version : 2.x.yy

 

4.20.5. Agent/Station Start/Stop/restart
========================================

- Use following command to start, stop or restart Agent:

   [root@host~]# /etc/init.d/Chelsio-uwire_mgmtd <start/stop/restart>

- Use following command to start, stop or restart Management station:

   [root@host~]# /etc/init.d/chelsio-mgmtstd <start/stop/restart>
 
 

4.20.6. Client Usage
====================

Use the following commands to view Management client Help file.

   [root@host~]# chelsio_uwcli /?

NOTE: For a detailed explanation on usage and configuration of various UM 
      components, please refer the User's Guide.


	  
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.21. Unified Boot Software
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

4.21.1. Flashing firmware & option ROM
======================================

Depending on the boot mode selected, Chelsio Unified Boot provides two methods 
to flash firmware and option ROM onto Chelsio adapters: Flash utility "cfut4" 
for Legacy mode and "HII" for uEFI mode. Both methods also provide the 
functionality to update/erase (T5/T4) Boot configuration, Hardware configuration
and Phy Firmware files.

a. Preparing USB flash drive
----------------------------

This document assumes that you are using an USB flash drive as a storage 
media for the necessary files. Follow the steps below to prepare the drive:

i. Create a DOS bootable USB flash drive.
ii. Create a directory "CHELSIO" on USB flash drive.
iii. If you haven't done already, download ChelsioUwire-x.xx.x.x.tar.gz from 
     Chelsio Download Center, service.chelsio.com
iv. Untar the downloaded package and change your working directory to "OptionROM"
    directory. 
	  
   [root@host~]# tar zxvfm ChelsioUwire-x.xx.x.x.tar.gz 	  
   [root@host~]# cd ChelsioUwire-x.xx.x.x/Uboot/OptionROM
   
v. Copy all the files and place them in the CHELSIO directory created on the 
   USB flash drive.
vi. Plug-in the USB flash drive in the system on which the Chelsio CNA is 
    installed.
vii. Reboot the system and enter the system BIOS setup.
viii. Make the USB flash drive as the primary boot device. 
ix. Save the changes and exit.

   
   
b. Legacy 
---------

i. Configure the system having Chelsio CNA to boot in Legacy mode. 

ii. Once the system boots from the USB flash drive, change your working directory
    to CHELSIO directory:

   C:\>cd CHELSIO

iii. Run the following command to list all Chelsio CNAs present in the 
     system. The list displays a unique index for each CNA found.

   C:\CHELSIO>cfut4 -l

iv. Delete any previous version of Option ROM flashed onto the CNA:

   C:\CHELSIO>cfut4 -d <idx> -xb 
   
Here, idx is the CNA index found in step (c) 

v. Delete any previous firmware using the following command:

   C:\CHELSIO>cfut4 -d <idx> -xh -xf 
  
vi. Delete any previous Option ROM settings:

   C:\CHELSIO>cfut4 -d <idx> -xc

vii. Run the following command to flash the appropriate firmware 
    (t5fw-x.xx.xx.x.bin for T5 adapters;t4fw-x.xx.xx.x.bin for T4 adapters). 

   C:\CHELSIO>cfut4 -d <idx> -uf <firmware_file>.bin
   
viii. Flash the Option ROM onto the Chelsio CNA using the following command:

   C:\CHELSIO>cfut4 -d <idx> -ub cubt4.bin  

Here, "cubt4.bin" is the unified option ROM image file present in the CHELSIO 
directory.   
 
ix. Flash the default boot configuration file.  

   C:\CHELSIO>cfut4 -d <idx> -uc bootcfg

x. Reboot the system for changes to take effect.



c. uEFI
----------

To configure Chelsio CNA using HII in uEFI mode, please refer User's Guide.



4.21.2. Driver Update Disk (DUD)
================================

The following section describes the procedure to create Driver Update Disks for 
RHEL and SLES distributions, for T5 adapters. In case of T4 adapters, you can 
skip this step and use inbox drivers to install the operating system.

a. Creating Driver Disk for RedHat Enterprise Linux
---------------------------------------------------

i. If you haven't done already, download ChelsioUwire-x.xx.x.x.tar.gz from 
   Chelsio Download Center, service.chelsio.com
ii. Untar the package.

   [root@host~]# tar zxvfm ChelsioUwire-x.xx.x.x.tar.gz

iii. Change your working directory to "LinuxDUD" directory. 

   [root@host~]# cd ChelsioUwire-x.xx.x.x/Uboot/LinuxDUD

iv. Insert a blank, formatted USB flash drive.
v. Depending on the distribution to be installed, copy the corresponding image 
   file to the USB drive.For example, execute the following command for 
   RHEL 6.6
    
   [root@host~]# cp Chelsio-DriverUpdateDisk-RHEL6.6-x86_64-x.xx.x.x.img <path to USB drive>
 
NOTE: For RHEL 7.X, use Chelsio-DriverUpdateDisk-RHEL7.X-x86_64-x.xx.x.x.iso



b. Creating Driver Disk for Suse Enterprise Linux
-------------------------------------------------

i. If you haven't done already, download ChelsioUwire-x.xx.x.x.tar.gz from 
   Chelsio Download Center, service.chelsio.com
ii. Untar the package

   [root@host~]# tar zxvfm ChelsioUwire-x.xx.x.x.tar.gz

iii. Insert a blank USB drive.
iv. Format the USB drive

   [root@host~]# mkfs.vfat /dev/sda1

v. Depending on the distribution to be installed, copy the corresponding image 
   file to the USB drive.For example, execute the following command for 
   SLES11sp4:
    
   [root@host~]# dd if=/root/ChelsioUwire-x.xx.x.x/Uboot/LinuxDUD/Chelsio-DriverUpdateDisk-SLES11sp4-x86_64-x.xx.x.x.img of=/dev/sda1

IMPORTANT:Please make sure the switch is upgraded to the latest available 
          firmware, before proceeding with the operating system installation.

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
4.22. Lustre File System 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

The Lustre file system is a scalable, secure, robust, and highly-available 
cluster file system that addresses I/O needs of large computing clusters, such 
as low latency and extreme performance. 

Creating/Configuring Lustre File System 
=======================================

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers

Follow the steps mentioned below to create and configure Lustre file system 
using Chelsio adapter:

i. Support for iWARP in the latest Lustre kernel is broken. To fix this, apply 
the patch "luster_kernel.patch" provided in "ChelsioUwire-x.xx.x.x/lustre/", 
before proceeding.

ii. Build kernel with Lustre support by following the procedure mentioned in 
http://wiki.lustre.org/index.php/Building_and_Installing_Lustre_from_Source_Code

NOTE: Lustre kernel RPMS can be downloaded from
https://downloads.hpdd.intel.com/public/lustre/lustre-2.6.0/el6/server/

iii. If you haven’t done already, install Chelsio Unfied Wire package. 

iv. Load the Network and iWARP driver as per requirement:

- To load Network driver in NIC mode:

   [root@host~]# modprobe cxgb4

- To load Network driver in TOE mode:

   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe t4_tom

- To load iWARP driver

   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe iw_cxgb4
   [root@host~]# modprobe rdma_ucm

v. Enable and assign IP address to Chelsio interface.

vi. Edit modprobe.conf file with appropriate interface name

   options lnet networks=tcp0(ethX),tcp1(ethY)  //For NIC/TOE
   options lnet networks=o2ib0(ethX),o2ib1(ethY) //For iWARP

where, ethX and ethY represent Chelsio interfaces.

vii. Load the following Lustre modules:

   [root@host~]# modprobe lnet	
   [root@host~]# modprobe lustre

viii. Create a combined MGS/MDT file system on a block device. Run the 
      following command on the MDS node:

   [root@host~]# mkfs.lustre --fsname=<fsname> --mgs --mdt <block_device>

ix. Mount the file system created in the previous step. Run the following 
    command on the MDS node:

   [root@host~]# mount -t lustre <block_device> <mount_point>

x. Create the OST on the OSS node by runnning the following command:

   [root@host~]# mkfs.lustre --ost --fsname=<fsname> --mgsnode=<NID> <block device name>

xi. On Client node, follow steps (i)-(vii).

xii. Mount the Lustre file system on the client node by running the following command:
 
    [root@host~]# mount -t lustre <MGS node>:/<fsname> <mount_point>
	
NOTE: For more information on additional configuration options, please refer 
      User's Guide.



5. Support Documentation
================================================================================

The documentation for this release can be found inside the 
ChelsioUwire-x.xx.x.x/docs folder. 
It contains:

- README
- Release Notes
- User's Guide



6. Customer Support
================================================================================

Please contact Chelsio support at support@chelsio.com for any issues regarding
the product.








********************************************************************************
Copyright (C) 2016 Chelsio Communications. All Rights Reserved.

The information in this document is furnished for informational use only, is
subject to change without notice, and should not be construed as a commitment by
Chelsio Communications. Chelsio Communications assumes no responsibility or
liability for any errors or inaccuracies that may appear in this document or any
software that may be provided in association with this document. Except as
permitted by such license, no part of this document may be reproduced, stored in
a retrieval system,or transmitted in any form or by any means without the
express written consent of Chelsio Communications.
