#!/bin/bash
bin_files="t580_cr_spider_variable_2133_vpd.bin t580_cr_variable_2133_vpd.bin t580_cr_qsa_variable_2133_vpd.bin t580_lp_cr_spider_variable_2133_vpd.bin t580_lp_cr_variable_2133_vpd.bin t580_lp_cr_qsa_variable_2133_vpd.bin t580_lp_so_spider_variable_2133_vpd.bin t580_lp_so_variable_vpd.bin t580_lp_so_qsa_variable_vpd.bin"
BINDIR="/lib/firmware/cxgb4"
exefiles="chelsio_adapter_config t5seeprom"
EXEDIR="/sbin"

#echo "Removed following VPD binaries from ${BINDIR}"
# Copies .bin files to BINDIR
for bins in ${bin_files} ; do
     if [ -f ${BINDIR}/${bins} ] ; then
         /bin/rm -vf ${BINDIR}/${bins} 
     fi
done
#echo ""

#echo "Removed following scripts from ${EXEDIR} "
#Copies exefiles to /sbin
for exes in ${exefiles} ; do
    if [ -f ${EXEDIR}/${exes} ] ; then
        /bin/rm -vf ${EXEDIR}/${exes} 
    fi
done


