#!/bin/bash
bin_files="t580_cr_spider_variable_2133_vpd.bin t580_cr_variable_2133_vpd.bin t580_cr_qsa_variable_2133_vpd.bin t580_lp_cr_spider_variable_2133_vpd.bin t580_lp_cr_variable_2133_vpd.bin t580_lp_cr_qsa_variable_2133_vpd.bin t580_lp_so_spider_variable_2133_vpd.bin t580_lp_so_variable_vpd.bin t580_lp_so_qsa_variable_vpd.bin"
BINDIR="/lib/firmware/cxgb4"
exefiles="chelsio_adapter_config t5seeprom"
EXEDIR="/sbin"

if [[ ! -d $BINDIR ]] ; then
    mkdir -p $BINDIR
fi

echo -n "Copying VPD binaries to ${BINDIR}   :  "
# Copies .bin files to BINDIR
for bins in ${bin_files} ; do
    /bin/cp vpds/${bins} ${BINDIR}
done
echo "DONE"

echo -n "Copying scripts to ${EXEDIR}   :  "
#Copies exefiles to /sbin
for exes in ${exefiles} ; do
    /bin/cp bin/${exes} ${EXEDIR}
done
echo "DONE"


