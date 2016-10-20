#!/bin/bash
kdist=$1
libs_ofed=$2
lib_build=`pwd`/build/libs/ ;\
libs_dirl=${lib_build}/${kdist} ;\
all_libs=(libcxgb4_udp libcxgb4_sock libcxgb4_udp_dbg libcxgb4_sock_dbg libwdtoe libwdtoe_dbg) ;\
#echo $lib_build
if [ ${libs_ofed} -eq 1 ] ; then \
        libs_dirl=${libs_dirl}/ofed ;\
else \
        libs_dirl=${libs_dirl}/inbox ;\
fi ; \
#echo ${libs_dirl}
for lib in ${all_libs[*]} ; do \
        if [ ! -h ${lib_build}/${lib} ] ; then \
                unlink ${lib_build}/${lib} > unlink_temp.log 2>&1 ; \
                rm -rf unlink_temp.log ; \
        fi;\
done; \
for lib in ${all_libs[*]} ; do \
        if [ ! -h ${lib_build}/${lib} ] ; then \
                ln -s ${libs_dirl}/${lib} ${lib_build}; \
        fi;\
done ;

