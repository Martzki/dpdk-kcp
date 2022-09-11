# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017-2018 Intel Corporation

if not is_linux
	build = false
	reason = 'only supported on linux'
endif
if has_libnuma == 1
	dpdk_conf.set10('RTE_LIBRTE_VHOST_NUMA', true)
endif
if (toolchain == 'gcc' and cc.version().version_compare('>=8.3.0'))
	cflags += '-DVHOST_GCC_UNROLL_PRAGMA'
elif (toolchain == 'clang' and cc.version().version_compare('>=3.7.0'))
	cflags += '-DVHOST_CLANG_UNROLL_PRAGMA'
elif (toolchain == 'icc' and cc.version().version_compare('>=16.0.0'))
	cflags += '-DVHOST_ICC_UNROLL_PRAGMA'
endif
#dpdk_conf.set('RTE_LIBRTE_VHOST_POSTCOPY',
#	      cc.has_header('linux/userfaultfd.h'))
allow_experimental_apis = true
cflags += '-fno-strict-aliasing'
sources = files('rte_ikcp.c', 'ikcp.c')
headers = files('rte_ikcp.h')
deps += ['ethdev', 'pci']
