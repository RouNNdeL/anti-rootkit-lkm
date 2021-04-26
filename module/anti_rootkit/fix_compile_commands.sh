#!/usr/bin/env bash

remove='-fnocoserve-stack -fno-allow-store-data-races -mindirect-branch-register -fconserve-stack -mindirect-branch=thunk-extern -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -mrecord-mcount -fplugin-arg-structleak_plugin-byref-all'

for i in $remove; do 
    sed -i "/$i/d" ./compile_commands.json
done
