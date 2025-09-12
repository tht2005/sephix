#!/usr/bin/env bash
cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON $@
make -C build && sudo make -C build install
