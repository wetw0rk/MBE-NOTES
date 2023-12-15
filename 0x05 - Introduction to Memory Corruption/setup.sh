#!/bin/sh

set -e 

rootdir=intro_to_memory_corruption
mkdir $rootdir 2>/dev/null || true
mkdir -p $rootdir/are_you_using_tab_completion_yet/I_really_hope_so 2>/dev/null || true

nointernet() {
   echo no internet. If you don\'t want to get it working, download lense.pw/mbe/arg_input_echo.c on your host and copy it to booksrc/
   echo then re-run this with the argument nointernet
   rm booksrc/arg_input_echo.c 2>/dev/null || true
   exit 1
}
[[ $1 = nointernet ]] || wget lense.pw/mbe/arg_input_echo.c -O booksrc/arg_input_echo.c || nointernet

files=( overflow_example auth_overflow arg_input_echo auth_overflow2 game_of_chance )

for num in {0..4};
do
   filename=${files[$num]}
   mkdir $rootdir/$num-$filename/ 2>/dev/null || true
   echo compiling $filename
   cp booksrc/$filename.c $rootdir/$num-$filename/$filename.c
   gcc -fno-stack-protector -z execstack -m32 -g booksrc/$filename.c -o $rootdir/$num-$filename/$filename
done

[[ $1 = nointernet ]] || echo setting up config files
[[ $1 = nointernet ]] || wget lense.pw/mbe/gdbinit -O .gdbinit

echo done.
echo now cd to the directory $rootdir
