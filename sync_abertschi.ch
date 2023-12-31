#!/bin/bash
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
sync_dir="$script_dir"

host=armcca@192.33.93.245
target=/home/armcca/encrypted-cuda

set -x

echo $sync_dir
echo $target
function sync {
    rsync -v -a $sync_dir $host:$target --checksum --ignore-times
}

sync
# inotifywait -r $script_dir;
while true; do
    sync
    sleep 1
done
