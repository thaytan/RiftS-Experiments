# RiftS-Experiments
This is a repository of experimental code for understanding the Oculus Rift S headset.

It is currently inactive - the experiments here were used to write a driver for the Rift S which was merged into OpenHMD in June 2020.

The repo contains a dump tool that logs a bunch of information from a
connected headset, and a parse utility that scans the dump logs for tracking
reports and reads out the contained information.

Enough of the USB protocol is now understood - and documented in this code - to permit writing
a full positional tracking implementation at some point, building on the 3DOF driver that already works.

## Collecting logs

I had instructions here on how to collect some logs of the headset and controller tracking
reports, to help with reverse engineering the packet stuctures. I've collected enough logs
for now and, while there are still some unknown fields / values, the decoding of the tracking
reports is fairly complete.

Thank you to the people that emailed me logs from their headsets!

## Problems?

Running the tool requires that your user account has access to the Rift S USB devices. The
OpenHMD wiki has some instructions on setting that up.

[OpenHMD udev rules guide](https://github.com/OpenHMD/OpenHMD/wiki/Udev-rules-list)

If you have any other problems following these instructions or getting it to see your headset, please file an issue.

## Building

The code has been tested on Linux. It might work on Windows too.

To build it, you need the [meson build](https://mesonbuild.com/) tool.

Run:
 * meson build/
 * ninja -C build
 * ./build/dump-rift-s

## Running

You can run `dump-rift-s --help` to get some basic information about some command line options it supports.

## Report parsing

The dump tool has some support for speculatively parsing the HMD and Controller reports
and printing the contents. You can run with:

`dump-rift-s -h -p` to print parsed HMD info with IMU readings, or
`dump-rift-s -c -p` to print parsed Controller reports. If you use the `-s` parameter,
then the outputs will be printed continuously to a single line, which is good for looking for
patterns in the output.

There is a parse-log utility that reads the output from the raw dump and can collate and print
the current state of each hand controller based on the partial updates in the tracking reports:

`./build/dump-rift-s | ./build/parse-log -s`

## License
Thiis code is released under the permissive Boost Software License (see LICENSE for more information), to make it compatible with eventual inclusion in OpenHMD

