# RiftS-Experiments
This is a repository of experimental code for understanding the Oculus Rift S headset.

At the moment, it contains a dump tool that logs a bunch of information from a
connected headset.

## Collecting logs

I am trying to collect logs from several headsets to see which parts of the data flow
change and which stay the same. If you want to contribute a log from your headset,
then build the tool and do this:

 1. Build the `dump-rift-s` tool. See the *Building* section below
 1. **Take the battery out** of your *right* controller
 1. Run the the `dump-rift-s` tool, redirecting the output to a log file.
    * `./build/dump-rift-s | tee rift-s-log.txt`
 1. Initially, the tool should print 'FOUND Rift S', dump some firmware blobs, and then start
    logging HMD and State packets.
 1. After a few seconds, the Rift S should become active and (depending your
    desktop environment and GPU) might show up as a second monitor. The output from
    the tool should also change to include Controller output like:
    * `Controller: 67 bf 2c 4f f2 c1 bb 13 a5 20 00 00 00 00 91 6b | g./....s. .....k`...
  1. Let that run for a few seconds to collect left controller packets.
  1. **Remove the battery** from your *left* controller
  1. **Insert the battery** into your *right* controller
  1. Let the tool run for 5-10 seconds more, then hit ctrl-C
  1. gzip the resulting log, and email it to <mailto:thaytan@noraisin.net>. If you could mention
     which git commit you used, that would be helpful - as I expect this tool to evolve quickly.

Note: The log files will contain device addresses and IDs that uniquely identify your headset and controllers.
I don't think that's a problem in general, but nevertheless I won't be publishing any portion of your log
without stripping that information.

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

## License
Thiis code is released under the permissive Boost Software License (see LICENSE for more information), to make it compatible with eventual inclusion in OpenHMD

