project('OpenHMD-RiftSPlayground', 'c', default_options: 'c_std=c99', version : '0.1')

dep_thread = dependency('threads')
dep_usb = dependency('libusb-1.0')
dep_libm = meson.get_compiler('c').find_library('m', required: false)

hidapi = 'hidapi'
_hidapi = get_option('hidapi')
if host_machine.system() == 'linux'
	if _hidapi == 'hidraw'
		hidapi = 'hidapi-hidraw'
	else
		hidapi = 'hidapi-libusb'
	endif
else
	if _hidapi != 'auto'
		warning('hidapi option ignored on non-Linux systems')
	endif
endif

dep_hidapi = dependency(hidapi, required : false)

main_sources = [
	'test.c',
]
main_deps = [
  dep_hidapi,
	dep_thread,
	dep_usb
]
executable('main', main_sources, dependencies : main_deps)
