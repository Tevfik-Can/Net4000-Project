ebpf probe file is to be used alongside the runner1,
it is a very basic program that tracks all kernel events unconditionally

ebpf net file is to be ran with the runner2,
this focuses specifically on the kernel tcp events

the simple test file runs and uses the code from the net file
