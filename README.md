# Gopcap - a packet capture tool

This is a training oriented project to discover the features of the package
[github.com/google/gopacket](https://github.com/google/gopacket), developed to
handle packet at different layers.

### Prerequisites
To use it libpcap devel headers must be installed on the system. On Fedora run
the following command:

```
$ sudo dnf install libpcap libcpap-devel
```

### Build
To build and install:
```
$ make
$ sudo make install
```

### Usage
gopcap must be used with root privileges in order to access the interface.
```
$ sudo gopcap
```

To display the help
```
$ gopcap -h
Usage of gopcap:
  -i string
    	Default interface (default "wlp4s0")
  -o string
    	Output mode (dump, short, tcpstat, udpstat) (default "short")
  -p	Set promiscuous mode
  -s int
    	Snapshot length to read for each packet (default 65536)
```

To run the capture on a different interface
```
$ sudo gopcap -i ens1
```

To print an hex dump of the packets:
```
$ sudo gopcap -o dump
```

To print live tcp stats:
```
$ sudo gopcap -o tcpstat
```

To print live udp stats:
```
$ sudo gopcap -o udpstat
```

### TODO
The program still needs a lot of development. Some possible features are:
* Implement tests
* Define different capture behaviors (ie: dump only HTTP/HTTPS traffic)
* If needed refactor with a CLI like cobra
* Refine the output layout of dumps

###
Authors:
- Gianni Salinetti <gbsalinetti@extraordy.com>  

