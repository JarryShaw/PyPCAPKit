// demo data
var data = {
	"Global Header" : {
		"magic_number" : "d4 c3 b2 a1",
		"version_major" : 2,
		"version_minor" : 4,
		"thiszone" : 0,
		"sigfigs" : 0,
		"snaplen" : 262144,
		"network" : "Ethernet"
	},
	"Frame 1" : {
		"frame_info" : {
			"ts_sec" : 1511106545,
			"ts_usec" : 471719,
			"incl_len" : 86,
			"orig_len" : 86
		},
		"time" : "2017-11-19T23:49:05Z",
		"number" : 1,
		"time_epoch" : "1511106545.471719 seconds",
		"len" : 86,
		"cap_len" : 86,
		"ethernet" : {
			"dst" : "40-33-1a-d1-85-1c",
			"src" : "a4-5e-60-d9-6b-97",
			"type" : "IPv6",
			"ipv6" : {
				"version" : "6",
				"tclass" : 96,
				"label" : 0,
				"len" : 32,
				"next" : "C",
				"limit" : 255,
				"src" : "fe80::a6:87f9:2793:16ee",
				"dst" : "fe80::1ccd:7c77:bac7:46b7",
				"icmpv6" : "87 00 0e aa 00 00 00 00 fe 80 00 00 00 00 00 00 1c cd 7c 77 ba c7 46 b7 01 01 a4 5e 60 d9 6b 97"
			}
		},
		"protocols" : "Ethernet:IPv6:ICMPv6"
	},
	"Frame 2" : {
		"frame_info" : {
			"ts_sec" : 1511106545,
			"ts_usec" : 578078,
			"incl_len" : 78,
			"orig_len" : 78
		},
		"time" : "2017-11-19T23:49:05Z",
		"number" : 2,
		"time_epoch" : "1511106545.578078 seconds",
		"len" : 78,
		"cap_len" : 78,
		"ethernet" : {
			"dst" : "a4-5e-60-d9-6b-97",
			"src" : "40-33-1a-d1-85-1c",
			"type" : "IPv6",
			"ipv6" : {
				"version" : "6",
				"tclass" : 96,
				"label" : 0,
				"len" : 24,
				"next" : "C",
				"limit" : 255,
				"src" : "fe80::1ccd:7c77:bac7:46b7",
				"dst" : "fe80::a6:87f9:2793:16ee",
				"icmpv6" : "88 00 3f 82 40 00 00 00 fe 80 00 00 00 00 00 00 1c cd 7c 77 ba c7 46 b7"
			}
		},
		"protocols" : "Ethernet:IPv6:ICMPv6"
	},
	"Frame 3" : {
		"frame_info" : {
			"ts_sec" : 1511106549,
			"ts_usec" : 777804,
			"incl_len" : 54,
			"orig_len" : 54
		},
		"time" : "2017-11-19T23:49:09Z",
		"number" : 3,
		"time_epoch" : "1511106549.777804 seconds",
		"len" : 54,
		"cap_len" : 54,
		"ethernet" : {
			"dst" : "a4-5e-60-d9-6b-97",
			"src" : "b8-f8-83-a5-f9-47",
			"type" : "IPv4",
			"ipv4" : {
				"version" : "4",
				"hdr_len" : 20,
				"dsfield" : {
					"dscp" : [ "Routine", "Normal Delay", "Normal Throughput", "Normal Relibility" ],
					"ecn" : "Not-ECT"
				},
				"len" : 40,
				"id" : 50484,
				"flags" : {
					"rb" : "00",
					"df" : true,
					"mf" : false
				},
				"frag_offset" : 0,
				"ttl" : 43,
				"proto" : "TCP",
				"checksum" : "7a 86",
				"src" : "123.129.210.135",
				"dst" : "192.168.1.100",
				"tcp" : {
					"srcport" : 80,
					"dstport" : 55232,
					"seq" : 3584012628,
					"ack" : 2793054463,
					"hdr_len" : 20,
					"flags" : {
						"res" : "00 00 00",
						"ns" : false,
						"cwr" : false,
						"ecn" : false,
						"urg" : false,
						"ack" : true,
						"push" : false,
						"reset" : false,
						"syn" : false,
						"fin" : true
					},
					"window_size" : 31920,
					"checksum" : "7c 8e",
					"urgent_pointer" : 0,
					"raw" : null
				}
			}
		},
		"protocols" : "Ethernet:IPv4:TCP:"
	},
	"Frame 4" : {
		"frame_info" : {
			"ts_sec" : 1511106549,
			"ts_usec" : 777868,
			"incl_len" : 54,
			"orig_len" : 54
		},
		"time" : "2017-11-19T23:49:09Z",
		"number" : 4,
		"time_epoch" : "1511106549.777868 seconds",
		"len" : 54,
		"cap_len" : 54,
		"ethernet" : {
			"dst" : "b8-f8-83-a5-f9-47",
			"src" : "a4-5e-60-d9-6b-97",
			"type" : "IPv4",
			"ipv4" : {
				"version" : "4",
				"hdr_len" : 20,
				"dsfield" : {
					"dscp" : [ "Routine", "Normal Delay", "Normal Throughput", "Normal Relibility" ],
					"ecn" : "Not-ECT"
				},
				"len" : 40,
				"id" : 0,
				"flags" : {
					"rb" : "00",
					"df" : true,
					"mf" : false
				},
				"frag_offset" : 0,
				"ttl" : 64,
				"proto" : "TCP",
				"checksum" : "2a bb",
				"src" : "192.168.1.100",
				"dst" : "123.129.210.135",
				"tcp" : {
					"srcport" : 55232,
					"dstport" : 80,
					"seq" : 2793054463,
					"ack" : 3584012629,
					"hdr_len" : 20,
					"flags" : {
						"res" : "00 00 00",
						"ns" : false,
						"cwr" : false,
						"ecn" : false,
						"urg" : false,
						"ack" : true,
						"push" : false,
						"reset" : false,
						"syn" : false,
						"fin" : false
					},
					"window_size" : 65535,
					"checksum" : "f9 3e",
					"urgent_pointer" : 0,
					"raw" : null
				}
			}
		},
		"protocols" : "Ethernet:IPv4:TCP:"
	},
	"Frame 5" : {
		"frame_info" : {
			"ts_sec" : 1511106549,
			"ts_usec" : 913720,
			"incl_len" : 54,
			"orig_len" : 54
		},
		"time" : "2017-11-19T23:49:09Z",
		"number" : 5,
		"time_epoch" : "1511106549.913720 seconds",
		"len" : 54,
		"cap_len" : 54,
		"ethernet" : {
			"dst" : "b8-f8-83-a5-f9-47",
			"src" : "a4-5e-60-d9-6b-97",
			"type" : "IPv4",
			"ipv4" : {
				"version" : "4",
				"hdr_len" : 20,
				"dsfield" : {
					"dscp" : [ "Routine", "Normal Delay", "Normal Throughput", "Normal Relibility" ],
					"ecn" : "Not-ECT"
				},
				"len" : 40,
				"id" : 0,
				"flags" : {
					"rb" : "00",
					"df" : true,
					"mf" : false
				},
				"frag_offset" : 0,
				"ttl" : 64,
				"proto" : "TCP",
				"checksum" : "2a bb",
				"src" : "192.168.1.100",
				"dst" : "123.129.210.135",
				"tcp" : {
					"srcport" : 55216,
					"dstport" : 80,
					"seq" : 768904481,
					"ack" : 1835365486,
					"hdr_len" : 20,
					"flags" : {
						"res" : "00 00 00",
						"ns" : false,
						"cwr" : false,
						"ecn" : false,
						"urg" : false,
						"ack" : true,
						"push" : false,
						"reset" : false,
						"syn" : false,
						"fin" : true
					},
					"window_size" : 65535,
					"checksum" : "2a f4",
					"urgent_pointer" : 0,
					"raw" : null
				}
			}
		},
		"protocols" : "Ethernet:IPv4:TCP:"
	},
	"Frame 6" : {
		"frame_info" : {
			"ts_sec" : 1511106551,
			"ts_usec" : 66835,
			"incl_len" : 159,
			"orig_len" : 159
		},
		"time" : "2017-11-19T23:49:11Z",
		"number" : 6,
		"time_epoch" : "1511106551.66835 seconds",
		"len" : 159,
		"cap_len" : 159,
		"ethernet" : {
			"dst" : "ff-ff-ff-ff-ff-ff",
			"src" : "b8-f8-83-a5-f9-47",
			"type" : "IPv4",
			"ipv4" : {
				"version" : "4",
				"hdr_len" : 20,
				"dsfield" : {
					"dscp" : [ "Routine", "Normal Delay", "Normal Throughput", "Normal Relibility" ],
					"ecn" : "Not-ECT"
				},
				"len" : 145,
				"id" : 0,
				"flags" : {
					"rb" : "00",
					"df" : true,
					"mf" : false
				},
				"frag_offset" : 0,
				"ttl" : 64,
				"proto" : "UDP",
				"checksum" : "78 b3",
				"src" : "192.168.1.1",
				"dst" : "255.255.255.255",
				"udp" : {
					"srcport" : 37444,
					"dstport" : 5001,
					"len" : 125,
					"checksum" : "63 b1",
					"raw" : "01 01 0e 00 e1 2b 83 c7 f9 8b 00 67 00 00 00 06 00 0a 54 4c 2d 57 44 52 36 33 30 30 00 0b 00 03 36 2e 30 00 07 00 01 01 00 05 00 11 42 38 2d 46 38 2d 38 33 2d 41 35 2d 46 39 2d 34 37 00 08 00 0b 31 39 32 2e 31 36 38 2e 31 2e 31 00 09 00 0a 74 70 6c 6f 67 69 6e 2e 63 6e 00 0a 00 0e 54 4c 2d 57 44 52 36 33 30 30 20 36 2e 30 00 0c 00 05 31 2e 37 2e 34"
				}
			}
		},
		"protocols" : "Ethernet:IPv4:UDP:"
	}
}

// define the item component
Vue.component('item', {
  template: '#item-template',
  props: {
    model: Object
  },
  data: function () {
    return {
      open: false
    }
  },
  computed: {
    isFolder: function () {
      return this.model.children &&
        this.model.children.length
    }
  },
  methods: {
    toggle: function () {
      if (this.isFolder) {
        this.open = !this.open
      }
    },
    changeType: function () {
      if (!this.isFolder) {
        Vue.set(this.model, 'children', [])
        this.addChild()
        this.open = true
      }
    },
    addChild: function () {
      this.model.children.push({
        name: 'new stuff'
      })
    }
  }
})

// boot up the demo
var demo = new Vue({
  el: '#demo',
  data: {
    treeData: data
  }
})
