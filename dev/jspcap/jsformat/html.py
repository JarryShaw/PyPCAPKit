#!/usr/bin/python3
# -*- coding: utf-8 -*-


import collections
import os
import textwrap


# Writer for JavaScript files
# Dump a JavaScript file for PCAP analyser


from .json import JSON


HEADER_START = '''\
// demo data
var data = {
'''

HEADER_END = """
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
"""


class JavaScript(JSON):

    _hsrt = HEADER_START
    _hend = HEADER_END
    _vctr = collections.defaultdict(int)    # value counter dict
