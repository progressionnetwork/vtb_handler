import lxml  # pip install lxml
import lxml.etree
import xmlschema  # pip install xmlschema
import xml.etree.ElementTree as elementTree
from pip._internal.utils import logging
import xml.etree.cElementTree as ET
import json


class Target(object):
    def __init__(self):
        self.start_tag = None
        self.builder = ET.TreeBuilder()
        self.tree = None
    def start(self, tag, attrib):
        if self.start_tag is None:
            self.start_tag = tag
        return self.builder.start(tag, attrib)
    def end(self, tag, attrib=None):
        ret = self.builder.end(tag, attrib)
        if self.start_tag == tag:
            self.tree = self.builder.close()
            return self.tree
        return ret
    def data(self, data):
        return self.builder.data(data)
    def close(self):
        if self.tree is None:
            self.tree = self.builder.close()
        return self.tree

