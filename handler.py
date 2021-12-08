from __future__ import print_function
import datetime
import logging
import json
import os, sys
import re
import struct
import tarfile
import time
import zipfile, zlib
import filetype  # pip install filetype
import base64
import random as r
import binascii
import pyunpack  # pip install patool pyunpack
import lxml  # pip install lxml
import lxml.etree
import xmlschema  # pip install xmlschema
import xml.etree.ElementTree as elementTree
import yara  # pip install yara-python
from pprint import pprint
from yara_scanner import YaraScanner  # pip install yara-scanner
from pip._internal.utils import logging
from zipfile import ZipFile
import xml.etree.cElementTree as ET
import json
import xml.dom.minidom
from pathlib import Path
from xml.sax.saxutils import quoteattr as xml_quoteattr
import networkx as nx  # pip install networkx
import random
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seedir as sd # pip install seedir

# Self modules
import extension_db
import vtscan
from xmlprocessor import Target


class DetectDocument(object):
    """
    DetectDocument is an abstraction of a JSON, XML or neither file type.
    """

    def __init__(self, input_file=None, *args, **kwargs):
        self._is_json_file = False
        self._is_xml_file = False
        self._parsed_file = None
        if input_file is not None:
            self.parse_file(input_file)

    @property
    def is_json_file(self):
        return self._is_json_file

    @property
    def is_xml_file(self):
        return self._is_xml_file

    def _parse_json_file(self, input_file):
        """
        Given a text file, returns a JSON object or None
        """
        with open(input_file, 'rb') as in_file:
            return json.load(in_file)

    def _parse_xml_file(self, input_file):
        """
        Given a text file, returns an XML element or None
        """
        with open(input_file, 'rb') as in_file:
            return ET.parse(in_file)

    def parse_file(self, input_file):
        """
        Checks if input report file is of type json or xml
        returns a json object or an xml element or None
        """
        try:
            self._parsed_file = self._parse_xml_file(input_file)
            self._is_xml_file = True
        except ET.ParseError:
            try:
                self._parsed_file = self._parse_json_file(input_file)
                self._is_json_file = True
            except ValueError:  # or in Python3 the specific error json.decoder.JSONDecodeError
                pass


def hierarchy_pos(G, root=None, width=1., vert_gap=0.2, vert_loc=0, xcenter=0.5):
    '''
    From Joel's answer at https://stackoverflow.com/a/29597209/2966723.
    Licensed under Creative Commons Attribution-Share Alike

    If the graph is a tree this will return the positions to plot this in a
    hierarchical layout.

    G: the graph (must be a tree)

    root: the root node of current branch
    - if the tree is directed and this is not given,
      the root will be found and used
    - if the tree is directed and this is given, then
      the positions will be just for the descendants of this node.
    - if the tree is undirected and not given,
      then a random choice will be used.

    width: horizontal space allocated for this branch - avoids overlap with other branches

    vert_gap: gap between levels of hierarchy

    vert_loc: vertical location of root

    xcenter: horizontal location of root
    '''
    if not nx.is_tree(G):
        raise TypeError('cannot use hierarchy_pos on a graph that is not a tree')

    if root is None:
        if isinstance(G, nx.DiGraph):
            root = next(iter(nx.topological_sort(G)))  # allows back compatibility with nx version 1.11
        else:
            root = random.choice(list(G.nodes))

    def _hierarchy_pos(G, root, width=1., vert_gap=0.2, vert_loc=0, xcenter=0.5, pos=None, parent=None):
        '''
        see hierarchy_pos docstring for most arguments

        pos: a dict saying where all nodes go if they have been assigned
        parent: parent of this branch. - only affects it if non-directed

        '''

        if pos is None:
            pos = {root: (xcenter, vert_loc)}
        else:
            pos[root] = (xcenter, vert_loc)
        children = list(G.neighbors(root))
        if not isinstance(G, nx.DiGraph) and parent is not None:
            children.remove(parent)
        if len(children) != 0:
            dx = width / len(children)
            nextx = xcenter - width / 2 - dx / 2
            for child in children:
                nextx += dx
                pos = _hierarchy_pos(G, child, width=dx, vert_gap=vert_gap,
                                     vert_loc=vert_loc - vert_gap, xcenter=nextx,
                                     pos=pos, parent=root)
        return pos

    return _hierarchy_pos(G, root, width, vert_gap, vert_loc, xcenter)


class Handler:
    """
        Handler is an abstraction of a Object handling functions.
    """

    def __init__(self, filename, blob, taskid, outputfilename):
        self.logger = logging.getLogger('fileHandler')
        self.filename = filename
        self.outputfilename = outputfilename
        self.blob = blob
        self.taskid = taskid

    def __exit__(self, *args):
        self.thefile.close()

    def get_filename(self):
        filename = os.path.basename(self.filename)
        print(f"File: {filename}")
        return filename

    def get_size(self):
        size = os.path.getsize(self.filename)  # / 1024
        print(f"Size: {round(size)} bytes")
        return size

    def get_ext(self):
        filename, file_extension = os.path.splitext(self.filename)
        file_extension = file_extension.replace('.', '')
        return file_extension

    def check_ext(self):
        file_extension = self.get_ext()
        ret = extension_db.ExtStatus
        return ret

    def check_json(self):
        try:
            json_object = json.loads(self.blob)
            print("Blob is valid json")
            return True
        except ValueError as e:
            print("Blob is invalid json")
            return False
        return False

    def check_xml(self):
        with open(self.filename, 'rb') as in_file:
            try:
                result = elementTree.parse(in_file)
                if result:
                    print("Blob is valid xml")
                    return True
                else:
                    print("Blob is invalid xml")
                    return False
            except elementTree.ParseError:
                print("Blob is invalid xml")
                return False
        return None

    def enum_xml_tags(self):
        xmlTree = elementTree.parse(self.filename)
        elemList = []

        for elem in xmlTree.iter():
            elemList.append(elem.tag)
        elemList = list(set(elemList))

        return elemList

    def combine_data_to_xml(self, dir_to_process):
        combined_xml = '<structure>\n' + process_dir(dir_to_process) + '\n</structure>'

        blob_file = open(self.outputfilename, 'w')
        blob_file.write(combined_xml)
        blob_file.close()
        print("Xml generated: ", self.outputfilename)

        return True

    def enum_xml_data(self, processed_dir):
        ext = 'unknown'
        output_dir = ''
        taskid = self.taskid
        shortname = Path(self.filename).stem
        path = processed_dir + '/' + shortname + '_' + taskid + '/'
        Path(path).mkdir(parents=True, exist_ok=True)
        print("Tmp dir created: ", path)

        tree = ET.parse(self.filename)
        root = tree.getroot()

        nested = './'
        nested_level = len(root.findall(nested))
        for i in range(nested_level):
            try:
                for data in root.findall(nested):
                    # Avoid saving of data less then 1 kb
                    if len(data.text) < 1024:
                        continue

                    content = (data.text[:15] + '..') if len(data.text) > 15 else data.text
                    print(content)
                    print("level:", nested)
                    # print("data.attrib:", data.attrib)
                    # print("data.tag:", data.tag)

                    attribs = str(data.attrib)
                    print(attribs)
                    if 'json' in attribs:
                        ext = 'json'
                    elif 'xml' in attribs:
                        ext = 'xml'
                    else:
                        ext = 'unknown'

                    guessed_filename = data.tag
                    # print("guessed_filename: ", guessed_filename)

                    level = guessed_filename + str(i) + '/'
                    path_tmp = path + level
                    Path(path_tmp).mkdir(parents=True, exist_ok=True)
                    # print(path_tmp)

                    if guessed_filename:
                        name = path_tmp + guessed_filename + str(r.randrange(77, 7777)) + '.' + ext
                    else:
                        name = path_tmp + 'blob_' + str(r.randrange(77, 7777)) + '.' + ext

                    # Decode base64 buffer
                    decoded = base64.urlsafe_b64decode(data.text)
                    # print('base64 decoded')

                    blob_file = open(name, 'wb')
                    blob_file.write(decoded)
                    blob_file.close()
                    print("Blob extracted: ", name)

                    # Extract mime type of file
                    kind = filetype.guess(name)
                    if kind is not None:
                        if 'x-7z-compressed' in kind.mime:
                            rename_file(name, '7z')
                        if 'x-rar-compressed' in kind.mime:
                            rename_file(name, 'rar')
                        if 'zip' in kind.mime:
                            rename_file(name, 'zip')
                        if 'x-tar' in kind.mime:
                            rename_file(name, 'x-tar')

                    output_dir = path
            except:  # KeyError
                print("ignoring..")

            nested += '/'
            print(f"Extracting from XML {self.filename} done..")
        return output_dir

    def process_xml_decompilation(self):
        parser = None

        with open(self.filename, 'rb') as f:
            lines = f.readlines()

        for line in lines:
            if parser is None:
                target = Target()
                parser = ET.XMLParser(target=target)
            parser.feed(line)
            if target.tree:
                # do_stuff_with(target.tree)
                parser = None

    def process_zip_archive(self):
        print("Testing zip file: %s" % self.filename)

        the_zip_file = zipfile.ZipFile(self.filename)
        ret = the_zip_file.testzip()

        if ret is not None:
            print("First bad file in zip: %s" % ret)
            sys.exit(1)
        else:
            print("Zip file is good.")

    def check_for_PE_file(self):
        if len(self.blob) > 97:
            raw_string_content = self.blob
            string_content = raw_string_content

            if raw_string_content[0:4] == '4d5a':
                # sometimes the strings is not correctl dumped, it needs more testing
                if not len(raw_string_content) % 2 == 0:
                    raw_string_content += '0'
                string_content = binascii.unhexlify(raw_string_content)

            if string_content[0:2] == 'MZ':
                offset = struct.unpack('<I', string_content[0x3c:0x3c + 4])[0]
                if len(string_content) > offset + 2 and string_content[offset:offset + 2] == 'PE':
                    today = datetime.today()
                    filename = "%d%d%d%d%d%d.bin" % (
                        today.year, today.month, today.day, today.hour, today.minute, today.second)
                    logging.info("Write possible PE file: %s" % filename)
                    with open(filename, 'w') as f:
                        f.write(string_content)

    def _generate_filename(self, name, ext):
        today = datetime.today()
        _dumped_file = f"{name}_%d%d%d%d%d%d.{ext}" % (
            today.year, today.month, today.day, today.hour, today.minute, today.second)
        logging.info("Created dumped file: %s" % _dumped_file)


def filename_in_archive(filename, archive_file):
    filename = os.path.normcase(filename)
    return any(
        filename == os.path.normcase(os.path.basename(tfn))
        for tfn in archive_file.getnames())


def process_dir(path):
    result = '<dir=%s>\n' % xml_quoteattr(os.path.basename(path))
    for item in os.listdir(path):
        itempath = os.path.join(path, item)
        if os.path.isdir(itempath):
            result += '\n'.join('  ' + line for line in process_dir(os.path.join(path, item)).split('\n'))
        elif os.path.isfile(itempath):
            with open(itempath, 'r', encoding="utf8", errors="ignore") as f:
                blob = f.read()
                blob = base64.urlsafe_b64encode(bytes(blob, "utf-8")).decode('UTF-8')
            result += ' <file=' + xml_quoteattr(item) + '>' + blob + '</file>\n'
    result += '</dir>\n'
    return result


def brute_dict(dict, str):
    for key in dict.values():
        if key.start_with(str):
            return True
    return False


def process_tar_archive(filename):
    tar = tarfile.open(filename)
    for tarinfo in tar:
        print(tarinfo.name, "is", tarinfo.size, "bytes in size and is ", end="")
        if tarinfo.isreg():
            print("a regular file.")
        elif tarinfo.isdir():
            print("a directory.")
        else:
            print("something else.")
    tar.extractall()
    tar.close()


def is_zip_file(filename):
    is_zip = zipfile.is_zipfile(filename)
    if is_zip:
        print("Zip file is good.")
        return True
    else:
        print("File is not zip.")
        return True


def is_tar_file(filename):
    is_tar = tarfile.is_tarfile(filename)
    if is_tar:
        print("Tar file is good.")
        return True
    else:
        print("File is not tar.")
        return True


def check_header(filename):
    # https://pypi.org/project/filetype/
    kind = filetype.guess(filename)
    if kind is None:
        print('Cannot guess file type!')
        return None

    print(f'Heur ext: {kind.extension}, Heur MIME type: {kind.mime}')
    return kind.mime


def check_arch(filename):
    magic_dict = {
        b"\x1f\x8b\x08": "gz",
        b"\x42\x5a\x68": "bz2",
        b"\x50\x4b\x03\x04": "zip"
    }

    max_len = max(len(x) for x in magic_dict)
    with open(filename, "rb") as f:
        file_start = f.read(max_len)
    for magic, filetype in magic_dict.items():
        if file_start.startswith(magic):
            return filetype
    return False


def check_base64_str(blob):
    std_base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    base64chars = []
    for c in std_base64chars:
        base64chars.append(c)
    for x in blob:
        if x not in base64chars:
            print("Not base64 str")
            return False
    print("base64 str")
    return True


def check_base64(blob):
    try:
        try:
            result = base64.b64decode(blob, validate=True)
            is_base64 = re.search("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$", result)
            if not is_base64:
                print("Blob is invalid base64")
                return False
            else:
                print("Blob is valid base64")
                return True
        except binascii.Error:
            print("Blob is invalid base64")
            return False
    except binascii.Error:
        print("Blob is invalid base64")
        return False
    return False


def rename_file(filename, new_ext):
    if filename.endswith('.unknown'):
        base = os.path.splitext(filename)[0]
        new_filename = base + '.' + new_ext
        print("# File:", filename, "renamed to:", new_filename)
        os.rename(filename, new_filename)
        return new_filename
    else:
        return filename


def unpack_archive_data(filename, dest_dir):
    zip_file = zipfile.ZipFile(filename)
    zip_list = zip_file.namelist()  # Get all the files in the compressed package
    for f in zip_list:
        zip_file.extract(f, dest_dir)  # Unzip files to the specified directory in a loop

    zip_file.close()


n = 0


def process_decompiled_from_xml(path, taskid):
    f = []
    global n

    # Build all files list to process
    for (root, _, filenames) in os.walk(path):
        for filename in filenames:
            print("* filenames:", filename)
            f.append(os.path.join(root, filename))

    # Process enumerated files in list
    for filename in f:
        print('***' * 30)

        filename = filename.replace('\\', '/').lower()
        print("* Processed file:", filename)

        # read file to buffer
        try:
            with open(filename, 'tr', encoding="utf8") as f:  # try open file in text mode
                blob = f.read()
                f.close()
        except:  # if fail then file is non-text (binary)
            with open(filename, 'rb') as f:
                blob = f.read()
                f.close()

        # Create handler class hinstance
        handler = Handler(filename, blob, taskid, '')

        # detect mime header
        mime = check_header(filename)

        # execute heuristics checker
        if handler.check_xml():  # TODO or 'application/xml' in mime
            rename_file(filename, 'xml')
            # create nested dir
            shortname = Path(filename).stem
            processed_dir = path + shortname + '_xml_' + str(n) + '/'
            Path(processed_dir).mkdir(parents=True, exist_ok=True)
            print("* Processed dir:", processed_dir)
            output_dir = handler.enum_xml_data(processed_dir)
            break

        elif handler.check_json():  # TODO JSON parser
            print(f"Valid JSON found!")
            rename_file(filename, 'json')

        elif 'x-7z-compressed' in mime:
            filename = rename_file(filename, '7z')
            if is_zip_file(filename):
                # create nested dir
                shortname = Path(filename).stem
                processed_dir = path + shortname + '_7z_' + str(n) + '/'
                Path(processed_dir).mkdir(parents=True, exist_ok=True)
                print("* Processed dir:", processed_dir)
                unpack_archive_data(filename, processed_dir)
                os.remove(filename)
                print(filename, 'removed!!')

        elif 'x-rar-compressed' in mime:
            print(f"RAR found!") # TODO: Implement rar support
            # create nested dir
            shortname = Path(filename).stem
            processed_dir = path + shortname + '_rar_' +  str(n) + '/'
            Path(processed_dir).mkdir(parents=True, exist_ok=True)
            print("* Processed dir:", processed_dir)
            filename = rename_file(filename, 'rar')
            #pyunpack.Archive(filename).extractall(processed_dir)
            #os.remove(filename)
            #print(filename, 'removed!!')
            # to process rar decompress we need Windows decompressor bin

        elif 'zip' in mime:
            filename = rename_file(filename, 'zip')
            if is_zip_file(filename):
                # create nested dir
                shortname = Path(filename).stem
                processed_dir = path + shortname + '_zip_' +  str(n) + '/'
                Path(processed_dir).mkdir(parents=True, exist_ok=True)
                print("* Processed dir:", processed_dir)
                print(f"ZIP found!")
                unpack_archive_data(filename, processed_dir)
                os.remove(filename)
                print(filename, 'removed!!')

        elif 'x-tar' in mime:
            filename = rename_file(filename, 'tar')
            if is_tar_file(filename):
                # create nested dir
                shortname = Path(filename).stem
                processed_dir = path + shortname + str(n) + '/'
                Path(processed_dir).mkdir(parents=True, exist_ok=True)
                print("* Processed dir:", processed_dir)
                process_tar_archive(filename)
                os.remove(filename)
                print(filename, 'removed!!')

        elif "rtf" in mime:
            filename = rename_file(filename, 'rtf')
            print(f"RTF found! Need additional check on AV engine!")

        elif 'x-msdownload' in mime:
            filename = rename_file(filename, 'exe')
            print(f"EXE found! Need additional check on AV engine!")

        elif 'jpeg' in mime or 'jpg' in mime:
            filename = rename_file(filename, 'jpg')

        elif 'png' in mime:
            filename = rename_file(filename, 'png')

        elif 'gif' in mime:
            filename = rename_file(filename, 'gif')

        elif 'bmp' in mime:
            filename = rename_file(filename, 'bmp')

        elif 'mpeg' in mime:
            filename = rename_file(filename, 'mp3')

        elif 'x-wav' in mime:
            filename = rename_file(filename, 'wav')

        elif 'pdf' in mime:
            filename = rename_file(filename, 'pdf')
            print(f"PDF found! Need additional check on AV engine!")

        elif 'tgz' in mime or 'gzip' in mime or 'gz' in mime:
            print(f"GZIP found!")
            filename = rename_file(filename, 'gzip')
            # implement GZIP processor

        n += 1


def visualize_fs_struct(process_dir, result):
    tree = sd.seedir(process_dir, printout=False, style='emoji')

    with open('tree.txt', 'w', encoding='utf-8') as file:
        file.write(tree)
        file.close()

    # G = nx.Graph()
    # i = 0
    # for (path, dirs, files) in os.walk(process_dir):
    #     bname = os.path.split(path)
    #     G.add_node(bname)
    #     for f in files:
    #         G.add_node(bname)
    #         G.add_edge(bname, f)
    #         #G.add_edge(i, bname)
    #         i += 1
    # f = plt.figure(1, figsize=(40, 40), dpi=100)
    # nx.draw(G,
    #         node_color='lightgreen',
    #         width=15,
    #         node_size=120,
    #         font_size=12,
    #         with_labels=True,
    #         arrows=True,
    #         node_shape="s",
    #         alpha=0.5,
    #         linewidths=9)
    # f.savefig(result)


def check_for_RTL_exploit(filename):
    for c in filename:
        if 0x600 <= c <= 0x6ff:
            print('Text contains RTL character')
            return True
    return False


def check_yara(filename):
    hdict = {}
    scanner = YaraScanner(signature_dir='yararules')
    scanner.load_rules()

    if scanner.scan(filename):
        # pprint(scanner.scan_results)
        malware_name = scanner.scan_results
        print(malware_name)

        if malware_name:
            return True
    return False


def scan_on_virustotal(filename):
    vt = vtscan.vtAPI()
    md5 = vtscan.checkMD5(filename)
    result = vtscan.parse(vt.getReport(md5), md5, True)

    return result


def scan_obj_av(filename):
    # result = avengine.scan(filename)
    result = None
    return result


def process_officedoc_macroscheck(filename):
    ret = False
    macros = ['vbaData.xml', 'vbaProject.bin']
    with ZipFile(filename, 'r') as zipObj:
        # Get list of files names in zip
        listOfiles = zipObj.namelist()
        # Iterate over the list of file names in given list & print them
        for elem in listOfiles:
            if elem in macros:
                print('Macro found: ', elem)
                ret = True
                break
    return ret


def process_decompiled_checker(path):
    f = []

    print("* Processed dir:", path)

    # Build all files list to process
    for (root, _, filenames) in os.walk(path):
        for filename in filenames:
            print("* filenames:", filename)
            f.append(os.path.join(root, filename))

    # Process enumerated files in list
    for filename in f:
        print('***' * 30)

        filename = filename.replace('\\', '/').lower()
        print("* Processed file:", filename)

        _, ext = os.path.splitext(filename)
        ext = ext.replace('.', '')

        try:
            for item in extension_db.archives_exts:
                if ext == item:
                    print('File is archives_exts, we need to remove it!')
                    os.remove(filename)
                    print("# Archive ", filename, 'removed!!')
        except:
            pass

        try:
            for item in extension_db.whitelist_exts:
                if ext == item:
                    print('File is whitelisted, pass it')
                    break
        except:
            pass

        try:
            for item in extension_db.middlelist_exts:
                if ext == item or ext == 'unknown':
                    print('File is middlelist, we need to check it!')
                    if ext == 'docx' or ext == 'xlsx' or ext == 'docm' or ext == 'docm' or ext == 'xlsm':
                        if process_officedoc_macroscheck(filename):
                            os.remove(filename)
                            print(filename, 'MALICIOUS removed!!')
                            break
                    # if check_yara(filename):
                    #     os.remove(filename)
                    #     print(filename, 'MALICIOUS removed!!')
                    #     break
                    if scan_obj_av(filename):
                        os.remove(filename)
                        print(filename, 'MALICIOUS removed!!')
                        break
        except:
            pass

        try:
            for item in extension_db.blacklist_exts:
                if ext == item:
                    print('File is blacklist, we need to remove it!')
                    os.remove(filename)
                    print(filename, 'removed!!')
                    break
        except:
            pass

    return True
