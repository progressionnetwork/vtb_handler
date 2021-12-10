#!/usr/bin/python
import os
import sys
import xml.etree.cElementTree as ET
import random as r
import random
import string
from yattag import Doc, indent  # pip install yattag
import base64

"""
XMLGEN XML/JSON sample files generator.
Able to generate non-standard XML nasted structures with multiple layers.
Stored data - random strings/values or base64 encoded files.
Can be used to testing & fuzzing XML parsers and so on.
for VTB Hackathon / (c) k0b1x 2021.
"""

NUM_OF_FILES_MIN = 1
NUM_OF_FILES_MAX = 5
NUM_OF_PARENTTAGS_MIN = 5
NUM_OF_PARENTTAGS_MAX = 10
NUM_OF_CHILDTAGS_MIN = 3
NUM_OF_CHILDTAGS_MAX = 5

parents = ['members', 'meta', 'data', 'assembly', 'entry', 'file']
subtags = ['string', 'summary', 'text', 'data', 'file', 'tag', 'param', 'message']


def b64enc_str(s):
    return base64.b64encode(s.encode()).decode()


def b64enc(s):
    return base64.b64encode(s).decode()


def b64dec(s):
    return base64.b64decode(s).decode()


def gen_rnd_data(words):
    upper_words = [word for word in words if word[0].isupper()]
    name_words = [word for word in upper_words if not word.isupper()]
    rand_name = ' '.join([name_words[random.randint(0, len(name_words))] for i in range(2)])
    return 0


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(r.choice(chars) for _ in range(size))


def gen_rnd_xml(filename):
    root = ET.Element("root")
    doc = ET.SubElement(root, "doc")

    for i in range(r.randrange(1, 10)):
        name = id_generator()
        data = id_generator(200, chars=string.ascii_uppercase)

        ET.SubElement(doc, "data" + str(i), name=name).text = data

    tree = ET.ElementTree(root)
    tree.write(filename)


def make_random_sentence(words):
    sent = ""
    for i in range(r.randrange(1, 10)):
        sent += " " + r.choice(words)
    return sent


def gen_xml_rnd_data(filename, words):
    doc, tag, text = Doc().tagtext()

    vid = 0
    with tag('root'):
        for n in range(r.randrange(NUM_OF_PARENTTAGS_MIN, NUM_OF_PARENTTAGS_MAX)):
            doc.asis('\n')
            doc.asis('<!-- ' + r.choice(parents) + ' -->')
            with tag(r.choice(parents)):
                with tag(r.choice(parents)):
                    for i in range(r.randrange(NUM_OF_CHILDTAGS_MIN, NUM_OF_CHILDTAGS_MAX)):

                        wordset = make_random_sentence(words)
                        num = r.randrange(1, 5)
                        name = id_generator()

                        if num == 0:
                            data = wordset
                            with tag(r.choice(subtags), name=r.choice(words), value=str(i), id=(str(vid))):
                                text(data)
                        if num == 1:
                            data = id_generator(r.randrange(10, 2000), chars=string.ascii_uppercase)
                            with tag(r.choice(subtags), name=r.choice(words), id=(str(vid))):
                                text(data)
                        if num == 2:
                            data = str(r.randrange(1, 99999))
                            with tag(r.choice(subtags), value=str(i), id=(str(vid))):
                                text(data)
                        if num == 3:
                            data = r.choice(words)
                            with tag(r.choice(subtags), name=r.choice(words)):
                                text(data)
                        if num == 4:
                            data = r.choice(words)
                            with tag(r.choice(subtags)):
                                text(data)
                        vid = + 1

    result = '<?xml version="1.0" encoding="utf-8"?>\n' + indent(
        doc.getvalue(),
        indentation=' ' * 4,
        newline='\r'
    )

    f = open(filename, "w")
    f.write(result)
    f.close()

    print(result)


def gen_xml_enchanted_vtb(filename, words):
    doc, tag, text = Doc().tagtext()

    vid = 0
    path = "media/samples/"

    f = []
    for (dirpath, dirnames, filenames) in os.walk(path):
        f.extend(filenames)
        break

    with tag('root'):
        for n in range(r.randrange(NUM_OF_PARENTTAGS_MIN, NUM_OF_PARENTTAGS_MAX)):

            with tag(r.choice(parents)):
                with tag(r.choice(parents)):
                    for i in range(r.randrange(NUM_OF_CHILDTAGS_MIN, NUM_OF_CHILDTAGS_MAX)):

                        wordset = make_random_sentence(words)
                        num = r.randrange(1, 4)
                        name = id_generator()

                        selected_file = r.choice(f)
                        value_name = (str(vid)) + '_' + selected_file.replace('.', '_')
                        sample_file = path + selected_file
                        print("Sample file: ", sample_file)
                        with open(sample_file, 'rb') as file:
                            blob = file.read()
                            blob = b64enc(blob)

                        if num == 0:
                            doc.asis('\n<!-- random word -->')
                            data = wordset
                            with tag(r.choice(subtags), name=r.choice(words), type="random word", value=str(i),
                                     id=(str(vid))):
                                text(data)
                        if num == 1:
                            doc.asis('\n<!-- encoded base64 file -->')
                            data = blob
                            with tag(r.choice(subtags), name=value_name, type="encoded base64 file", id=(str(vid))):
                                text(data)
                        if num == 2:
                            doc.asis('\n<!-- random value -->')
                            data = str(r.randrange(1, 99999))
                            with tag(r.choice(subtags), type="random value", value=str(i), id=(str(vid))):
                                text(data)
                        if num == 3:
                            doc.asis('\n<!-- encoded base64 file -->')
                            data = blob
                            with tag(r.choice(subtags), name=value_name, type="encoded base64 file"):
                                text(data)
                        if num == 4:
                            doc.asis('\n<!-- random word -->')
                            data = r.choice(words)
                            with tag(r.choice(subtags), type="random word", ):
                                text(data)
                        vid = + 1

    result = '<?xml version="1.0" encoding="utf-8"?>\n' + indent(
        doc.getvalue(),
        indentation=' ' * 4,
        newline='\r'
    )

    f = open(filename, "w")
    f.write(result)
    f.close()

    # print(result)


if __name__ == '__main__':

    f = open("words.txt", "r")
    words = [word for line in f for word in line.split()]

    for i in range(r.randrange(NUM_OF_FILES_MIN, NUM_OF_FILES_MAX)):
        fname = "media/xmls/sample_" + id_generator() + '.xml'
        print(f"{i}. Generating: ", fname)
        gen_xml_enchanted_vtb(fname, words)

    sys.exit()
