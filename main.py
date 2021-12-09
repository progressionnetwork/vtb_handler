import base64
import json
import logging
import os, sys
from pathlib import Path
import time
from handler import Handler, DetectDocument, process_decompiled_from_xml, process_decompiled_checker, visualize_fs_struct, process_json_report, process_restore_struct
import binascii
import extension_db
import random as r
import yara  # pip install yara-python
from yara_scanner import YaraScanner  # pip install yara-scanner

GLOBAL_PATH = 'MEDIA_ROOT'


def process_nested_file(filename, taskid):
    print("File: ", filename, "task id: ", taskid)

    with open(filename, 'rb') as f:
        blob = f.read()

    shortname = Path(filename).stem
    outputfilename = GLOBAL_PATH + '/processed/' + shortname + '_' + taskid + '.xml'
    handler = Handler(filename, blob, taskid, outputfilename)
    file_extension = handler.get_ext().lower()
    print(f"Extension: {file_extension}")
    ret = handler.check_ext()
    print(ret)

    size = handler.get_size()
    if size / 1024 > 128000:
        print('! File size is oversize: {}'.format(size))
        print('! Noting to scan!')
        sys.exit(1)

    if len(file_extension) == 0:
        print("File or blob without extension!!!")
        print("Trying to guess file is XML?")

    is_xml = handler.check_xml()
    if is_xml:

        # Extract and dump all files from XML file to output_dir
        output_dir = handler.enum_xml_data(GLOBAL_PATH + '/extracted')
        # Detect file types and unpack archives
        process_decompiled_from_xml(output_dir, taskid)
        # Generate visualization tree of file struct
        visualize_fs_struct(output_dir, GLOBAL_PATH + '/tree.txt')
        # Generate JSON report
        report = process_json_report(output_dir)
        # Execute white\blacklists & malicious checks
        total_objects, total_malicious, total_archives, malicious_list, malicious_blobs = process_decompiled_checker(output_dir)
        # Compress archives and XML back, restore structure
        process_restore_struct(output_dir)
        # Build outer xml file after removing malicious
        result_xml = handler.combine_data_to_xml(output_dir)

        report['xml_data']['input_xml_file'] = filename
        report['xml_data']['output_xml_file'] = os.path.abspath(result_xml)
        report['xml_data']['input_xml_size'] = round(os.path.getsize(filename) / 1024)
        report['xml_data']['output_xml_size'] = round(os.path.getsize(result_xml) / 1024)
        report['xml_data']['total_objects'] = total_objects
        report['xml_data']['malicious_objects'] = total_malicious
        report['xml_data']['malicious_list'] = malicious_list
        report['xml_data']['malicious_blobs'] = malicious_blobs
        report['xml_data']['total_archives'] = total_archives
        report['xml_data']['tags'] = handler.enum_xml_tags()

        print(json.dumps(report, indent=4))
        with open('report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=4)
            f.close()
        print('---' * 30)


if __name__ == '__main__':

    print('Starting handler...')

    taskid = time.strftime("%d_%H%M") + str(r.randrange(77,7777))
    filename = GLOBAL_PATH + "/xmls/2_sample_BN2D9R.xml"

    filename = os.path.abspath(filename)
    filename = filename.lower()
    logging.info('File:', filename)
    process_nested_file(filename, taskid)

    sys.exit()

        # with open(filename, 'rb') as f:
        #     blob = f.read()
        #
        # handler = Handler(filename, blob)
        # file_extension = handler.get_ext().lower()
        # print(f"Extension: {file_extension}")
        # ret = handler.check_ext()
        #
        # if 'xml' in file_extension:
        #     print(f"XML found!")
        #     handler.check_xml()
        #     print("List of tags found: ")
        #     result = handler.enum_xml_tags()
        #     print(result)
        #
        # if len(file_extension) == 0:
        #     print("File or blob without extension!!!")
        # if file_extension in extension_db.blacklist_exts:
        #     print('! Is blacklisted: {}'.format(ret))
        #     print('* Executing a deep scan!')
        # if file_extension in extension_db.middlelist_exts:
        #     print('! Is middlelisted, need additional check: {}'.format(ret))
        # if file_extension in extension_db.whitelist_exts:
        #     print('! Is whitelisted: {}'.format(ret))
        #     print('! Noting to scan!')
        #     sys.exit(1)
        #
        #
        # sys.exit(1)
        #
        # mime = handler.check_header()
        # handler.check_yara()
        #
        # # Check if file is JSON or XML
        # detector = DetectDocument(filename)
        #
        # print("{file_type}: \n\t is_json:{is_json_file} \n\t is_xml:{is_xml_file}".format(
        #     file_type=detector._parsed_file,
        #     is_json_file=detector.is_json_file,
        #     is_xml__file=detector.is_xml_file)
        # )
        #
        # # handler.check_base64()
        # handler.check_json()


        # handler.check_xml()
