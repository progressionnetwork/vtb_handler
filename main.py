PRODUCT = False

import base64
import json
import logging
import os, sys
from pathlib import Path
import time
from api.services.vtb_handler.handler import Handler, DetectDocument, process_decompiled_from_xml, process_decompiled_checker, visualize_fs_struct, process_json_report, process_restore_struct, process_enum_malicious
# Self modules for DEBUG
#from handler import Handler, DetectDocument, process_decompiled_from_xml, process_decompiled_checker, visualize_fs_struct, process_json_report, process_restore_struct, process_enum_malicious
import binascii
import extension_db
import random as r
# import yara  # pip install yara-python
# from yara_scanner import YaraScanner  # pip install yara-scanner

# Config for PROD
from Config.settings import MEDIA_ROOT
GLOBAL_PATH = MEDIA_ROOT[:-1]
# Config for DEBUG
# GLOBAL_PATH = 'media'
# MEDIA_ROOT = 'media'


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
        total_objects, total_malicious, total_archives, malicious_list, folder_name = process_decompiled_checker(output_dir)
        # Extact malicious file names from temp dir
        malw_list = process_enum_malicious(folder_name)
        # Compress archives and XML back, restore structure
        process_restore_struct(output_dir)
        # Build outer xml file after removing malicious
        result_xml = handler.combine_data_to_xml(output_dir)

        report['xml_data']['uniq_id'] = taskid
        report['xml_data']['input_xml_file'] = filename
        report['xml_data']['output_xml_file'] = result_xml.replace(MEDIA_ROOT,"")
        report['xml_data']['input_xml_size'] = round(os.path.getsize(filename) / 1024)
        report['xml_data']['output_xml_size'] = round(os.path.getsize(result_xml) / 1024)
        report['xml_data']['total_objects'] = total_objects
        report['xml_data']['malicious_objects'] = total_malicious
        report['xml_data']['malicious_list'] = malicious_list
        report['xml_data']['total_archives'] = total_archives
        report['xml_data']['tags'] = handler.enum_xml_tags()
        report['xml_data']['malicious_folder'] = GLOBAL_PATH + '/tmp/' + folder_name
        report['xml_data']['malicious_paths'] = malw_list

        with open('report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=4)
            f.close()
        return report,outputfilename

        # print('---' * 30)


def file_checker(file_path):
    print(file_path)
    print('Starting handler...')

    taskid = time.strftime("%d_%H%M") + str(r.randrange(77,7777))
    # filename = GLOBAL_PATH + "/xmls/2_sample_BN2D9R.xml"

    # filename = os.path.abspath(filename)
    file_path = file_path
    logging.info('File:', file_path)
    return process_nested_file(file_path, taskid)


# if __name__ == '__main__':
#
#     print('Starting handler...')
#
#     taskid = time.strftime("%d_%H%M") + str(r.randrange(77,7777))
#     filename = GLOBAL_PATH + "/xmls/2_sample_BN2D9R.xml"
#
#     filename = os.path.abspath(filename)
#     filename = filename.lower()
#     logging.info('File:', filename)
#     process_nested_file(filename, taskid)
#
#     sys.exit()