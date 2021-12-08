import struct
import enum

whitelist_exts = ['png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp', '3gp', 'mp4', 'mp3', 'mkv', 'm4v', 'avi', 'mov',
                  'mpg', 'flv', 'ogg', 'wav', 'm4a', "doc", "xls"]

middlelist_exts = ["docx", "xlsx", "tif", 'pdf', "rtf",
                   'docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm'
                   "br",  # application/x-brotli
                   "rpm",  # application/x-rpm
                   "dcm",  # application/dicom
                   "zip",  # application/zip
                   "tar",  # application/x-tar
                   "rar",  # application/x-rar-compressed
                   "gz",  # application/gzip
                   "bz2",  # application/x-bzip2
                   "7z",  # application/x-7z-compressed
                   "xz",  # application/x-xz
                   "swf",  # application/x-shockwave-flash
                   "eot",  # application/octet-stream
                   "ps",  # application/postscript
                   "ar",  # application/x-unix-archive
                   "Z",  # application/x-compress
                   "lzo",  # application/x-lzop
                   "lz",  # application/x-lzip
                   "lz4",  # application/x-lz4
                   ]
# https://www.howtogeek.com/137270/50-file-extensions-that-are-potentially-dangerous-on-windows/
blacklist_exts = ['exe', 'dll', 'pif', 'cmd', 'com', 'sh', 'bat', 'js', 'jse', 'vbs', 'vbe', 'sct', 'msi', 'scr',
                  'application', 'gadget', 'hta', 'cpl', 'msc', 'msp', 'jar', 'ws', 'wsf',
                  'wsc', 'wsh+', 'ps1', 'ps1xml', 'ps2', 'ps2xml', 'psc1', 'psc2', 'msh', 'msh1', 'msh2', 'mshxml',
                  'msh1xml', 'msh2xml', 'scf', 'lnk', 'reg', 'crx', 'cab']

archives_exts = ['zip', 'rar', '7z', 'tgz', 'gzip', 'gz', 'tar']


class ExtStatus(enum.Enum):
    whitelisted = 0
    blacklisted = 1
    middlelisted = 2
    unknown = 3
