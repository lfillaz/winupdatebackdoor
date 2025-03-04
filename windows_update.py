# UTF-8
#
# Windows Update Version Information
from PyInstaller.utils.win32 import versioninfo

VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(6, 3, 9600, 17031),
    prodvers=(6, 3, 9600, 17031),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          u'040904B0',
          [StringStruct(u'CompanyName', u'Microsoft Corporation'),
           StringStruct(u'FileDescription', u'Windows Update Service'),
           StringStruct(u'FileVersion', u'6.3.9600.17031'),
           StringStruct(u'InternalName', u'Windows Update'),
           StringStruct(u'LegalCopyright', u'(c) Microsoft Corporation. All rights reserved.'),
           StringStruct(u'OriginalFilename', u'WindowsUpdate.exe'),
           StringStruct(u'ProductName', u'Microsoft Windows Operating System'),
           StringStruct(u'ProductVersion', u'6.3.9600.17031')])
      ]
    ),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
