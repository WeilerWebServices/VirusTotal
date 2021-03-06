Base64 Decoding and Unpacking
=============================

This module allows you to extract base64 encoded content from a
string or columns of a Pandas DataFrame. The library returns the
following information:

-  decoded string (if decodable to utf-8 or utf-16)
-  hashes of the decoded segment (MD5, SHA1, SHA256)
-  string of printable byte values (e.g. for submission to a
   disassembler)
-  the detected decoded file type (limited)

If the results of the decoding contain further encoded strings these
will be decoded recursively. If the encoded string appears to be a
zip, gzip or tar archive, the contents will be decompressed after
decoding. In the case of zip and tar, the contents of the archive
will also be checked for base64 encoded content and
decoded/decompressed if possible.


See :py:mod:`b64decode<msticpy.sectools.b64decode>`


.. code:: python

   # Imports
   import sys
   MIN_REQ_PYTHON = (3,6)
   if sys.version_info < MIN_REQ_PYTHON:
         print('Check the Kernel->Change Kernel menu and ensure that Python 3.6')
         print('or later is selected as the active kernel.')
         sys.exit("Python %s.%s or later is required.\n" % MIN_REQ_PYTHON)


   from IPython.display import display
   import pandas as pd

   # Import Base64 module
   from msticpy.nbtools import *
   from msticpy.sectools import *



.. container:: cell code

   .. code:: python

      # Load test data
      process_tree = pd.read_csv('data/process_tree.csv',
                                 parse_dates=["TimeGenerated"],
                                 infer_datetime_format=True)
      process_tree[['CommandLine']].head()

   .. container:: output execute_result

      ::

                                                  CommandLine
         0                   .\ftp  -s:C:\RECYCLER\xxppyy.exe
         1  .\reg  not /domain:everything that /sid:shines...
         2                 cmd  /c "systeminfo && systeminfo"
         3                           .\rundll32  /C 12345.exe
         4       .\rundll32  /C c:\users\MSTICAdmin\12345.exe



Base64 decode an input string
-----------------------------

unpack(input_string=cmdline)

See :py:func:`unpack<msticpy.sectools.b64decode.unpack>`


Items that decode to utf-8 or utf-16 strings will be returned as decoded
strings replaced in the original string. If the encoded string is a
known binary type it will identify the file type and return the hashes
of the file. If any binary types are known archives (zip, tar, gzip) it
will unpack the contents of the archive.
For any binary it will return the decoded file as a byte array, and as a
printable list of byte values.

The function a tuple of the decoded string and a pandas DataFrame of
metadata (hashes, list of byte values, etc.)

.. container:: cell code

   .. code:: python

      # get a commandline from our data set
      cmdline = process_tree['CommandLine'].loc[39]
      cmdline

   .. container:: output execute_result

      ::

         '.\\powershell  -enc JAB0ACAAPQAgACcAZABpAHIAJwA7AA0ACgAmACAAKAAnAEkAbgB2AG8AawBlACcAKwAnAC0ARQB4AHAAcgBlAHMAcwBpAG8AbgAnACkAIAAkAHQA'

.. container:: cell code

   .. code:: python

      # Decode the string
      base64_dec_str = base64.unpack(input_string=cmdline)

      # Print decoded string
      print(base64_dec_str)

   .. container:: output stream stdout

      ::

         (".\\powershell  -enc <decoded type='string' name='[None]' index='1' depth='1'>$\x00t\x00 \x00=\x00 \x00'\x00d\x00i\x00r\x00'\x00;\x00\r\x00\n\x00&\x00 \x00(\x00'\x00I\x00n\x00v\x00o\x00k\x00e\x00'\x00+\x00'\x00-\x00E\x00x\x00p\x00r\x00e\x00s\x00s\x00i\x00o\x00n\x00'\x00)\x00 \x00$\x00t\x00</decoded>",    reference                                    original_string file_name  \
         0  (, 1., 1)  JAB0ACAAPQAgACcAZABpAHIAJwA7AA0ACgAmACAAKAAnAE...   unknown

           file_type                                        input_bytes  \
         0      None  b"$\x00t\x00 \x00=\x00 \x00'\x00d\x00i\x00r\x0...

                                               decoded_string encoding_type  \
         0  $ t   =   ' d i r ' ; \r \n &   ( ' I n v o k ...         utf-8

                                                  file_hashes  \
         0  {'md5': '6cd1486db221e532cc2011c9beeb4ffc', 's...

                                         md5                                      sha1  \
         0  6cd1486db221e532cc2011c9beeb4ffc  6e485467d7e06502046b7c84a8ef067cfe1512ad

                                                       sha256  \
         0  d3291dab1ae552b91e6b50d7460ceaa39f6f92b2cda433...

                                              printable_bytes
         0  24 00 74 00 20 00 3d 00 20 00 27 00 64 00 69 0...  )



Using a DataFrame as input
--------------------------

You can use :py:func:`unpack_df<msticpy.sectools.b64decode.unpack_df>`
to pass a DataFrame as an
argument. Use the ``column`` parameter to specify which column to
process.

In the case of DataFrame input, the output DataFrame contains these
additional columns:

-  src_index - the index of the row in the input dataframe from which
   the data came.
-  full_decoded_string - the full decoded string with any decoded
   replacements. This is only really useful for top-level items,
   since nested items will only show the 'full' string representing
   the child fragment.


Base64 decode strings taken from a pandas dataframe.


Items that decode to utf-8 or utf-16 strings will be returned as
decoded strings replaced in the original string. If the encoded
string is a known binary type it will identify the file type and
return the hashes of the file. If any binary types are known archives
(zip, tar, gzip) it will unpack the contents of the archive. For any
binary it will return the decoded file as a byte array, and as a
printable list of byte values.

.. container:: cell code

   .. code:: python

      # specify the data and column parameters
      dec_df = base64.unpack_df(data=process_tree, column='CommandLine')
      dec_df

   .. container:: output execute_result

      ::

            reference                                    original_string file_name  \
         0  (, 1., 1)  JAB0ACAAPQAgACcAZABpAHIAJwA7AA0ACgAmACAAKAAnAE...   unknown
         1  (, 1., 1)                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa   unknown
         2  (, 1., 1)                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa   unknown
         3  (, 1., 1)                   81ed03caf6901e444c72ac67d192fb9c   unknown

           file_type                                        input_bytes  \
         0      None  b"$\x00t\x00 \x00=\x00 \x00'\x00d\x00i\x00r\x0...
         1      None  b'i\xa6\x9ai\xa6\x9ai\xa6\x9ai\xa6\x9ai\xa6\x9...
         2      None  b'i\xa6\x9ai\xa6\x9ai\xa6\x9ai\xa6\x9ai\xa6\x9...
         3      None  b'\xf3W\x9d\xd3w\x1a\x7f\xaft\xd5\xee8\xe1\xce...

                                               decoded_string encoding_type  \
         0  $ t   =   ' d i r ' ; \r \n &   ( ' I n v o k ...         utf-8
         1                                       ????????????????????????????????????        utf-16
         2                                       ????????????????????????????????????        utf-16
         3                                       ????????????????????????????????????        utf-16

                                                  file_hashes  \
         0  {'md5': '6cd1486db221e532cc2011c9beeb4ffc', 's...
         1  {'md5': '9a45b2520e930dc9186f6d93a7798a13', 's...
         2  {'md5': '9a45b2520e930dc9186f6d93a7798a13', 's...
         3  {'md5': '1c8cc6299bd654bbcd85710968d6a87c', 's...

                                         md5                                      sha1  \
         0  6cd1486db221e532cc2011c9beeb4ffc  6e485467d7e06502046b7c84a8ef067cfe1512ad
         1  9a45b2520e930dc9186f6d93a7798a13  f526c90fa0744e3a63d84421ff25e3f5a3d697cb
         2  9a45b2520e930dc9186f6d93a7798a13  f526c90fa0744e3a63d84421ff25e3f5a3d697cb
         3  1c8cc6299bd654bbcd85710968d6a87c  55377391141f59a2ff5ae4765d9f0b4438adfd73

                                                       sha256  \
         0  d3291dab1ae552b91e6b50d7460ceaa39f6f92b2cda433...
         1  c1f6c05bdbe28a58557a9477cd0fa96fbc5e7c54ceb605...
         2  c1f6c05bdbe28a58557a9477cd0fa96fbc5e7c54ceb605...
         3  fd80ceba7cfb49d296886c10d9a3497d63c89a589587cd...

                                              printable_bytes  src_index  \
         0  24 00 74 00 20 00 3d 00 20 00 27 00 64 00 69 0...         39
         1  69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a 6...         40
         2  69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a 6...         41
         3  f3 57 9d d3 77 1a 7f af 74 d5 ee 38 e1 ce f6 6...         44

                                          full_decoded_string
         0  .\powershell  -enc <decoded type='string' name...
         1  cmd  /c "echo # <decoded type='string' name='[...
         2  cmd  /c "echo # <decoded type='string' name='[...
         3  implant.exe  <decoded type='string' name='[Non...


Interpreting the DataFrame output
---------------------------------


For simple strings the Base64 decoded output is straightforward.
However for nested encodings this can get a little complex and
difficult to represent in a tabular format.

Output columns
~~~~~~~~~~~~~~

*  **reference** - The index of the row item in dotted notation, in
   depth.seq pairs (e.g. 1.2.2.3 would be the 3 item at depth 3 that
   is a child of the 2nd item found at depth 1). This may not always
   be an accurate notation - it is mainly use to allow you to
   associate an individual row with the reference value contained in
   the full_decoded_string column of the topmost item).
*  **original_string** - the original string before decoding.
*  **file_name** - filename, if any (only if this is an item in zip or
   tar file).
*  **file_type** - a guess at the file type (this is currently elementary
   and only includes a few file types).
*  **input_bytes** - the decoded bytes as a Python bytes string.
*  **decoded_string** - the decoded string if it can be decoded as a
   UTF-8 or UTF-16 string. Note: binary sequences may often
   successfully decode as UTF-16 strings but, in these cases, the
   decodings are meaningless.
*  **encoding_type** - encoding type (UTF-8 or UTF-16) if a decoding was
   possible, otherwise 'binary'.
*  **file_hashes** - collection of file hashes for any decoded item.
*  **md5** - md5 hash as a separate column.
*  **sha1** - sha1 hash as a separate column.
*  **sha256** - sha256 hash as a separate column.
*  **printable_bytes** - printable version of input_bytes as a string of
   \\xNN values
*  **src_index** - the DataFrame index of the input row.


The ``src_index`` column allows you to merge the results with
the input DataFrame.


Where an input row results in multiple decoded elements, (e.g. a
nested encoding or encoded archive file), the output of this merge
will result in duplicate rows from the input (one per decoded element).
The row index of the input is preserved in the src_index.

.. note:: In order to merge output with input you may need to explictly force
   the type of the SourceIndex column. In the
   example below case we are matching with the default numeric index so
   we force the type to be numeric. In cases where you are using an
   index of a different dtype you will need to convert the SourceIndex
   (dtype=object) to match the type of your index column.

.. note:: the output of unpack_items() may have multiple rows
   (for nested encodings). In this case merged DF will have
   duplicate rows from the source.

.. container:: cell code

   .. code:: python

      # Set the type of the SourceIndex column.
      dec_df['SourceIndex'] = pd.to_numeric(dec_df['src_index'])
      merged_df = (process_tree
                   .merge(right=dec_df, how='left', left_index=True, right_on='SourceIndex')
                   .drop(columns=['Unnamed: 0'])
                   .set_index('SourceIndex'))

      # Show the result of the merge (only those rows that have a value in original_string)
      merged_df.dropna(subset=['original_string'])

      # Note the output of unpack_items() may have multiple rows (for nested encodings)
      # In this case merged DF will have duplicate rows from the source.

   .. container:: output execute_result

      ::

                                                  TenantId                     Account  \
         SourceIndex
         39           802d39e1-9d70-404d-832c-2de5e2478eda  MSTICAlertsWin1\MSTICAdmin
         40           802d39e1-9d70-404d-832c-2de5e2478eda  MSTICAlertsWin1\MSTICAdmin
         41           802d39e1-9d70-404d-832c-2de5e2478eda  MSTICAlertsWin1\MSTICAdmin
         44           802d39e1-9d70-404d-832c-2de5e2478eda  MSTICAlertsWin1\MSTICAdmin

                      EventID           TimeGenerated         Computer  \
         SourceIndex
         39              4688 2019-01-15 05:15:13.567  MSTICAlertsWin1
         40              4688 2019-01-15 05:15:13.683  MSTICAlertsWin1
         41              4688 2019-01-15 05:15:13.793  MSTICAlertsWin1
         44              4688 2019-01-15 05:15:12.003  MSTICAlertsWin1

                                                    SubjectUserSid SubjectUserName  \
         SourceIndex
         39           S-1-5-21-996632719-2361334927-4038480536-500      MSTICAdmin
         40           S-1-5-21-996632719-2361334927-4038480536-500      MSTICAdmin
         41           S-1-5-21-996632719-2361334927-4038480536-500      MSTICAdmin
         44           S-1-5-21-996632719-2361334927-4038480536-500      MSTICAdmin

                     SubjectDomainName SubjectLogonId NewProcessId  ...  \
         SourceIndex                                                ...
         39            MSTICAlertsWin1       0xfaac27       0x1684  ...
         40            MSTICAlertsWin1       0xfaac27       0x16b8  ...
         41            MSTICAlertsWin1       0xfaac27       0x16ec  ...
         44            MSTICAlertsWin1       0xfaac27       0x1250  ...

                                                            input_bytes  \
         SourceIndex
         39           b"$\x00t\x00 \x00=\x00 \x00'\x00d\x00i\x00r\x0...
         40           b'i\xa6\x9ai\xa6\x9ai\xa6\x9ai\xa6\x9ai\xa6\x9...
         41           b'i\xa6\x9ai\xa6\x9ai\xa6\x9ai\xa6\x9ai\xa6\x9...
         44           b'\xf3W\x9d\xd3w\x1a\x7f\xaft\xd5\xee8\xe1\xce...

                                                         decoded_string encoding_type  \
         SourceIndex
         39           $ t   =   ' d i r ' ; \r \n &   ( ' I n v o k ...         utf-8
         40                                                ????????????????????????????????????        utf-16
         41                                                ????????????????????????????????????        utf-16
         44                                                ????????????????????????????????????        utf-16

                                                            file_hashes  \
         SourceIndex
         39           {'md5': '6cd1486db221e532cc2011c9beeb4ffc', 's...
         40           {'md5': '9a45b2520e930dc9186f6d93a7798a13', 's...
         41           {'md5': '9a45b2520e930dc9186f6d93a7798a13', 's...
         44           {'md5': '1c8cc6299bd654bbcd85710968d6a87c', 's...

                                                   md5  \
         SourceIndex
         39           6cd1486db221e532cc2011c9beeb4ffc
         40           9a45b2520e930dc9186f6d93a7798a13
         41           9a45b2520e930dc9186f6d93a7798a13
         44           1c8cc6299bd654bbcd85710968d6a87c

                                                          sha1  \
         SourceIndex
         39           6e485467d7e06502046b7c84a8ef067cfe1512ad
         40           f526c90fa0744e3a63d84421ff25e3f5a3d697cb
         41           f526c90fa0744e3a63d84421ff25e3f5a3d697cb
         44           55377391141f59a2ff5ae4765d9f0b4438adfd73

                                                                 sha256  \
         SourceIndex
         39           d3291dab1ae552b91e6b50d7460ceaa39f6f92b2cda433...
         40           c1f6c05bdbe28a58557a9477cd0fa96fbc5e7c54ceb605...
         41           c1f6c05bdbe28a58557a9477cd0fa96fbc5e7c54ceb605...
         44           fd80ceba7cfb49d296886c10d9a3497d63c89a589587cd...

                                                        printable_bytes src_index  \
         SourceIndex
         39           24 00 74 00 20 00 3d 00 20 00 27 00 64 00 69 0...      39.0
         40           69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a 6...      40.0
         41           69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a 6...      41.0
         44           f3 57 9d d3 77 1a 7f af 74 d5 ee 38 e1 ce f6 6...      44.0

                                                    full_decoded_string
         SourceIndex
         39           .\powershell  -enc <decoded type='string' name...
         40           cmd  /c "echo # <decoded type='string' name='[...
         41           cmd  /c "echo # <decoded type='string' name='[...
         44           implant.exe  <decoded type='string' name='[Non...

         [4 rows x 36 columns]



Decoding Nested Base64/Archives
-------------------------------


The module will try to follow nested encodings. It uses the following
algorithm:

1. Search for a pattern in the input that looks like a Base64 encoded
   string
2. If not a known undecodable_string, try to decode the matched
   pattern.

   -  If the base 64 string matches a known archive type (zip, tar,
      gzip) also decompress or unpack

      -  For multi-item archives (zip, tar) process each contained
         item recursively (i.e. go to item 1. with child item as
         input)

   -  For anything that decodes to a UTF-8 or UTF-16 string replace
      the input pattern with the decoded string
   -  Recurse over resultant output (i.e. submit decoded/replaced
      string to 1.)

3. If decoding fails, add to list of undecodable_strings (prevents
   infinite looping over something that looks like a base64 string
   but isn't)

.. container:: cell code

   .. code:: python

      encoded_cmd = '''
      powershell.exe  -nop -w hidden -encodedcommand
      UEsDBBQAAAAIAGBXkk3LfdszdwAAAIoAAAAJAAAAUGVEbGwuZGxss6v+sj/A0diA
      UXmufa/PFcYNcRwX7I/wMC4oZAjgUJyzTEgqrdHbfuWyy/OCExqUGJkZGBoYoEDi
      QPO3P4wJuqsQgGvVKimphoUIIa1Fgr9OMLyoZ0z4y37gP2vDfxDp8J/RjWEzs4NG
      +8TMMoYTCouZGRSShAFQSwMEFAAAAAAAYYJrThx8YzUhAAAAIQAAAAwAAABiNjRp
      bnppcC5mb29CYXNlNjQgZW5jb2RlZCBzdHJpbmcgaW4gemlwIGZpbGVQSwMEFAAA
      AAAAi4JrTvMfsJUaAAAAGgAAABIAAABQbGFpblRleHRJblppcC5kbGxVbmVuY29k
      ZWQgdGV4dCBmaWxlIGluIHppcFBLAQIUABQAAAAIAGBXkk3LfdszdwAAAIoAAAAJ
      AAAAAAAAAAAAIAAAAAAAAABQZURsbC5kbGxQSwECFAAUAAAAAABhgmtOHHxjNSEA
      AAAhAAAADAAAAAAAAAABACAAAACeAAAAYjY0aW56aXAuZm9vUEsBAhQAFAAAAAAA
      i4JrTvMfsJUaAAAAGgAAABIAAAAAAAAAAQAgAAAA6QAAAFBsYWluVGV4dEluWmlw
      LmRsbFBLBQYAAAAAAwADALEAAAAzAQAAAAA='''

      import re
      dec_string, dec_df = base64.unpack(input_string=encoded_cmd)
      print(dec_string.replace('<decoded', '\n<decoded'))

   .. container:: output stream stdout

      ::


         powershell.exe  -nop -w hidden -encodedcommand
         <decoded value='multiple binary' type='multiple' index='1' depth='1'>
         <decoded type='string' name='[zip] Filename: PeDll.dll' index='1.1' depth='2'>????????????????????????????????????????????????????????????????????? ??   ??????????????????????????????????????????????????????????????????????????????????????????????????????v???????????</decoded>
         <decoded type='string' name='[zip] Filename: b64inzip.foo' index='1.2' depth='2'>Base64 encoded string in zip file</decoded>
         <decoded type='string' name='[zip] Filename: PlainTextInZip.dll' index='1.3' depth='2'>Unencoded text file in zip</decoded></decoded>


IPython magic
-------------

You can use the cell magic ``%%b64`` to decode
text directly in a cell

The b64 magic supports the following options:

::

   --out OUT, -o OUT  The variable to return the results in the variable `OUT`
                      Note: the output is a tuple of decoded string and pandas DataFrame
   --pretty, -p       Print formatted version of output (if you `print` the output)
   --clean, -c        Print decoded string with no formatting

.. code:: ipython3

    %%b64 --pretty --out dec_xml
    powershell.exe  -nop -w hidden -encodedcommand
    UEsDBBQAAAAIAGBXkk3LfdszdwAAAIoAAAAJAAAAUGVEbGwuZGxss6v+sj/A0diA
    UXmufa/PFcYNcRwX7I/wMC4oZAjgUJyzTEgqrdHbfuWyy/OCExqUGJkZGBoYoEDi
    QPO3P4wJuqsQgGvVKimphoUIIa1Fgr9OMLyoZ0z4y37gP2vDfxDp8J/RjWEzs4NG
    +8TMMoYTCouZGRSShAFQSwMEFAAAAAAAYYJrThx8YzUhAAAAIQAAAAwAAABiNjRp
    bnppcC5mb29CYXNlNjQgZW5jb2RlZCBzdHJpbmcgaW4gemlwIGZpbGVQSwMEFAAA
    AAAAi4JrTvMfsJUaAAAAGgAAABIAAABQbGFpblRleHRJblppcC5kbGxVbmVuY29k
    ZWQgdGV4dCBmaWxlIGluIHppcFBLAQIUABQAAAAIAGBXkk3LfdszdwAAAIoAAAAJ
    AAAAAAAAAAAAIAAAAAAAAABQZURsbC5kbGxQSwECFAAUAAAAAABhgmtOHHxjNSEA
    AAAhAAAADAAAAAAAAAABACAAAACeAAAAYjY0aW56aXAuZm9vUEsBAhQAFAAAAAAA
    i4JrTvMfsJUaAAAAGgAAABIAAAAAAAAAAQAgAAAA6QAAAFBsYWluVGV4dEluWmlw
    LmRsbFBLBQYAAAAAAwADALEAAAAzAQAAAAA=




.. parsed-literal::

    '<?xml version="1.0" encoding="utf-8"?>\n<decoded_string>\n powershell.exe  -nop -w hidden -encodedcommand\n <decoded depth="1" index="1" type="multiple" value="multiple binary">\n  <decoded depth="2" index="1.1" name="[zip] Filename: PeDll.dll" type="zip" value="binary">\n   3e 7b f4 bf 50 41 33 30 01 23 9d 3f 8d 4c d4 01 b0 5e 08 d0 3f c4 0c 01 a0 71 00 50 08 21 9c a6 12 1a 66 81 4b 3f a9 a6 d3 9e 53 60 80 22 01 03 00 00 80 00 00 00 00 00 00 00 00 18 c0 83 f6 fc 01 60 2d aa aa aa aa aa aa aa aa aa aa aa 0a aa aa 1a 1a 80 a1 2d aa aa aa aa aa aa aa aa aa 2a a2 11 fa c8 00 e8 7f 01 60 fd 07 c0 ff 05 80 ff 07 c0 ff 05 40 ff 01 46 00 b3 03 40 28 87 91 69 76 00 c8 20 a3 03 00 20 62 13\n  </decoded>\n  <decoded depth="2" index="1.2" name="[zip] Filename: b64inzip.foo" type="string">\n   Base64 encoded string in zip file\n  </decoded>\n  <decoded depth="2" index="1.3" name="[zip] Filename: PlainTextInZip.dll" type="string">\n   Unencoded text file in zip\n  </decoded>\n </decoded>\n</decoded_string>'


Display the pretty-printed version of the decoded string.


.. code:: ipython3

    print(dec_xml[0])


.. parsed-literal::

    <?xml version="1.0" encoding="utf-8"?>
    <decoded_string>
     powershell.exe  -nop -w hidden -encodedcommand
     <decoded depth="1" index="1" type="multiple" value="multiple binary">
      <decoded depth="2" index="1.1" name="[zip] Filename: PeDll.dll" type="zip" value="binary">
       3e 7b f4 bf 50 41 33 30 01 23 9d 3f 8d 4c d4 01 b0 5e 08 d0 3f c4 0c 01 a0 71 00 50 08 21 9c a6 12 1a 66 81 4b 3f a9 a6 d3 9e 53 60 80 22 01 03 00 00 80 00 00 00 00 00 00 00 00 18 c0 83 f6 fc 01 60 2d aa aa aa aa aa aa aa aa aa aa aa 0a aa aa 1a 1a 80 a1 2d aa aa aa aa aa aa aa aa aa 2a a2 11 fa c8 00 e8 7f 01 60 fd 07 c0 ff 05 80 ff 07 c0 ff 05 40 ff 01 46 00 b3 03 40 28 87 91 69 76 00 c8 20 a3 03 00 20 62 13
      </decoded>
      <decoded depth="2" index="1.2" name="[zip] Filename: b64inzip.foo" type="string">
       Base64 encoded string in zip file
      </decoded>
      <decoded depth="2" index="1.3" name="[zip] Filename: PlainTextInZip.dll" type="string">
       Unencoded text file in zip
      </decoded>
     </decoded>
    </decoded_string>


Pandas Extension
----------------

The decoding functionality is also available in a pandas extension
``mp_b64``. This supports a single method ``extract()``.

This supports the same syntax as ``unpack_df`` (described earlier).
It returns a DataFrame with the decoded contents (this may be
multiple output lines for inputs where there is a nested encoding.

.. code:: ipython3

    process_tree.mp_b64.extract(column='CommandLine')


.. container:: cell markdown

   .. rubric:: To-Do Items
      :name: to-do-items

   -  Use more comprehensive list of binary magic numbers and match on
      byte values after decoding to get better file typing
   -  Output nested decodings in a more readable output
   -  Add a pandas pipe() partial function to allow inline decoding in a
      pands pipeline. E.g.

   ``my_df = pd.read_cs('input.csv').b64decode(column='CommandLine').drop_duplicates().some_func()``
