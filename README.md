# BloomAutoYara
This library perform automatic yara rule generation by using bloom filter for whitelisting.

Basic issue with present automatic yara generation tools is there isn't inbuilt effective whitelisting mechanism. They typically rely on user to provide text file containing whitelisted strings. This trivial approach is not scalable and can't avoid false positive detections.

In BloomAutoYara library, this issue is tackled using Bloom Filter. Bloom filters are explained very well in http://billmill.org/bloomfilter-tutorial/.

By design, bloom filter can't check for substring. This library overcomes this limitation by checking for non ascii character at start and end of each rule string

- Dependencis are python2.7 & pybloom library

This library exposes following functions used for automated yara rule generation. (Remaining internal functions can be easily understood from source)

- build_filter(cleanfiledir,extensions) :-
create a bloom filter using files having 'extensions' inside 'cleanfiledir'
- find_file_topn(filename,topn) :-
gets list of topn strings from 'filename' which are not present in bloom filter
- find_dir_topn(dirname,topn) :-
get list of topn most common strings from all files in directory 'dirname' where none of the string present in bloom filter
- list_to_rule(list,rulename,threshold=0.5) :- 
generates 'rulename.yara' file using strings from list. Number of strings matches before rule is triggered is decided by threshold.

- uploaded baseclean.bf file which contains around 16 million unique strings from 50k clean exe,dll,ocx,sys files

- created a simple program run.py which can be used for building bloom filter from clean files & also for creating yara signatures
```
usage: run.py [-h] [-n NAME] [-o OUTPUT] [-b] -s SOURCE [-ty THRESHOLDYARA]
              [-tf THRESHOLDFILE] [-m MAX] [-l LENGTHMIN] [-e EXTENSIONS]

optional arguments:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  name of the bloom filter file e.g. test.bf
  -o OUTPUT, --output OUTPUT
                        name of the yara rule
  -b, --build           build signature set
  -s SOURCE, --source SOURCE
                        source file/folder to process
  -ty THRESHOLDYARA, --thresholdyara THRESHOLDYARA
                        min percentage of strings to be matched to trigger
                        yara rule
  -tf THRESHOLDFILE, --thresholdfile THRESHOLDFILE
                        min percentage of files which have a string common
  -m MAX, --max MAX     maximum common strings to be considered for signature
                        generation
  -l LENGTHMIN, --lengthmin LENGTHMIN
                        minimum length of string
  -e EXTENSIONS, --extensions EXTENSIONS
                        file with given extensions will be used for creating
                        filter/signature
  
  e.g. 
  build bloom filter
  python run.py -b -n myfilter.bf -s c:\tmp
  This will generate byfilter.bf file
  
  gen yara rule
  python run.py -n myfilter.bf -s c:\malwares -m 10 -tf 50 -ty 50 -l 4 -e exe,dll -o myrule
  This will generate myrule.yara file (exe & dll extensions) using myfilter.bf as whitelist
  ```



