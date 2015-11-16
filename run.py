import argparse
import os
import sys
import BloomAutoYara


def run(args):
  filter = BloomAutoYara.BloomAutoYara(args.name)
  if args.build == True:
    if os.path.isdir(args.source) == False:
      print "for building signature source should be dictionary"
      sys.exit()
    filter.build_filter(args.source,args.extensions.split(","))
  else:
    list = []
    if os.path.isdir(args.source) == True:
      topn = filter.find_dir_topn(args.source,args.max,args.lengthmin)
      for val,occ in topn:
        list.append(val)
    else:
      list = filter.find_file_topn(args.source,args.max,args.lengthmin)
    
    filter.list_to_rule(list,args.output,args.threshold)

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument("-n", "--name", default="test.bf",help="name of the bloom filter file e.g. test.bf")
  parser.add_argument("-o", "--output",default="testrule",help="name of the yara rule")
  parser.add_argument("-b", "--build", action="store_true", help="build signature set")
  parser.add_argument("-s", "--source", required=True, help="source file/folder to process")
  parser.add_argument("-t", "--threshold", type=float,default=0.5, help="threshold for percentage of signature strings to be matched")
  parser.add_argument("-m", "--max", type=int,default=15, help="maximum common strings to be considered for signature generation")
  parser.add_argument("-l", "--lengthmin", type=int,default=4,help="minimum length of string")
  parser.add_argument("-e", "--extensions", default=[],help="file with given extensions will be used for creating filter/signature")
  args = parser.parse_args()
  
  if len(sys.argv)==1:
    parser.print_help()
    sys.exit()
    
  run(args)
  
  


