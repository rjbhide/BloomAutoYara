from pybloom import ScalableBloomFilter
import sys
import re
import os
from collections import Counter

class BloomAutoYara:
  def __init__(self,filterfile):
    self.filterfile = filterfile
	  #if filterfile is present load bloom filter from that file, else create new one
    if os.path.exists(filterfile):
      self.bf = ScalableBloomFilter.fromfile(open(filterfile,"rb"))
      print "available signatures = %d"%len(self.bf)
    else:
      self.bf = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH)

  def save_filter(self):
    print "saving filter to file %s "%self.filterfile
    self.bf.tofile(open(self.filterfile,"wb"))

  def add_string(self,str):
    self.bf.add(str)

  def search_string(self,str):
    if str in self.bf:
      return True
    else:
      return False

  def extractlines(self,filename,min_len=4):
    chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
    shortest_run = 4
    regexp = '[%s]{%d,}' % (chars, shortest_run)
    pattern = re.compile(regexp)
    fp = open(filename,"rb")
    data = fp.read()
    lines = pattern.findall(data)
    s = set(lines)
    fp.close()
    return list(s)
   
  def build_filter(self,dirname,extensions=[]):
    print extensions
    total = 0
    for (dir, _, files) in os.walk(dirname):
      for f in files:
        ext = f.split(".")[-1]
        
        if len(extensions) != 0 and ext not in extensions:
          continue
          
        print "processing file %s"%f
        total += 1
        path = os.path.join(dir, f)
        lines = self.extractlines(path)
        for line in lines:
          self.add_string(line)
  
    print "creating bloom filter done. Total files = %d (Total entries = %d). Overwriting to bloom filter output file %s"%(total,len(self.bf),self.filterfile)
    self.save_filter()
    
  def find_file_topn(self,filename,topn=10):
    tmp = []
    lines = self.extractlines(filename)
    print "total unique strings in file %s = %d"%(filename,len(lines))
    for line in lines:
      if self.search_string(line) == False:
        tmp.append(line)
    tmp.sort(key=len)
    print "total strings which can be used for signature = %d"%len(tmp)
    tmp = tmp[-topn:]
    tmp.reverse()
    return tmp
    
  def find_dir_topn(self,dirname,topn=10):
    tmplist = []
    for (dir, _, files) in os.walk(dirname):
      for f in files:
        path = os.path.join(dir, f)
        lines = self.extractlines(path)
        for line in lines:
          if self.search_string(line) == False:
            tmplist.append(line) 
    
    counts = Counter(list(tmplist))
    return counts.most_common(topn)

  def escapechars(self,str):
    for c in "\/.^$*+-?()[]{}|":
      str = str.replace(c,"\\"+c)
    return str
    
  def list_to_rule(self,list,rulename,threshold=0.5):
    tmp = "rule " + rulename + "{\n"
    tmp += " strings:\n"
    
    for i in xrange(0,len(list)):
      esc = self.escapechars(list[i])
      tmp = tmp + "$str%d = "%i + r"/[^A-Za-z0-9\/\-:.,_$%'()\[\]<> ]" + esc + r"[^A-Za-z0-9\/\-:.,_$%'()\[\]<> ]/"
      tmp += "\n"
    
    tmp += "condition:\n"
    tmp += str(int(len(list)*threshold))
    tmp += " of ("
    for i in xrange(0,len(list)):
      tmp += "$str"+ str(i)
      if i != (len(list) - 1):
        tmp += ","
    
    tmp += ")\n}"
    
    print "rule = %s.yara is written to disk "%rulename
    fp = open(rulename+".yara","w")
    fp.write(tmp)
    fp.close()
    
