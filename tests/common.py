import os, sys, inspect
ourfilename = os.path.abspath(inspect.getfile(inspect.currentframe()))
currentdir = os.path.dirname(ourfilename)
parentdir = os.path.dirname(currentdir)
src=os.path.join(parentdir,"src")
if src not in sys.path:
    sys.path.insert(0, src)