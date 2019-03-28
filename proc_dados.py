#!/usr/bin/env python

import pandas as pd
import sys

df = pd.read_csv(str(sys.argv[1])+".txt", sep=" ", names=['data','horario','src', 'dst', 'len','proto','mac_src','mac_dst'])

df.dropna()

print(df.groupby(['proto','src','dst'])['len'].sum())




