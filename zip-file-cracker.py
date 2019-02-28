#!/usr/bin/env python
# coding=utf-8
import zipfile
import optparse
from threading import Thread

def extractFile(zFile, password):
    try:
        
