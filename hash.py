#!/usr/bin/env python
# coding=utf-8
# -*- coding:utf-8 -*-

import hashlib

def md5(s):
    # 字符串编码为utf-8
    return hashlib.md5(s.encode('utf-8')).hexdigest()

if __name__ == '__main__':

    for i in range(1, 999999):  # 范围
        if md5(str(i)).startswith('f8b98f'):  # 待爆破的字符串
            print(i)
