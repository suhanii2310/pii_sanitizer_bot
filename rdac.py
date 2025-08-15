#!/usr/bin/env python3

'''
Copyright (c) 2022 Cloudfabrix Software Inc. All rights reserved.

This program is a wrapper to setup docker based environment to run RDA Client command line tool.

Requirements to run this script:
- python3
- docker

To run:
   * Save this file as rdac.py and run using
   $ python3 rdac.py

   or

   $ cdmod +x rdac.py
   $ ./rdac.py

Change History:
   - Aug 25, 2022: Add docker log driver options
   - Aug 15, 2022: Fix issue with spaces in arguments
   - May 18, 2022: Initial Version

'''

import json
import os
import sys
import re
import platform

actual_config_path = None
user_data_path = None

def check_dependencies():
    global actual_config_path
    global user_data_path

    # Check OS
    osname = platform.system()
    print (f"Detected OS Name: {osname}")

    # Check for python  3
    if sys.version_info < (3, 0):
        print ("ERROR: This script should be run with any python3 environment.")
        print ()
        sys.exit(1)

    # Check for docker
    strm = os.popen("docker --version")
    verstr = strm.read()

    expr = "Docker version (.*),.*"
    m = re.match(expr, verstr)
    if not m:
        print ("Error: docker not detected on this system. Docker must be installed to run rdac command")
        sys.exit(1)
    
    print ("Detected docker version: {}".format(m.group(1)))

    # Check for RDA Configuration
    env_path = os.environ.get("RDA_NETWORK_CONFIG")
    if env_path:
        if not os.path.isfile(env_path):
            print (f"Error: file specified by ENV variable: RDA_NETWORK_CONFIG does not exist: {env_path}")
            print ()
            print ("RDA Configuration JSON file should be placed under your home directory path: ~/.rda/rda_network_config.json")
            print ("")
            print ("or ")
            print ("")
            print ("A path to that file must be specified using Env variable RDA_NETWORK_CONFIG")
            print ("")
            sys.exit(1)
        
        actual_config_path = env_path
        
    else:
        default_path = os.path.expanduser("~/.rda/rda_network_config.json")
        if not os.path.isfile(default_path):
            print (f"Error: RDA Configuration not found: {default_path}")
            print ()
            print ("RDA Configuration JSON file should be placed under your home directory path: ~/.rda/rda_network_config.json")
            print ("")
            print ("or ")
            print ("")
            print ("A path to that file must be specified using Env variable RDA_NETWORK_CONFIG")
            print ("")
            sys.exit(1)
        
        actual_config_path = default_path

    try:
        json.loads(open(actual_config_path).read())
    except Exception as e:
        print (e)
        print (f"Error: RDA Configuration file '{actual_config_path}' is not a valid JSON file")
        print ()
        sys.exit(1)
    
    user_data_path = os.path.expanduser('~/rdac_data/')
    if not os.path.isdir(user_data_path):
        print (f"Creating Data directory: {user_data_path}")
        try:
            os.makedirs(user_data_path)
        except:
            print (f"Error: Failed to create data directory: {user_data_path}")
            sys.exit(1)


    # do docker login
    if osname.lower() in [ "darwin", "linux" ]:
        command = "docker login -u=readonly -p='readonly' cfxregistry.cloudfabrix.io >/dev/null 2>&1"

        status = os.system(command)
        if status != 0:
            print ("Error: Failed to login to docker registry")
            print ("Make sure that")
            print ("  * Your docker daemon is running")
            print ("  * And you have network access to cfxregistry.cloudfabrix.io")
            print ()
            sys.exit(1)
    else:
        # to be added login for windows
        pass


def run():
    check_dependencies()

    args = sys.argv[1:]

    cwd = os.getcwd()
    mount1 = f"{actual_config_path}:/root/.rda/rda_network_config.json"
    mount2 = f"{user_data_path}:/data/"
    mount3 = f"{cwd}:/home/"
    image = "cfxregistry.cloudfabrix.io/ubuntu-rdac:daily"

    extra_args = ""

    if len(args) > 0:
        if args[0] == "update":
            print ("Updating docker image...")
            print ()
            status = os.system(f"docker pull {image}")
            if status != 0:
                print ("")
                print ("Failed to download latest docker image")
                sys.exit(1)
            sys.exit(0)

        if args[0] != "shell":
            fargs = []
            for a in args:
                
                #a = a.replace('"', '\\"').replace("'","\\'")
                #fargs.append(f'"{a}"')

                a = a.replace(' ', '\ ')
                fargs.append(a)

            extra_args = "rdac {}".format(' '.join(fargs))

    command = f"docker run --log-driver json-file --log-opt max-size=10m --log-opt max-file=5 --rm -it -v {mount1} -v {mount2} -v {mount3} {image} {extra_args}"
    os.system(command)



if __name__ == "__main__":
    run()