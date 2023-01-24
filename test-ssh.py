# use paramiko to create a ssh connection and test it

import argparse
import paramiko
import time
from paramiko import SSHClient, AutoAddPolicy, RSAKey
from io import StringIO, BytesIO
import os

def ssh_connect_private_key(ip_address, username, ssh_key, ssh_port,passphrase=None, timeout=None):
    try:
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        private_key = StringIO(ssh_key)
        ssh_client.connect(
            hostname=ip_address,
            username=username,
            pkey=RSAKey.from_private_key(private_key,password=passphrase), 
            passphrase=passphrase,
            look_for_keys=False,
            timeout=timeout,
            port=ssh_port
            )
            
        print("Connected to ssh client using key")
        return ssh_client
    except Exception as ex:
        print("Error connecting to ssh client using key. Exception: %s",str(ex))
        return None

def ssh_connect_password(ip_address, username, password, ssh_port, timeout=None):
    try:
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        ssh_client.connect(
            hostname=ip_address,
            username=username,
            password=password,
            look_for_keys=False,
            timeout=timeout,
            port=ssh_port
            )
            
        print("Connected to ssh client using password")
        return ssh_client
    except Exception as ex:
        print("Error connecting to ssh client using password. Exception: %s",str(ex))
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Automation script for secops cli')
    parser.add_argument('-ip','--ip_address', action='store', help='ip_address',default=None)
    parser.add_argument('-u', '--username', help='username', action='store', default=None)
    parser.add_argument('-p', '--port', help='port', action='store', default=22)
    parser.add_argument('-k', '--key', help='key', action='store', default=None)
    parser.add_argument('-ph', '--passphrase', help='passphrase', action='store', default=None)
    parser.add_argument('-pw', '--password', help='password', action='store', default=None)
    args, unknown = parser.parse_known_args()

    if args.ip_address:
        print("IP address: %s" % args.ip_address)
    if args.username:
        print("Username: %s" % args.username)
    if args.port:
        print("Port: %s" % args.port)
    # check if key exists on disk
    if args.key:
        if not os.path.exists(args.key):
            print("Key file does not exist")
            exit(1)
        else:
            print("Reading key from file")
            with open(args.key, 'r') as f:
                args.key = f.read()
            print("SSH key found")


    if not args.ip_address or not args.username:
        print("Please provide ip_address and username")
        exit(1)
    if args.password:
        ssh_client = ssh_connect_password(args.ip_address, args.username, args.password, args.port)
    else:
        ssh_client = ssh_connect_private_key(args.ip_address, args.username, args.key, args.port, args.passphrase)

    if ssh_client is not None:
        print("SSH connection successful")
        ssh_client.close()
    else:
        print("SSH connection failed")

