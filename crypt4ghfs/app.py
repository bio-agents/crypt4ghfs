#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import logging
from logging.config import dictConfig
import argparse
from funcagents import partial
from getpass import getpass
from configparser import RawConfigParser

import pyfuse3
import trio
from crypt4gh.keys import get_private_key, get_public_key
from nacl.public import PrivateKey

from .operations import Crypt4ghFS

try:
    import faulthandler
    # See https://docs.python.org/3.8/library/faulthandler.html
except ImportError:
    pass
else:
    faulthandler.enable()

LOG = logging.getLogger(__name__)


DEFAULT_LOG_HANDLER = "default"

def load_logger(level: "int", include_crypt4gh: "bool" = False, logfile: "Optional[str]" = None, is_foreground: "bool" = False) -> "None":
    assert( level ), "You must pass a Python logging level"
    loggers = {
        'crypt4ghfs': {
            'level': level,
            'handlers': [
                DEFAULT_LOG_HANDLER,
            ],
            'propagate': True
        },
        # 'pyfuse3': {'level': level,
        #             'handlers': [DEFAULT_LOG_HANDLER],
        #             'propagate': True },
        # 'trio': {'level': level,
        #          'handlers': [DEFAULT_LOG_HANDLER],
        #          'propagate': True },
    }
    if include_crypt4gh:
        loggers['crypt4gh'] = {
            'level': level,
            'handlers': [
                DEFAULT_LOG_HANDLER,
            ],
            'propagate': True
        }
    if logfile is not None:
        default_handler = {
            'class': 'logging.FileHandler',
            'formatter': 'simple',
            'filename': logfile,
        }
    elif is_foreground:
        default_handler = {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
            'stream': 'ext://sys.stderr'
        }
    else:
        default_handler = {
            'class': 'logging.SysLogHandler',
            'formatter': 'simple',
            'address': '/dev/log',
            'facility': 'local7',
        }

    dictConfig({
        'version': 1,
        'root': {
            'level': 'NOTSET',
            'handlers': [
                'noHandler'
            ]
        },
        'loggers': loggers,
        'handlers': {
            'noHandler': {
                'class': 'logging.NullHandler',
                'level': 'NOTSET'
            },
            DEFAULT_LOG_HANDLER: default_handler,
        },
        'formatters': {'simple': {'format': '[{name:^10}][{levelname:^6}] (L{lineno}) {message}',
                                  'style': '{'},
        }
    })

def retrieve_secret_key(conf):
    seckey = conf.get('CRYPT4GH', 'seckey')
    seckeypath = os.path.expanduser(seckey)
    LOG.info('Loading secret key from %s', seckeypath)
    if not os.path.exists(seckeypath):
        raise ValueError('Secret key not found')

    passphrase = os.getenv('C4GH_PASSPHRASE')
    if passphrase:
        #LOG.warning("Using a passphrase in an environment variable is insecure")
        print("Warning: Using a passphrase in an environment variable is insecure", file=sys.stderr)
        cb = lambda : passphrase
    else:
        cb = partial(getpass, prompt=f'Passphrase for {seckey}: ')

    return get_private_key(seckeypath, cb)


def check_perms_ok(conf_file):
    st = os.lstat(conf_file) # raise error if not found
    if st.st_uid == os.getuid() and st.st_mode & 0o077 != 0:
        print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", file=sys.stderr)
        print("@        WARNING: UNPROTECTED CONFIGURATION FILE!         @", file=sys.stderr)
        print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@", file=sys.stderr)
        print("Permissions {:3o} for '{}' are too open.".format(st.st_mode & 0o777, conf_file), file=sys.stderr)
        print("It is required that your private key files are NOT accessible by others.", file=sys.stderr)
        print("This private key will be ignored.", file=sys.stderr)
        raise ValueError(f'Bad permissions for {conf_file}')

def parse_options() -> "Tuple[str, RawConfigParser, bool]":
    parser = argparse.ArgumentParser(description='Crypt4GH filesystem')
    parser.add_argument('mountpoint', help='mountpoint for the Crypt4GH filesystem')
    parser.add_argument('--conf', help='configuration file', default='~/.c4gh/fs.conf')
    parser.add_argument('-f', '--foreground', action='store_true', help='do not deamonize and keep in the foreground', default=False)
    parser.add_argument('-l', '--logfile', help='Send log messages to this file instead of the defaults')

    args = parser.parse_args()

    # Mountpoint
    mountpoint = os.path.expanduser(args.mountpoint)
    if not os.path.exists(mountpoint):
        raise ValueError(f'Mountpoint {mountpoint} does not exist')

    # Load configuration file
    conf_file = os.path.expanduser(args.conf)
    check_perms_ok(conf_file)
    conf = RawConfigParser(converters={
        'barlist': lambda value: set(value.split('|')), # bar-separated
        'set': lambda value: set(value.split(',')),
    })
    conf.read([conf_file], encoding='utf-8')

    # Logging
    log_level = conf.get('DEFAULT', 'log_level', fallback=None)
    include_crypt4gh_log = conf.getboolean('DEFAULT', 'include_crypt4gh_log', fallback=False)
    if log_level is not None:
        load_logger(log_level, include_crypt4gh=include_crypt4gh_log, logfile=args.logfile, is_foreground=args.foreground)

    return (mountpoint, conf, args.foreground)


def _main():

    # Parse the arguments
    mountpoint, conf, foreground = parse_options()

    LOG.info('Mountpoint: %s', mountpoint)

    # Required configurations
    rootdir = conf.get('DEFAULT', 'rootdir')
    if not rootdir:
        raise ValueError('Missing rootdir configuration')
    rootdir = os.path.expanduser(rootdir)
    if not os.path.exists(rootdir):
        raise ValueError(f'Rootdir {rootdir} does not exist')
    LOG.info('Root dir: %s', rootdir)
    rootfd = os.open(rootdir, os.O_PATH | os.O_NOFOLLOW)

    # Encryption/Decryption keys
    seckey = retrieve_secret_key(conf)

    # Default configurations
    options = conf.getset('FUSE', 'options', fallback='ro,default_permissions')
    LOG.debug('mount options: %s', options)

    extension = conf.get('DEFAULT', 'extension', fallback='.c4gh')

    header_size_hint = conf.getint('CRYPT4GH', 'header_size_hint', fallback=0)
    assume_same_size_headers = conf.getboolean('CRYPT4GH', 'assume_same_size_headers', fallback=True)

    # Build the file system
    fs = Crypt4ghFS(rootdir, rootfd, seckey,
                    extension, header_size_hint, assume_same_size_headers)
    pyfuse3.init(fs, mountpoint, options)

    if not foreground:
        LOG.info('Running current process in background')
        detach() # daemonize

    try:
        LOG.debug('Entering main loop')
        trio.run(pyfuse3.main)
        # This is an infinite loop.
        # Ctrl-C / KeyboardInterrupt will be propagated (properly?)
        # - https://trio.readthedocs.io/en/stable/reference-core.html
        # - https://vorpus.org/blog/control-c-handling-in-python-and-trio/
    except Exception as e:
        LOG.debug("%r", e)
        raise
    finally:
        LOG.debug('Unmounting')
        pyfuse3.close(unmount=True)

    # The proper way to exit is to call:
    # umount <the-mountpoint>
    return 0


def detach(umask=0):
    '''PEP 3143
    https://www.python.org/dev/peps/pep-3143/#correct-daemon-behaviour
    https://daemonize.readthedocs.io/en/latest/_modules/daemonize.html#Daemonize
    '''
    try:
        LOG.info('Forking current process, and exiting the parent')
        pid = os.fork()
        if pid > 0:  # make the parent exist
            os._exit(0)
    except OSError as err:
        print('fork failed:', err, file=sys.stderr)
        sys.exit(1)

    # decouple from parent environment
    LOG.info('decouple from parent environment')
    os.setsid()
    pid = os.fork()
    if pid:
        os._exit(0)
    os.chdir('/')
    os.umask(umask)

    # redirect standard file descriptors
    LOG.info('redirect standard file descriptors')
    sys.stdout.flush()
    sys.stderr.flush()
    si = open(os.devnull, 'r')
    so = open(os.devnull, 'a+')
    se = open(os.devnull, 'a+')
    
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


def main():
    try:
        sys.exit(_main())
    except Exception as e:
        LOG.error('%s', e)
        LOG.exception("Stack")
        sys.exit(1)

