"""conftest.py for pam"""

from __future__ import print_function
import subprocess
import pytest
import time
import ldap
import posixpath
import os
import random
from pytest_multihost import make_multihost_fixture
from sssd.testlib.common.qe_class import session_multihost
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF
from sssd.testlib.common.utils import PkiTools, sssdTools, LdapOperations
from sssd.testlib.common.libdirsrv import DirSrvWrap
from sssd.testlib.common.exceptions import PkiLibException, LdapException
from sssd.testlib.common.libkrb5 import krb5srv


def pytest_configure():
    """ Namespace hook to add below dict in the pytest namespace """
    pytest.num_masters = 1
    pytest.num_ad = 0
    pytest.num_atomic = 0
    pytest.num_replicas = 0
    pytest.num_clients = 1
    pytest.num_others = 0


@pytest.fixture(scope="class")
def multihost(session_multihost, request):
    """ Multihost fixture to be used by tests """
    if hasattr(request.cls(), 'class_setup'):
        request.cls().class_setup(session_multihost)
        request.addfinalizer(
            lambda: request.cls().class_teardown(session_multihost))
    return session_multihost


@pytest.fixture(scope='function')
def backupsssdconf(session_multihost, request):
    """ Backup and restore sssd.conf """
    bkup = 'cp -f %s %s.orig' % (SSSD_DEFAULT_CONF,
                                 SSSD_DEFAULT_CONF)
    session_multihost.client[0].run_command(bkup)
    session_multihost.client[0].service_sssd('stop')

    def restoresssdconf():
        """ Restore sssd.conf """
        restore = 'cp -f %s.orig %s' % (SSSD_DEFAULT_CONF, SSSD_DEFAULT_CONF)
        session_multihost.client[0].run_command(restore)
    request.addfinalizer(restoresssdconf)

