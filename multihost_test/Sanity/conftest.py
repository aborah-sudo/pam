from __future__ import print_function
import subprocess
import pytest
import time
import ldap
import random
from pytest_multihost import make_multihost_fixture
from sssd.testlib.common.qe_class import session_multihost
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF


def pytest_configure():
    """ Namespace hook to add below dict in the pytest namespace """
    pytest.num_masters = 0
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


@pytest.fixture(scope='function')
def create_localusers(session_multihost, request):
    """ create users for test """
    session_multihost.client[0].run_command("cp -vf /etc/pam.d/system-auth "
                                            "/etc/pam.d/system-auth_anuj")
    session_multihost.client[0].run_command("useradd local_anuj")
    session_multihost.client[0].run_command("useradd pamtest1")

    def restore_conf():
        """ Restore """
        session_multihost.client[0].run_command("cp -vf /etc/pam.d/system-auth_anuj "
                                                "/etc/pam.d/system-auth")
        session_multihost.client[0].run_command("userdel -rf local_anuj")
        session_multihost.client[0].run_command("userdel -rf pamtest1")

    request.addfinalizer(restore_conf)