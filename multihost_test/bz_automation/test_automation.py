
import pytest
import subprocess
import os
import time
import paramiko
from sssd.testlib.common.utils import SSHClient
from sssd.testlib.common.expect import pexpect_ssh


def execute_cmd(multihost, command):
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.tier1
class TestPamBz(object):
    def test_read_faillock_conf_option(self, multihost, create_localusers):
        """
        :title: Faillock command does not read faillock.conf option
        :id: df4ef7e0-a754-11ec-8300-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1978029
        """
        execute_cmd(multihost, "yum install policycoreutils-python-utils")
        execute_cmd(multihost, "authselect select sssd --force")
        execute_cmd(multihost, "authselect enable-feature with-faillock")
        if "faillock" not in execute_cmd(multihost, "ls /var/log/").stdout_text:
            execute_cmd(multihost, "mkdir /var/log/faillock")
        multihost.client[0].run_command('semanage fcontext '
                                        '-a -t faillog_t '
                                        '"/var/log/faillock(/.*)?"',
                                        raiseonerr=False)
        execute_cmd(multihost, "restorecon -Rv /var/log/faillock")
        execute_cmd(multihost, "cp -vf /etc/security/faillock.conf "
                               "/etc/security/faillock.conf_bkp")
        execute_cmd(multihost, "echo 'dir = /var/log/faillock' >> "
                               "/etc/security/faillock.conf")
        # Make a wrong password attempt to generate logs
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            SSHClient(multihost.client[0].ip, username="local_anuj",
                      password="bad_pass")
        # Tests faillock with prefix --user
        assert 'V' in execute_cmd(multihost, "faillock --user local_anuj").stdout_text.split('\n')[2]
        # check --reset command without directory
        execute_cmd(multihost, "faillock --user local_anuj --reset")
        # check above command worked
        assert 'V' not in execute_cmd(multihost, "faillock --user local_anuj").stdout_text.split('\n')[2]
        # Make a wrong password attempt to generate logs after reset
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            SSHClient(multihost.client[0].ip, username="local_anuj",
                      password="bad_pass")
        # Tests faillock with prefix --dir and --user
        assert 'V' in execute_cmd(multihost, "faillock --dir "
                                             "/var/log/faillock "
                                             "--user local_anuj").stdout_text.split('\n')[2]
        # check --reset command with directory along with other prefixes
        execute_cmd(multihost, "faillock --dir "
                               "/var/log/faillock "
                               "--user local_anuj --reset")
        # check if command works again after reset
        assert 'V' not in execute_cmd(multihost, "faillock --dir "
                                             "/var/log/faillock "
                                             "--user local_anuj").stdout_text.split('\n')[2]
        # Just cleaning and restoring
        execute_cmd(multihost, "faillock --dir "
                               "/var/log/faillock --user "
                               "local_anuj --reset")
        execute_cmd(multihost, "cp -vf /etc/security/faillock.conf_bkp "
                               "/etc/security/faillock.conf")

    def test_cve_2010_3316(self, multihost, bkp_pam_config, compile_myxauth):
        """
        :title: CVE-2010-3316-pam_xauth-missing-return-value-checks-from-setuid
        :id: aebe751c-31b8-11ed-a91f-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=637898
        """
        TUSER = "pam-xauth-tester"
        SLOG = "/var/log/secure"
        execute_cmd(multihost, '> /tmp/xauthlog')
        execute_cmd(multihost, f"useradd {TUSER}")
        execute_cmd(multihost, "cp -f myxauth /myxauth")
        execute_cmd(multihost, 'sed -i "s/pam_xauth\.so/pam_xauth\.so '
                               'debug xauthpath=\/myxauth/g" /etc/pam.d/su')
        execute_cmd(multihost, 'echo "pam-xauth-tester    hard    nproc   '
                               '0" >> /etc/security/limits.conf')
        execute_cmd(multihost, 'mkdir -p /root/.xauth')
        execute_cmd(multihost, "echo '*' >> /root/.xauth/export")
        execute_cmd(multihost, f"id -u {TUSER}")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, f"DISPLAY=0:0 su - {TUSER} -c exit")
        time.sleep(3)
        execute_cmd(multihost, f"tail -n 11 {SLOG} | tee mktemp")
        for i in ["/tmp/myxauth.c", "myxauth"]:
            execute_cmd(multihost, f"rm -vf {i}")
        execute_cmd(multihost, 'rm -vfr /root/.xauth')
        execute_cmd(multihost, f"userdel -rf {TUSER}")
        assert int(execute_cmd(multihost, "cat /tmp/xauthlog | wc -l" ).stdout_text.split()[0]) >= 2

    def test_2082442(self, multihost, bkp_pam_config, create_localusers):
        """
        :title: pam_faillock prints "Consecutive login failures
         for user root account temporarily locked" without even_deny_root
        :id: c1802552-5151-11ed-b8c2-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2126648
                   https://bugzilla.redhat.com/show_bug.cgi?id=2082442
        """
        execute_cmd(multihost, "> /var/log/secure")
        ssh1 = SSHClient(multihost.client[0].ip, username="local_anuj", password="password123")
        for i in range(4):
            (result, result1, exit_status) = ssh1.execute_cmd('su -', stdin="password1234")
            assert "Password: su: Authentication failure" in result1.readlines()[0]
        assert "Consecutive login failures for user root account temporarily locked" \
               not in execute_cmd(multihost, "cat /var/log/secure").stdout_text

    def test_2091062(self, multihost, create_localusers):
        """
        :title: "error scanning directory" errors from pam_motd
        :id: 556ae15e-560b-11ed-850a-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2091062
        """
        execute_cmd(multihost, "> /var/log/secure")
        for dirc in ['/run/motd.d', '/etc/motd.d', '/usr/lib/motd.d']:
            execute_cmd(multihost, f"rm -vfr {dirc}")
        client = pexpect_ssh(multihost.client[0].sys_hostname,
                             "local_anuj", 'password123', debug=False)
        client.login(login_timeout=30, sync_multiplier=5, auto_prompt_reset=False)
        client.logout()
        assert "pam_motd: error scanning directory" not in \
               execute_cmd(multihost, "cat /var/log/secure").stdout_text

    def test_bcrypt_support(self, multihost, create_localusers, bkp_pam_config):
        """
        :title: Add support for bcrypt password hashes for local users
        :id: f25c7438-6db5-11ee-a613-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2218330
        :steps:
            1. Replace the string sha512 with blowfish in the /etc/pam.d/system-auth
                and /etc/pam.d/password-auth files.
            2. Set the password for the local_anuj.
            3. Checks that the hashed password starts with $2b$, which is a signature for the Blowfish algorithm
                (specifically the bcrypt version of Blowfish).
                If the password's hash doesn't start with this signature, the assertion will fail.
        :expectedresults:
            1. Should Success
            2. Should Success
            3. Should Success
        """
        client = multihost.client[0]
        client.run_command("sed -i s/sha512/blowfish/g /etc/pam.d/system-auth")
        client.run_command("sed -i s/sha512/blowfish/g /etc/pam.d/password-auth")
        client.run_command(f"echo password123 | passwd --stdin local_anuj")
        password = client.run_command("grep local_anuj /etc/shadow").stdout_text
        assert password.split(":")[1].startswith("$2b$")
