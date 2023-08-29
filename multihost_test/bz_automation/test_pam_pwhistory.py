
import pytest
import subprocess
import os


def execute_cmd(multihost, command):
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.tier1
class TestPamBz(object):
    def test_pwhistory_enforces_root(self, multihost, bkp_pam_config, create_localusers):
        """
        :title: bz824858-pam-pwhistory-enforces-root-to-password-change
        :id: e7c4db96-eaf9-11eb-8fbb-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=824858
        """
        _PASSWORD = "01_pass_change_01"
        _PASSWORD2 = "02_change_pass_02"
        _PASSWORD3 = "03_aother_pass_03"
        _PASSWORD4 = "04_yet_new_pass_04"
        execute_cmd(multihost, "cat /etc/pam.d/system-auth > /tmp/system-auth")
        execute_cmd(multihost, "rm -f /etc/security/opasswd")
        execute_cmd(multihost, "touch /etc/security/opasswd")
        execute_cmd(multihost, "chown root:root /etc/security/opasswd")
        execute_cmd(multihost, "chmod 600 /etc/security/opasswd")
        execute_cmd(multihost, "echo R3dh4T1nC | passwd --stdin pamtest1")
        execute_cmd(multihost, "> /etc/security/opasswd")
        execute_cmd(multihost, "sed -i -e 's/^password\s\+sufficient\s\+pam_unix.so/password"
                               "    requisite     pam_pwhistory.so remember=3 "
                               "use_authtok enforce_for_root\\n\\0/'  "
                               "/etc/pam.d/system-auth")
        file_location = "/multihost_test/bz_automation/script/bz824858.sh"
        multihost.client[0].transport.put_file(os.getcwd() +
                                               file_location,
                                               '/tmp/bz824858.sh')
        for i in [_PASSWORD, _PASSWORD2, _PASSWORD3]:
            execute_cmd(multihost, f"sh /tmp/bz824858.sh pamtest1 {i}")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, f"sh /tmp/bz824858.sh pamtest1 {_PASSWORD}")
        execute_cmd(multihost, "echo R3dh4T1nC | passwd --stdin pamtest1")
        execute_cmd(multihost, "> /etc/security/opasswd")
        execute_cmd(multihost, "cat /tmp/system-auth > /etc/pam.d/system-auth")
        execute_cmd(multihost, "sed -i -e 's/^password\s\+sufficient\s\+pam_unix.so/password"
                               "    requisite     pam_pwhistory.so remember=3 use_authtok\\n\\0/'  "
                               "/etc/pam.d/system-auth")
        for i in [_PASSWORD, _PASSWORD2, _PASSWORD3, _PASSWORD4, _PASSWORD]:
            execute_cmd(multihost, f"sh /tmp/bz824858.sh pamtest1 {i}")
