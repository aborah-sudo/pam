
import pytest


def execute_cmd(multihost, command):
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.tier1
class TestPamBz(object):
    def test_unlimited(self, multihost):
        """
        :title: For nofile, a value of "unlimited" should be allowed.
        :id: 54d940a6-540d-11ec-9a01-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1989900
        """
        execute_cmd(multihost, "cp -vf /etc/security/limits.conf /tmp/limits.conf_anuj")
        user = "anuj_test"
        execute_cmd(multihost, "useradd anuj_test")
        execute_cmd(multihost, f"echo password123 | passwd --stdin {user}")
        execute_cmd(multihost, 'echo "anuj_test hard nofile -1" >> "/etc/security/limits.conf"')
        execute_cmd(multihost, "su -c 'id' anuj_test > /tmp/anuj")
        cmd = execute_cmd(multihost, "cat /tmp/anuj")
        for id_id in ['uid=', 'gid=', 'groups=', 'anuj_test']:
            assert id_id in cmd.stdout_text
        execute_cmd(multihost, "cp -vf /tmp/limits.conf_anuj /etc/security/limits.conf")
        execute_cmd(multihost, "userdel -rf anuj_test")
