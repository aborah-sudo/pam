
import pytest
import subprocess
import os


def exceute_cmd(multihost, command):
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.tier1
class TestPamBz(object):
    def test_chkpwd_onlyroot(self, multihost):
        """
        :title: This test checks whether unix_chkpwd
        doesn't allow other user's password guessing.
        :id: d3e88514-859a-11ec-bd05-845cf3eff344
        """
        exceute_cmd(multihost, "dnf -y install expect shadow-utils sed grubby")
        username1 = "testuser1"
        username2 = "testuser2"
        password = "tYnef*9sX"
        file_location1 = "/multihost_test/bz_automation/script/chkpwd-onlyroot_1.sh"
        file_location2 = "/multihost_test/bz_automation/script/chkpwd-onlyroot_2.sh"
        multihost.client[0].transport.put_file(os.getcwd() + file_location1, '/tmp/chkpwd-onlyroot_1.sh')
        multihost.client[0].transport.put_file(os.getcwd() + file_location2, '/tmp/chkpwd-onlyroot_2.sh')
        exceute_cmd(multihost, f"useradd {username1}")
        exceute_cmd(multihost, f"sh /tmp/chkpwd-onlyroot_1.sh {username1} {password}")
        exceute_cmd(multihost, f'useradd {username2}')
        exceute_cmd(multihost, f"sh /tmp/chkpwd-onlyroot_1.sh {username2} {password}")
        exceute_cmd(multihost, f"sh /tmp/chkpwd-onlyroot_2.sh {username1} {username1} {password}")
        exceute_cmd(multihost, f"sh /tmp/chkpwd-onlyroot_2.sh {username2} {username2} {password}")
        with pytest.raises(subprocess.CalledProcessError):
            exceute_cmd(multihost, f"sh /tmp/chkpwd-onlyroot_2.sh {username1} {username2} {password}")
        exceute_cmd(multihost, f"userdel -rf {username1}")
        exceute_cmd(multihost, f"userdel -rf {username2}")

    def test_bz675835(self, multihost, create_localusers):
        """
        :title: bz675835-RFE-Please-support-nodefgroup-in-pam-access
        :id: a9c10cf2-85c7-11ec-9ed5-845cf3eff344
        """
        exceute_cmd(multihost, "yum install -y expect")
        exceute_cmd(multihost, "yum install -y openssh")
        file_location1 = "/multihost_test/bz_automation/script/bz675835.sh"
        file_location2 = "/multihost_test/bz_automation/script/bz675835_1.sh"
        multihost.client[0].transport.put_file(os.getcwd() + file_location1, '/tmp/bz675835.sh')
        multihost.client[0].transport.put_file(os.getcwd() + file_location2, '/tmp/bz675835_1.sh')
        exceute_cmd(multihost, "sed -i '/^account.*/i account required pam_access.so nodefgroup' /etc/pam.d/sshd")
        exceute_cmd(multihost, "echo 'account required pam_access.so nodefgroup' >> /etc/pam.d/sshd")
        exceute_cmd(multihost, "usermod -a -G testgroup local_anuj")
        exceute_cmd(multihost, "usermod -a -G testgroup pamtest1")
        exceute_cmd(multihost, "sh /tmp/bz675835_1.sh")
        exceute_cmd(multihost, 'echo "-:testgroup:ALL" > /etc/security/access.conf')
        exceute_cmd(multihost, "sh /tmp/bz675835.sh local_anuj x")
        exceute_cmd(multihost, "sh /tmp/bz675835.sh pamtest1 x")
        exceute_cmd(multihost, 'echo "-:(testgroup):ALL" > /etc/security/access.conf')
        with pytest.raises(subprocess.CalledProcessError):
            exceute_cmd(multihost, "sh /tmp/bz675835.sh local_anuj x")
        with pytest.raises(subprocess.CalledProcessError):
            exceute_cmd(multihost, "sh /tmp/bz675835.sh pamtest1 x")
