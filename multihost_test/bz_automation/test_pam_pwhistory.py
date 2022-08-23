
import pytest
import subprocess


def execute_cmd(multihost, command):
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.tier1
class TestPamBz(object):
    def test_2068461(self, multihost, create_localusers, bkp_pam_config):
        """
        :title: RFE allow to configure pam_pwhistory with configuration file.
        :id: 47e71a8e-2203-11ed-968a-845cf3eff344
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=2068461
        """
        execute_cmd(multihost, "sed -i "
                               "'x;/./{x;b};x;/password/h;"
                               "//ipassword\trequired\tpam_pwhistory.so' "
                               "/etc/pam.d/system-auth")
        for data in ['remember = 3', 'enforce_for_root']:
            execute_cmd(multihost, f"echo {data} >> /etc/security/pwhistory.conf")
        # Try same password continually
        execute_cmd(multihost, f"echo x86_64_baseos_rpms | passwd --stdin local_anuj")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, f"echo x86_64_baseos_rpms | passwd --stdin local_anuj")
        # Try same password after 2nd time
        for passwd in ['x86#64#baseos#rpms',
                       'x86^64^baseos^rpms']:
            execute_cmd(multihost, f"echo {passwd} | passwd --stdin local_anuj")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, f"echo x86#64#baseos#rpms | passwd --stdin local_anuj")
        # Try same password after 3rd time
        for passwd in ['HI_I_AM_ANUJ',
                       'HI#I#AM#ANUJ',
                       'HI^I^AM^ANUJ']:
            execute_cmd(multihost, f"echo {passwd} | passwd --stdin local_anuj")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, f"echo HI_I_AM_ANUJ | passwd --stdin local_anuj")
        # Try same password after 4th time
        for passwd in ['ANUJ_AM_I_HI',
                       'ANUJ#AM#I#HI',
                       'ANUJ^AM^I^HI',
                       'x86_64_baseos_rpms',
                       'ANUJ_AM_I_HI']:
            execute_cmd(multihost, f"echo {passwd} | passwd --stdin local_anuj")
