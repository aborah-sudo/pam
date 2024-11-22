"""
PAM Test Cases

:requirement: pam
:casecomponent: pam
:subsystemteam: sst_idm_sssd
:status: approved
"""


import pytest
import subprocess
import os
import time


def execute_cmd(multihost, command):
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.mark.tier1
class TestPamPwquality(object):
    def test_simple_test_system_auth(self, multihost, bkp_pam_config, create_localusers):
        """Sanity tests for pam_pwquality.so minlen, dcredit, ucredit, lcredit, ocredit

        :id: e30c75be-eaf9-11eb-9781-845cf3eff344
        """
        client = multihost.client[0]
        execute_cmd(multihost, 'yum install -y expect')
        assert 'password' in execute_cmd(multihost,
                                         "grep system-auth "
                                         "/etc/pam.d/passwd").stdout_text
        execute_cmd(multihost, "echo pass | passwd --stdin local_anuj")
        execute_cmd(multihost, "sed -i 's/.*pam_pwquality.*/password  "
                               "requisite pam_pwquality.so try_first_pass "
                               "local_users_only enforce_for_root/'  "
                               "/etc/pam.d/system-auth")
        # Is the new password just the old password with the letters
        # reversed ("password" vs. "drowssap") or
        # rotated ("password" vs. "asswordp")
        assert "error" in client.run_command(
            "echo ssap | passwd --stdin local_anuj", raiseonerr=False).stderr_text
        # Does the new password only differ from the
        # old one due to change of case
        # ("password" vs. "Password")?
        assert "error" in client.run_command(
            "echo PASS | passwd --stdin local_anuj", raiseonerr=False).stderr_text
        execute_cmd(multihost, "sed -i 's/.*pam_pwquality.*/password "
                               "requisite pam_pwquality.so try_first_pass "
                               "retry=3 minlen=9 dcredit=-1 ucredit=-1 "
                               "lcredit=-1 ocredit=-1 type= enforce_for_root/' "
                               "/etc/pam.d/system-auth")
        # bad pass minlen < 9, dcredit < 1, ucredit < 1, lcredit < 1, ocredit < 1
        for password in ["pass", "Passdonew#", "passdonewt1#", "PASSWORDU1#", "PassdonewO1"]:
            command = client.run_command(
                f"echo {password} | passwd --stdin local_anuj", raiseonerr=False).stderr_text
            assert "failed" in command or "exhausted" in command
        # right password
        execute_cmd(multihost, f"echo Pass#donew1 | passwd --stdin local_anuj")

    def test_pam_retry_difok(self, multihost, bkp_pam_config, create_localusers):
        """Sanity tests for pam_pwquality.so with difok, retry

        :id: e7c4db96-eaf9-11eb-8fbb-845cf3eff344
        """
        execute_cmd(multihost, "rm -vfr /tmp/anuj")
        execute_cmd(multihost, "echo pass | passwd --stdin local_anuj")
        execute_cmd(multihost, "sed -i 's/.*pam_pwquality.*/password   "
                               "requisite pam_pwquality.so authtok_type=PAMTEST "
                               "enforce_for_root/'  /etc/pam.d/system-auth")
        file_location = "/multihost_test/bz_automation/script/pam_pwquality.sh"
        multihost.client[0].transport.put_file(os.getcwd() +
                                               file_location,
                                               '/tmp/pam_pwquality.sh')
        execute_cmd(multihost, "chmod 755 /tmp/pam_pwquality.sh")
        execute_cmd(multihost, "sh /tmp/pam_pwquality.sh  "
                               "local_anuj pass R3dh4T1nC R3dh4T1nC > /tmp/anuj")
        assert "New PAMTEST password" in execute_cmd(multihost,
                                                     "cat /tmp/anuj").stdout_text
        assert "Retype new PAMTEST password" in execute_cmd(multihost,
                                                            "cat /tmp/anuj").stdout_text
        execute_cmd(multihost, "sed -i 's/.*pam_pwquality.*/password   "
                               "requisite pam_pwquality.so retry=1 enforce_for_root/'  "
                               "/etc/pam.d/system-auth")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/pam_pwquality.sh  "
                                   "local_anuj R3dh4T1nC k4ddL32rfg NOPASS")
        execute_cmd(multihost, "sed -i 's/.*pam_pwquality.*/password   "
                               "requisite pam_pwquality.so retry=2 enforce_for_root/'  "
                               "/etc/pam.d/system-auth")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/pam_pwquality.sh  "
                                   "local_anuj R3dh4T1nC k4ddL32rfg NOPASS")
        execute_cmd(multihost, "sed -i 's/.*pam_pwquality.*/password   "
                               "requisite pam_pwquality.so retry=1 difok=3 enforce_for_root/'  "
                               "/etc/pam.d/system-auth")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/pam_pwquality.sh  "
                                   "local_anuj R3dh4T1nC aR3dh4T1nCb aR3dh4T1nCb")
        execute_cmd(multihost, "sh /tmp/pam_pwquality.sh  "
                               "local_anuj R3dh4T1nC aR3dh4T1nCbD aR3dh4T1nCbD")
        execute_cmd(multihost, "sed -i 's/.*pam_pwquality.*/password   "
                               "requisite pam_pwquality.so retry=1 minlen=5 enforce_for_root/'  "
                               "/etc/pam.d/system-auth")
        execute_cmd(multihost, "sh /tmp/pam_pwquality.sh  "
                               "local_anuj aR3dh4T1nCbD jf@#FafR3dh4T1nC!!F jf@#FafR3dh4T1nC!!F")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/pam_pwquality.sh  "
                                   "local_anuj jf@#FafR3dh4T1nC!!F 3214 3214")

    def test_pam_gecoscheck(self, multihost, bkp_pam_config, create_localusers):
        """Sanity tests for pam_pwquality.so gecoscheck

        :id: 60afc548-f063-11eb-9639-845cf3eff344
        """
        # Test gecoscheck parameter
        execute_cmd(multihost, "echo pamtest1 | passwd --stdin pamtest1")
        execute_cmd(multihost, "usermod -c 'Karci' pamtest1")
        execute_cmd(multihost, "pinky -l pamtest1")
        execute_cmd(multihost, "sed -i 's/.*pam_pwquality.*/password    "
                               "required pam_pwquality.so "
                               "gecoscheck=1 enforce_for_root/' "
                               "/etc/pam.d/system-auth")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/pam_pwquality.sh  "
                                   "pamtest1 pamtest1 KarciMir4 KarciMir4")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/pam_pwquality.sh  "
                                   "pamtest1 pamtest1 rYb4aicraK rYb4aicraK")

    def test_pam_maxclassrepeat(self, multihost, bkp_pam_config, create_localusers):
        """Sanity tests for pam_pwquality.so maxclassrepeat

        :id: f8ba83e6-f063-11eb-b434-845cf3eff344
        """
        # Test maxclassrepeat parameter
        execute_cmd(multihost, "echo R3dh4T1nC | passwd --stdin local_anuj")
        execute_cmd(multihost, "sed -i 's/.*pam_pwquality.*/password   "
                               "requisite pam_pwquality.so maxclassrepeat=2 enforce_for_root/'  "
                               "/etc/pam.d/system-auth")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/pam_pwquality.sh  "
                                   "local_anuj R3dh4T1nC jjjfGGjjFDFdj!@32 jjjfGGjjFDFdj!@32")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/pam_pwquality.sh  "
                                   "local_anuj R3dh4T1nC fG333GjjFDFdj!@32 fG333GjjFDFdj!@32")
        with pytest.raises(subprocess.CalledProcessError):
            execute_cmd(multihost, "sh /tmp/pam_pwquality.sh  "
                                   "local_anuj R3dh4T1nC fG33GjjFDFd!@@@32 fG33GjjFDFd!@@@32")

    def test_bz_769694(self, multihost,
                       bkp_pam_config,
                       create_localusers):
        """RFE-Adding-the-size-option-for-tmpfs

        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=769694
        :id: 925dc91c-39b6-11ed-b859-845cf3eff344
        """
        execute_cmd(multihost, "echo 'session required pam_namespace.so'"
                               " >> /etc/pam.d/system-auth")
        execute_cmd(multihost, "echo '/dev/shm tmpfs tmpfs:mntopts=size=20M'"
                               " >>/etc/security/namespace.conf")
        root_shm = execute_cmd(multihost, "df -lh |grep '/dev/shm'"
                                          " |awk '{print $2}'").stdout_text.split()[0]
        user_shm = execute_cmd(multihost, "su -l -c 'df -lh'"
                                          " - local_anuj |grep '/dev/shm' | "
                                          "awk '{print $2}'").stdout_text.split()[0]
        assert user_shm == '20M'
        assert root_shm != user_shm
