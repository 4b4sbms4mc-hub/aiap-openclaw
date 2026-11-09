# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import subprocess
import unittest


class StaticSSHDInventoryTests(unittest.TestCase):
    script = Path(__file__).resolve().parents[1] / 'inspect_sshd_config_static.awk'

    def inventory(self, text):
        result = subprocess.run(['awk', '-f', str(self.script)], input=text,
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_case_whitespace_equals_multiple_paths_and_quoted_comment(self):
        output = self.inventory(' # ignored\n  PuBkeyAuthentication = yes # PRIVATE_COMMENT\n'
                                'AuthorizedKeysFile=".ssh/first#key" .ssh/second # SECRET\n'
                                'AuthenticationMethods publickey,password publickey,keyboard-interactive\n')
        self.assertIn('2 pubkeyauthentication yes\n', output)
        self.assertIn('authorizedkeysfile ".ssh/first#key" .ssh/second\n', output)
        self.assertIn('publickey,password publickey,keyboard-interactive', output)
        self.assertNotIn('SECRET', output)
        self.assertNotIn('PRIVATE_COMMENT', output)

    def test_commands_environment_and_private_block_are_redacted(self):
        output = self.inventory('AuthorizedKeysCommand /secret --token=COMMAND_SECRET\n'
                                'ForceCommand none\nSetEnv KEY=ENV_SECRET\n'
                                'HostKey /PRIVATE_HOST_KEY\n'
                                '-----BEGIN OPENSSH PRIVATE KEY-----\n'
                                'AuthorizedKeysFile PRIVATE_KEY_CONTENT\n'
                                '-----END OPENSSH PRIVATE KEY-----\n'
                                'StrictModes yes\n')
        self.assertIn('authorizedkeyscommand_present yes', output)
        self.assertIn('forcecommand_present no', output)
        self.assertIn('strictmodes yes', output)
        for secret in ('COMMAND_SECRET', 'ENV_SECRET', 'PRIVATE_HOST_KEY', 'PRIVATE_KEY_CONTENT'):
            self.assertNotIn(secret, output)

    def test_include_is_only_a_reference_and_match_is_not_evaluated(self):
        output = self.inventory('Include /etc/ssh/sshd_config.d/*.conf\n'
                                'Match User synthetic\nAuthorizedKeysFile .ssh/matched\n'
                                'SetEnv StrictModes=ENV_SECRET\n')
        self.assertIn('STATIC_INCLUDE=1 /etc/ssh/sshd_config.d/*.conf', output)
        self.assertIn('STATIC_MATCH_BLOCK=2 present_not_evaluated', output)
        self.assertIn('static_text_not_effective_configuration', output)
        self.assertNotIn('ENV_SECRET', output)
        self.assertNotIn('effective=yes', output)

    def test_bounds_and_control_characters_do_not_emit_unbounded_values(self):
        output = self.inventory('AuthorizedKeysFile ' + 'X'*2050 + '\n'
                                'AuthorizedKeysFile secret\x1bvalue\n'
                                + '# ignored\n'*4094 + 'AuthorizedKeysFile OUTSIDE_LIMIT\n')
        self.assertIn('oversized_line', output)
        self.assertIn('control_character', output)
        self.assertIn('line_limit_reached', output)
        self.assertNotIn('X'*20, output)
        self.assertNotIn('secret', output)
        self.assertNotIn('OUTSIDE_LIMIT', output)


if __name__ == '__main__':
    unittest.main()
