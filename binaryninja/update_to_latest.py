import pexpect
import subprocess
import sys

child = pexpect.spawn('python /tmp/version_switcher.py')
child.logfile = sys.stdout
child.expect('Choice:')
child.sendline('1')
child.expect('Choice:')
child.sendline('1')
child.timeout=600
child.expect(['Choice:', 'UpdateSuccess'])
child.terminate()
