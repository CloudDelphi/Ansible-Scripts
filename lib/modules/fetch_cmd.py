#!/usr/bin/python3

# Fetch the output of a remote command
# Copyright (c) 2016 Guilhem Moulin <guilhem@fripost.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# import module snippets
from ansible.module_utils.basic import *

def main():
    module = AnsibleModule(
        argument_spec   = dict(
            cmd   = dict( default=None ),
            stdin = dict( default=None ),
            dest  = dict( default=None ),
        ),
        supports_check_mode=False
    )

    params = module.params
    cmd    = params['cmd']
    stdin  = params['stdin']
    dest   = params['dest']

    if cmd is None or dest is None:
        return dict(failed=True, msg="cmd and dest are required")

    changed = False
    try:
        if stdin is not None:
            stdin = open(stdin, 'r')

        with open(dest, 'w') as stdout:
            subprocess.check_call(cmd.split(), stdin=stdin, stdout=stdout)
            if stdin is not None:
                stdin.close()

    except KeyError as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=changed)

main()
