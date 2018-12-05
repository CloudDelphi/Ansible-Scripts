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

import subprocess, os
from ansible.plugins.action import ActionBase
from ansible.utils.path import makedirs_safe
from ansible.utils.hashing import checksum

class ActionModule(ActionBase):
    TRANSFERS_FILES = True

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = dict()

        if self._play_context.check_mode:
            return dict(skipped=True, msg='check mode not supported for this module')

        result = super(ActionModule, self).run(tmp, task_vars)

        cmd = self._task.args.get('cmd', None)
        stdin = self._task.args.get('stdin', None)
        dest = self._task.args.get('dest', None)

        if cmd is None or dest is None:
            return dict(failed=True, msg="cmd and dest are required")

        if stdin is not None:
            stdin = self._connection._shell.join_path(stdin)
            stdin = self._remote_expand_user(stdin)

        remote_user = task_vars.get('ansible_ssh_user') or self._play_context.remote_user
        stdout = self._connection._shell.join_path(self._make_tmp_path(remote_user), 'stdout')
        result.update(self._execute_module(module_args=dict(cmd=cmd, stdin=stdin, dest=stdout), task_vars=task_vars))

        # calculate checksum for the local file
        local_checksum = checksum(dest)

        # calculate checksum for the remote file, don't bother if using become as slurp will be used
        remote_checksum = self._remote_checksum(stdout, all_vars=task_vars)

        if remote_checksum != local_checksum:
            makedirs_safe(os.path.dirname(dest))
            self._connection.fetch_file(stdout, dest)
            if checksum(dest) == remote_checksum:
                result.update(dict(changed=True))
            else:
                result.update(dict(failed=True))
        return result
