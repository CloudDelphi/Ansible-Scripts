# Manage OpenLDAP databases
# Copyright (c) 2014 Guilhem Moulin <guilhem@fripost.org>
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

from ansible.plugins.action import ActionBase
from ansible.utils.unicode import to_bytes, to_unicode

class ActionModule(ActionBase):
    TRANSFERS_FILES = True

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = dict()

        if self._play_context.check_mode:
            return dict(skipped=True, msg='check mode not supported for this module')

        result = super(ActionModule, self).run(tmp, task_vars)

        target = self._task.args.get('target', None)
        local = self._task.args.get('local', 'no')

        if local not in [ 'no', 'file', 'template' ]:
            return dict(failed=True, msg="local must be in ['no','file','template']")

        if local != 'no' and target is None:
            return dict(failed=True, msg="target is required in local mode")

        if local == 'no':
            # run the module remotely
            return self._execute_module(module_args=self._task.args, task_vars=task_vars)

        if self._task._role is not None:
            target = self._loader.path_dwim_relative(self._task._role._role_path, local+'s', target)
        else:
            target = self._loader.path_dwim_relative(self._loader.get_basedir(), local+'s', target)

        remote_user = task_vars.get('ansible_ssh_user') or self._play_context.remote_user
        new_module_args = self._task.args.copy()
        new_module_args['target'] = self._connection._shell.join_path(self._make_tmp_path(remote_user), 'target.ldif')
        new_module_args['local'] = 'no'

        if local == 'template':
            # template the source data locally
            try:
                with open(target, 'r') as f:
                    template_data = to_unicode(f.read())
                target = self._templar.template(template_data, preserve_trailing_newlines=True, escape_backslashes=False, convert_data=False)
            except Exception as e:
                result['failed'] = True
                result['msg'] = type(e).__name__ + ": " + str(e)
                return result

        # transfer the file and run the module remotely
        self._transfer_data(new_module_args['target'], target)
        result.update(self._execute_module(module_args=new_module_args, task_vars=task_vars))
        return result
