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

import os
import pipes
import tempfile

from ansible.utils import template
from ansible import utils
from ansible.runner.return_data import ReturnData

class ActionModule(object):
    TRANSFERS_FILES = True

    def __init__(self, runner):
        self.runner = runner

    def run(self, conn, tmp, module_name, module_args, inject, complex_args=None, **kwargs):
        ''' handler for file transfer operations '''

        # load up options
        options  = {}
        if complex_args:
            options.update(complex_args)
        options.update(utils.parse_kv(module_args))

        target = options.get('target', None)
        local = options.get('local', 'no')

        if local not in [ 'no', 'file', 'template' ]:
            result = dict(failed=True, msg="local must be in ['no','file','template']")
            return ReturnData(conn=conn, comm_ok=False, result=result)

        if local != 'no' and target is None:
            result = dict(failed=True, msg="target is required in local mode")
            return ReturnData(conn=conn, comm_ok=False, result=result)

        if local == 'no':
            # run the module remotely
            return self.runner._execute_module(conn, tmp, 'openldap', module_args, inject=inject, complex_args=complex_args)
        elif '_original_file' in inject:
            target = utils.path_dwim_relative(inject['_original_file'], local+'s', target, self.runner.basedir)
        else:
            # the source is local, so expand it here
            target = os.path.expanduser(target)

        options['local'] = 'no'
        options['target'] = os.path.join(tmp, os.path.basename(target))
        if local == 'template':
            # template the source data locally and transfer it
            try:
                s = template.template_from_file(self.runner.basedir, target, inject, vault_password=self.runner.vault_pass)
                tmpfile = tempfile.NamedTemporaryFile(delete=False)
                tmpfile.write(s)
                tmpfile.close()
                target = tmpfile.name
            except Exception, e:
                result = dict(failed=True, msg=str(e))
                return ReturnData(conn=conn, comm_ok=False, result=result)
            conn.put_file(tmpfile.name, options['target'])
            os.unlink(tmpfile.name)

        elif local == 'file':
            conn.put_file(target, options['target'])

        # run the script remotely with the new (temporary) filename
        module_args = ""
        for o in options:
            module_args = "%s %s=%s" % (module_args, o, pipes.quote(options[o]))
        return self.runner._execute_module(conn, tmp, 'openldap', module_args, inject=inject)
