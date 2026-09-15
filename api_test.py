python3 -c "
from pyVim.connect import SmartConnect
import ssl, time
si = SmartConnect(host='<host>', user='<user>', pwd='<pwd>', sslContext=ssl._create_unverified_context())
vm = next(v for v in si.content.viewManager.CreateContainerView(si.content.rootFolder, [__import__('pyVmomi').vim.VirtualMachine], True).view if v.name == '<vm_name>')
t = vm.CreateSnapshot_Task(name='test', description='test', memory=True, quiesce=False)
while t.info.state not in ['success','error']: time.sleep(1)
print(t.info.state, t.info.error.msg if t.info.state=='error' else '')
"
