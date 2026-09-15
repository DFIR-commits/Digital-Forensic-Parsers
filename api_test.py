python3 -c "
from pyVim.connect import SmartConnect
import ssl, time
si = SmartConnect(host='<host>', user='<user>', pwd='<pwd>', sslContext=ssl._create_unverified_context())
vm = next(v for v in si.content.viewManager.CreateContainerView(si.content.rootFolder, [__import__('pyVmomi').vim.VirtualMachine], True).view if v.name == '<vm_name>')
t = vm.CreateSnapshot_Task(name='test', description='test', memory=True, quiesce=False)
while t.info.state not in ['success','error']: time.sleep(1)
print(t.info.state, t.info.error.msg if t.info.state=='error' else '')
"




python3 -c "
from pyVim.connect import SmartConnect
import ssl
ctx = ssl.create_default_context(cafile='/opt/vcenter-watcher/vcenter-chain.pem')
si = SmartConnect(host='vc.net', user='alesher', pwd='YOUR_ACTUAL_PASSWORD_HERE', sslContext=ctx)
print(repr(si._stub.cookie))
"

curl -k -H 'Cookie: vmware_soap_session="f7c009fb-7dc0-1f38-1d61-3a44e27886c1"' \
  "https://vc.net/folder/<vmname>/<filename>?dcPath=localhost&dsName=datastore" \
  -o /tmp/manual-test.vmsn -v



python3 -c "
from pyVim.connect import SmartConnect
import ssl
ctx = ssl._create_unverified_context()
si = SmartConnect(host='<esxi-ip>', user='root', pwd='<esxi-root-password>', sslContext=ctx)
print(si.content.about.apiType)
"


$ds = Get-Datastore -Name "<datastore-name>"
Get-ChildItem -Path "vmstore:\ha-datacenter\$($ds.Name)\<vm-name>\" | Where-Object { $_.Name -like "*.vmem" -or $_.Name -like "*.vmsn" }
