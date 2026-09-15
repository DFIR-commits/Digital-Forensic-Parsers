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


Prior to traveling to the customer site, the team will work with the customer to:

Review and obtain the necessary approvals for the planned CrowdStrike configuration changes.
Assist with configuring CrowdStrike SOAR triggers and associated response actions.
Identify and work through customer-specific configuration requirements and any issues encountered during implementation.
Determine what infrastructure and storage requirements are necessary to support evidence preservation when automated response triggers are activated.
Design and configure the supporting evidence-preservation infrastructure so that forensic artifacts can be collected and retained when response actions are initiated.
Configure and validate a Sysmon deployment and Splunk Universal Forwarder integration with the deployment kit.
Validate connectivity, permissions, and other technical prerequisites required for the on-site deployment.

$ds = Get-Datastore -Name "<datastore-name>"
Get-ChildItem -Path "vmstore:\ha-datacenter\$($ds.Name)\<vm-name>\" | Where-Object { $_.Name -like "*.vmem" -or $_.Name -like "*.vmsn" }
