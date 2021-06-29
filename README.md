![alt text1][logo]

[logo]: img/kubepatrol_logo.png "KubePatrol"

## KubePatrol
This tool provides a comprehensive scanning and reporting of the security status of a Kubernetes cluster. It helps Kubernetes cluster administrator to check whether Network related security checks and Pod related security checks are in place or not. Tool goes deep into the container and analyze security issues within the underlying container, and, in most cases, suggests fixes to the detected security issues. It further performs the drift configuration detection for implemented network polices. This tool can be run from either worker nodes or master node.

## Developer
This tool has been developed by Monika Rangta (https://github.com/mrangta), while working as Master´s Thesis Worker in Nokia. 

## Installation
Check out **kubernetes-security-scanning** repository:

`git clone git@github.com:nokia/kubernetes-security-scanning.git`

#### For Ubuntu Users:
Please ensure to have **python3**, **nmap**, **iptables** installed on the nodes to use this tool
#### For Windows Users:
Please ensure to have **python3**, **nmap** installed on the nodes to use this tool

-------------------------------------------------------------------------------------------------------------------------------

Also ensure all the required modules mentioned in **requirements.txt** are installed, if not please install using the following:

`pip3 install -r requirements.txt`

## Usage


```
#  python3 main.py -h
usage: main.py [-h] -kubeconfig KUBECONFIGPATH -apiServer APISERVERPODNAME -ip
               CLUSTERIP [-win]

optional arguments:
  -h, --help            show this help message and exit
  -kubeconfig KUBECONFIGPATH, --kubeConfigPath KUBECONFIGPATH
                        Enter Kubernetes cluster kubeconfig path
  -apiServer APISERVERPODNAME, --apiServerPodname APISERVERPODNAME
                        Enter Kubernetes API-server pod name running in the
                        kube-system namespace
  -ip CLUSTERIP, --clusterIP CLUSTERIP
                        Enter the Kubernetes cluster IP
  -win, --windows       Enter -win if Kubernetes cluster is running on windows
```
## Generating Files
Currently the **main.py** script generates the **psp_capabilities.csv**, **pods_info.csv**, **nsp.csv**, **nmap.xml**, **iptables_nat.xml**, **iptables_nat_kubeservices.txt** and **main_result.log** files

All these files will be generated in their respective directories under **output** directory. Currently **output** directory contains the example output files, which will automatically update with your cluster configurations after running this tool.

## Generation Examples (Manual Procedure)
#### Successful case
```
# python3 main.py -kubeconfig /home/vagrant/.kube/config -apiServer kube-apiserver-master -ip 10.0.0.2
  INFO     | Checking enabled authorization modes and admission controllers
  WARNING  | AlwaysPullImages admission controller should be enforced on the cluster
  INFO     | Fetching Pod Security Policies...
  INFO     | Now, Fetching Pods information...
  INFO     |                                      Podname      Namespace  ...     resources_limits                                 resources_requests
0   calico-kube-controllers-5ccd78d7d4-tdpm6  calico-system  ...                 None                                               None
1                          calico-node-b84cv  calico-system  ...                 None                                               None
2                          calico-node-vtjtv  calico-system  ...                 None                                               None
3              calico-typha-547486645c-f9zfj  calico-system  ...                 None                                               None
4              calico-typha-547486645c-xgcrs  calico-system  ...                 None                                               None
5                               hostpath-pod        default  ...                 None                                               None
6                                    hostpid        default  ...                 None                                               None
7                               priv-esc-pod        default  ...                 None                                               None
8                             privileged-pod        default  ...                 None                                               None
9                                       pod3       external  ...                 None                                               None
10                   coredns-74ff55c5b-jbpbz    kube-system  ...  {'memory': '170Mi'}                  {'cpu': '100m', 'memory': '70Mi'}
11                   coredns-74ff55c5b-q82ct    kube-system  ...  {'memory': '170Mi'}                  {'cpu': '100m', 'memory': '70Mi'}
12                               etcd-master    kube-system  ...                 None  {'cpu': '100m', 'ephemeral-storage': '100Mi', ...
13                     kube-apiserver-master    kube-system  ...                 None                                    {'cpu': '250m'}
14            kube-controller-manager-master    kube-system  ...                 None                                    {'cpu': '200m'}
15                          kube-proxy-c8tl2    kube-system  ...                 None                                               None
16                     kube-scheduler-master    kube-system  ...                 None                                    {'cpu': '100m'}

[17 rows x 20 columns]
  CRITICAL | AllowPrivilageEscalation should be avoided. Remove it from below pods 
         Podname Namespace
7  priv-esc-pod   default

  CRITICAL | Pods running with privileged capabilities should be avoided. Remove it from below pods 
           Podname Namespace
8  privileged-pod   default

  WARNING  | ReadOnlyRootFileSystem should be enforced. Enforce it on below pods 
           Podname Namespace
5    hostpath-pod   default
           Podname Namespace
5    hostpath-pod   default
6         hostpid   default
7    priv-esc-pod   default
8  privileged-pod   default
9            pod3  external

  CRITICAL | HostPID usage should be avoided. Remove it from below pods
    Podname Namespace
6  hostpid   default

  CRITICAL | Host Network usage should be avoided. Remove it from below pods 
    Podname Namespace
6  hostpid   default 

  CRITICAL | Host IPC usage should be avoided. Remove it from below pods 
    Podname Namespace
6  hostpid   default 

  WARNING  | Default token mounting should be avoided. Remove it from below pods 
           Podname Namespace
6         hostpid   default
7    priv-esc-pod   default
8  privileged-pod   default
9            pod3  external 

  WARNING  | Pods must run as non_root user. For example: add "runAsUser: 1000" in below pods 
           Podname Namespace
5    hostpath-pod   default
6         hostpid   default
7    priv-esc-pod   default
8  privileged-pod   default
9            pod3  external 

  WARNING  | Pod´s group must run as non_root. For example: add "runAsGroup: 3000" in below pods 
           Podname Namespace
5    hostpath-pod   default
6         hostpid   default
7    priv-esc-pod   default
8  privileged-pod   default
9            pod3  external

  WARNING  | Drop all capabilities and add only those required to reduce syscall attack surface. Drop capabilities from below pods 
           Podname Namespace
5    hostpath-pod   default
6         hostpid   default
7    priv-esc-pod   default
8  privileged-pod   default
9            pod3  external

  INFO     | Capturing networkpolicies in default namespace
  WARNING  | position-simulator-f6896665b-474z9 pod doesnot have a network policy
  WARNING  | position-tracker-5b767bb48b-bdqrs pod doesnot have a network policy
  WARNING  | webapp-5d9d655b68-rsndj pod doesnot have a network policy
  INFO     | Detecting configurations drift between previous and current networkpolicies
  WARNING  | {'dictionary_item_removed': [root['default-deny-ingress']],
 'values_changed': {"root['gateway-network-policy']['Egress'][0]['to'][1]['podSelector']['matchLabels']['app']": {'new_value': 'position-simulator',   
                                                                                                                  'old_value': 'position-tracker'}}}   
  INFO     |   PeerAuthenticationName       Namespace                            Selector                mtlsMode                  portLevelMtls
0                default  namespace_name  {'matchLabels': {'app': 'webapp'}}  {'mode': 'PERMISSIVE'}  {'8080': {'mode': 'DISABLE'}}
1                default  namespace_name                                None      {'mode': 'STRICT'}                           None
  WARNING  | Strict mTLS should be enforced for applying Zero-Trust in the cluster. Please apply Strict mode on below peerauthentications 
   PeerAuthenticationName       Namespace                mtlsMode
0                default  namespace_name  {'mode': 'PERMISSIVE'}

  INFO     | Running nmap on cluster IP
  INFO     | Running iptables command on cluster IP
  INFO     | Completed the static analysis scan. Please check output folder for the scan result.
```

