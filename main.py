#
# Copyright (C) 2021 Nokia
# Licensed under the GNU General Public License v2.0 only
# SPDX-License-Identifier: GPL-2.0-only
#

import argparse
import json
import pandas as pd
from utils.runshell import run_shell_cmd
from utils.fileutils import csv_write, nonesafe_loads, csv_write_dict
from utils.logformatter import log_formatter
from utils.kubernetes import k8s_utils
from utils.netutils import (
    nmap,
    iptables,
    fetch_networkpolicies,
    check_pods_without_nsp,
    networkpolicies_drift_detection,
)


# -----------------------------------------------------------
# Pass below arguments from CLI
# -----------------------------------------------------------
def __get_cli():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-kubeconfig",
        "--kubeConfigPath",
        required=True,
        type=str,
        default="",
        help="Enter Kubernetes cluster kubeconfig path",
    )
    parser.add_argument(
        "-apiServer",
        "--apiServerPodname",
        required=True,
        type=str,
        default="",
        help="Enter Kubernetes API-server pod name running in the kube-system namespace",
    )
    parser.add_argument(
        "-ip", "--clusterIP", required=True, type=str, default="", help="Enter the Kubernetes cluster IP"
    )
    parser.add_argument(
        "-win", "--windows", action="store_true", help="Enter -win if Kubernetes cluster is running on windows"
    )
    args = vars(parser.parse_args())
    return args


# ------------------------------------------------------------------------
# Fetching pods whole configuration in json for each namespace
# ------------------------------------------------------------------------
def pods_config_json(pods, log, kubeconfig):
    for pod in pods.items:
        pod_name = pod.metadata.name
        pod_namespace = pod.metadata.namespace
        filepath = "./output/pods_files/pods_in_{}.json".format(pod_namespace)
        cmd = "kubectl get pods -o json -n {} --kubeconfig={}".format(pod_namespace, kubeconfig)
        log.info("Capturing configurations of pod {} in {} namespace".format(pod_name, pod_namespace))
        run_shell_cmd("{} > {}".format(cmd, filepath))


# ------------------------------------------------------------------------
# Check API server for --authorization-mode and --enable-admission-plugins
# ------------------------------------------------------------------------
def check_admissioncontroller(pods, checks, apiServer):
    for pod in pods.items:
        if pod.metadata.name == "{}".format(apiServer) and pod.metadata.namespace == "kube-system":
            for j in pod.spec.containers[0].command:
                key = j.split("=")
                if key[0] == "--authorization-mode" or key[0] == "--enable-admission-plugins":
                    checks[key[0]] = key[1].split(",")
    return checks


# ------------------------------------------------------------------------
# Fetching only required information about pods
# ------------------------------------------------------------------------
def pods_info(pods):
    header = [
        "Podname",
        "Namespace",
        "PodIP",
        "PodSecurityPolicy",
        "allow_privilege_escalation",
        "capabilities",
        "NET_RAW",
        "SYS_ADMIN",
        "privileged",
        "read_only_root_filesystem",
        "runAsGroup",
        "runAsUser",
        "image_pull_policy",
        "host_ipc",
        "host_network",
        "host_pid",
        "volume_mounts",
        "volume_mounts_token",
        "host_path",
        "resources_limits",
        "resources_requests",
    ]
    filename = "./output/pods_files/pods_info.csv"
    csv_write(filename, "w", header)

    for pod in pods.items:
        capabilities_dict = pod.spec.containers[0].to_dict()
        volumes = pod.spec.volumes[0].to_dict()
        pod_annotations = pod.metadata.annotations
        pod_name = pod.metadata.name
        pod_namespace = pod.metadata.namespace
        pod_ip = pod.status.pod_ip

        if pod_annotations != None:
            security_context = capabilities_dict["security_context"]
            pod_psp = pod_annotations["kubernetes.io/psp"] if "kubernetes.io/psp" in pod_annotations else "None"
            image_pull_policy = (
                capabilities_dict["image_pull_policy"] if capabilities_dict["image_pull_policy"] != None else "None"
            )
            host_ipc = str("None" if "host_ipc" == None else pod.spec.host_ipc)
            host_network = str("None" if "host_network" == None else pod.spec.host_network)
            host_pid = str("None" if "host_pid" == None else pod.spec.host_pid)
            volume_mounts = (
                capabilities_dict["volume_mounts"][0] if capabilities_dict["volume_mounts"][0] != None else "None"
            )
            volume_mounts_token = (
                volume_mounts["name"] if "name" in capabilities_dict["volume_mounts"][0] != None else "None"
            )
            host_path = (
                volumes["host_path"]["path"] if "host_path" in volumes and volumes["host_path"] != None else "None"
            )

            resources_limits = (
                capabilities_dict["resources"]["limits"] if capabilities_dict["resources"]["limits"] != None else "None"
            )
            resources_requests = (
                capabilities_dict["resources"]["requests"]
                if capabilities_dict["resources"]["requests"] != None
                else "None"
            )

            if capabilities_dict["security_context"] != None:
                allow_privilege_escalation = security_context["allow_privilege_escalation"]
                pod_capabilities = security_context["capabilities"]

                if pod_capabilities != None and "add" in pod_capabilities:
                    NET_RAW = (
                        "NET_RAW"
                        if pod_capabilities["add"] != None and "NET_RAW" in pod_capabilities["add"]
                        else "None"
                    )
                    SYS_ADMIN = (
                        "SYS_ADMIN"
                        if pod_capabilities["add"] != None and "SYS_ADMIN" in pod_capabilities["add"]
                        else "None"
                    )
                else:
                    NET_RAW = "None"
                    SYS_ADMIN = "None"

                privileged = security_context["privileged"]
                read_only_root_filesystem = security_context["read_only_root_filesystem"]

                if "kubectl.kubernetes.io/last-applied-configuration" in pod_annotations:
                    sec_ctxt = json.loads(pod_annotations["kubectl.kubernetes.io/last-applied-configuration"])
                    if "securityContext" in sec_ctxt["spec"]:
                        runAsGroup = (
                            int(sec_ctxt["spec"]["securityContext"]["runAsGroup"])
                            if "runAsGroup" in sec_ctxt["spec"]["securityContext"]
                            else "None"
                        )
                        runAsUser = (
                            sec_ctxt["spec"]["securityContext"]["runAsUser"]
                            if "runAsUser" in sec_ctxt["spec"]["securityContext"]
                            else "None"
                        )
            else:
                allow_privilege_escalation = "None"
                pod_capabilities = "None"
                privileged = "None"
                read_only_root_filesystem = "None"
                runAsGroup = "None"
                runAsUser = "None"
                NET_RAW = "None"
                SYS_ADMIN = "None"

            data = [
                pod_name,
                pod_namespace,
                pod_ip,
                pod_psp,
                allow_privilege_escalation,
                pod_capabilities,
                NET_RAW,
                SYS_ADMIN,
                privileged,
                read_only_root_filesystem,
                runAsGroup,
                runAsUser,
                image_pull_policy,
                host_ipc,
                host_network,
                host_pid,
                volume_mounts,
                volume_mounts_token,
                host_path,
                resources_limits,
                resources_requests,
            ]
            csv_write(filename, "a", data)


# ------------------------------------------------------------------------
# Fetch the spec of PodSecurityPolicies
# ------------------------------------------------------------------------
def list_psp(log, kubeconfig):
    podsecuritypolicies_json = nonesafe_loads(
        run_shell_cmd("kubectl get podsecuritypolicies -A -o=json --kubeconfig={}".format(kubeconfig))
    )

    header = [
        "PodSecurityPolicy",
        "allowPrivilegeEscalation",
        "allowedCapabilities",
        "fsGroup",
        "hostIPC",
        "hostNetwork",
        "hostPID",
        "hostPorts",
        "privileged",
        "requiredDropCapabilities",
        "runAsUser",
        "seLinux",
        "supplementalGroups",
        "volumes",
    ]
    filename = "./output/psp_files/psp_capabilities.csv"
    psp_data = []

    if podsecuritypolicies_json == None:
        log.warning("This cluster doesn't have a resource type podsecuritypolicies")
    elif podsecuritypolicies_json["items"] == []:
        log.warning(
            "Cluster should have PodSecurityPolicies to control security-sensitive aspects of the Pod specification"
        )
    else:
        for psp in podsecuritypolicies_json["items"]:
            podSecurityPolicyName = psp["metadata"]["name"]
            if "spec" in psp:
                pspSpec = psp["spec"]
                allowPrivilegeEscalation = (
                    pspSpec["allowPrivilegeEscalation"] if "allowPrivilegeEscalation" in pspSpec else "None"
                )
                allowedCapabilities = pspSpec["allowedCapabilities"] if "allowedCapabilities" in pspSpec else "None"
                fsGroup = pspSpec["fsGroup"] if "fsGroup" in pspSpec else "None"
                hostIPC = pspSpec["hostIPC"] if "hostIPC" in pspSpec else "None"
                hostNetwork = pspSpec["hostNetwork"] if "hostNetwork" in pspSpec else "None"
                hostPID = pspSpec["hostPID"] if "hostPID" in pspSpec else "None"
                hostPorts = pspSpec["hostPorts"] if "hostPorts" in pspSpec else "None"
                privileged = pspSpec["privileged"] if "privileged" in pspSpec else "None"
                requiredDropCapabilities = (
                    pspSpec["requiredDropCapabilities"] if "requiredDropCapabilities" in pspSpec else "None"
                )
                runAsUser = pspSpec["runAsUser"] if "runAsUser" in pspSpec else "None"
                seLinux = pspSpec["seLinux"] if "seLinux" in pspSpec else "None"
                supplementalGroups = pspSpec["supplementalGroups"] if "supplementalGroups" in pspSpec else "None"
                volumes = pspSpec["volumes"] if "volumes" in pspSpec else "None"
            else:
                allowPrivilegeEscalation = "None"

            values = {
                "PodSecurityPolicy": podSecurityPolicyName,
                "allowPrivilegeEscalation": allowPrivilegeEscalation,
                "allowedCapabilities": allowedCapabilities,
                "fsGroup": fsGroup,
                "hostIPC": hostIPC,
                "hostNetwork": hostNetwork,
                "hostPID": hostPID,
                "hostPorts": hostPorts,
                "privileged": privileged,
                "requiredDropCapabilities": requiredDropCapabilities,
                "runAsUser": runAsUser,
                "seLinux": seLinux,
                "supplementalGroups": supplementalGroups,
                "volumes": volumes,
            }

            psp_data.append(values)

        csv_write_dict(filename, "w", header, psp_data)


# --------------------------------------------------------------------------------
# Conditions to check pods parameters values
# --------------------------------------------------------------------------------
def security_check_against(parameter, log_type, msg):
    if not parameter.empty:
        log_type("{} \n {} \n".format(msg, parameter))


# --------------------------------------------------------------------------------
# Performing Pods and underlying container related security checks
# --------------------------------------------------------------------------------
def pods_security_checks(log):
    df_pod = pd.read_csv("./output/pods_files/pods_info.csv", sep=";", engine="python")
    df_pod = df_pod.where(pd.notnull(df_pod), "None")
    log.info(df_pod)

    # df_pod = df_pod.drop(
    #     df_pod[
    #         (df_pod.Namespace == "kube-system")
    #         | (df_pod.Namespace == "calico-system")
    #         | (df_pod.Namespace == "istio-system")
    #     ].index
    # )

    allow_privilege_escalation = df_pod.loc[df_pod["allow_privilege_escalation"] == "True", ["Podname", "Namespace"]]
    security_check_against(
        allow_privilege_escalation,
        log.critical,
        "AllowPrivilegeEscalation should be avoided. Remove it from below pods",
    )

    privileged = df_pod.loc[df_pod["privileged"] == "True", ["Podname", "Namespace"]]
    security_check_against(
        privileged,
        log.critical,
        "Pods running with privileged capabilities should be avoided. Remove it from below pods",
    )

    read_only_root_filesystem = df_pod.loc[df_pod["read_only_root_filesystem"] == "None", ["Podname", "Namespace"]]
    security_check_against(
        read_only_root_filesystem, log.warning, "ReadOnlyRootFileSystem should be enforced. Enforce it on below pods"
    )

    image_pull_policy = df_pod.loc[df_pod["image_pull_policy"] != "Always", ["Podname", "Namespace"]]
    security_check_against(
        image_pull_policy, log.warning, 'ImagePullPolicy="Always" should be enforced. Enforce it on below pods'
    )

    host_path = df_pod.loc[df_pod["host_path"] != "None", ["Podname", "Namespace"]]
    security_check_against(host_path, log.critical, "HostPath mounting should be avoided. Remove it from below pods")

    resources_limits = df_pod.loc[df_pod["resources_limits"] == "None", ["Podname", "Namespace"]]
    security_check_against(
        resources_limits, log.warning, "Resources memory limits should be defined. Add it on below pods"
    )

    resources_requests = df_pod.loc[df_pod["resources_requests"] == "None", ["Podname", "Namespace"]]
    security_check_against(
        resources_requests, log.warning, "Resources requests limits should be defined. Add it on below pods"
    )

    host_pid = df_pod.loc[df_pod["host_pid"] != "None", ["Podname", "Namespace"]]
    security_check_against(host_pid, log.critical, "HostPID usage should be avoided. Remove it from below pods")

    host_network = df_pod.loc[df_pod["host_network"] != "None", ["Podname", "Namespace"]]
    security_check_against(
        host_network, log.critical, "Host Network usage should be avoided. Remove it from below pods"
    )

    host_ipc = df_pod.loc[df_pod["host_ipc"] != "None", ["Podname", "Namespace"]]
    security_check_against(host_ipc, log.critical, "Host IPC usage should be avoided. Remove it from below pods")

    volume_mounts = df_pod.loc[
        df_pod["volume_mounts"].str.contains("default-token", case=False), ["Podname", "Namespace"]
    ]
    security_check_against(
        volume_mounts, log.warning, "Default token mounting should be avoided. Remove it from below pods"
    )

    runAsUser = df_pod.loc[df_pod["runAsUser"] == "None", ["Podname", "Namespace"]]
    security_check_against(
        runAsUser, log.warning, 'Pods must run as non_root user. For example: add "runAsUser: 1000" in below pods'
    )

    runAsGroup = df_pod.loc[df_pod["runAsGroup"] == "None", ["Podname", "Namespace"]]
    security_check_against(
        runAsGroup, log.warning, 'Pod group must run as non_root. For example: add "runAsGroup: 3000" in below pods'
    )

    capabilities = df_pod.loc[df_pod["capabilities"] == "None", ["Podname", "Namespace"]]
    security_check_against(
        capabilities,
        log.warning,
        "Drop all capabilities and add only required capabilities to reduce syscall attack surface. Drop capabilities from below pods",
    )

    cap_net_raw = df_pod.loc[df_pod["NET_RAW"] == "NET_RAW", ["Podname", "Namespace"]]
    security_check_against(
        cap_net_raw,
        log.warning,
        "Drop NET_RAW capability to reduce network exploits on host machines. Drop NET_RAW capability from below pods",
    )

    cap_sys_admin = df_pod.loc[df_pod["SYS_ADMIN"] == "SYS_ADMIN", ["Podname", "Namespace"]]
    security_check_against(
        cap_sys_admin,
        log.warning,
        "CAP_SYS_ADMIN is the most privileged capability and should always be avoided. Drop SYS_ADMIN capability from below pods",
    )


# --------------------------------------------------------------------------------
# Performing Network security checks
# --------------------------------------------------------------------------------
def nsp_security_checks(namespaces, pods, log, kubeconfig):
    networkpolicies_json = nonesafe_loads(
        run_shell_cmd("kubectl get networkpolicies -A -o=json --kubeconfig={}".format(kubeconfig))
    )
    if networkpolicies_json["items"] == [] or networkpolicies_json == None:
        log.warning(
            "Network Policies should be enforced on pods running in the cluster. Currently there are not any networkpolicies in the cluster."
        )
    else:
        """Running netutils functions"""
        nsp_pods_labels = fetch_networkpolicies(namespaces, log, kubeconfig)
        check_pods_without_nsp(pods, nsp_pods_labels, log)

        df_nsp = pd.read_csv("./output/nsp_files/nsp.csv", sep=";", engine="python")
        df_nsp = df_nsp.where(pd.notnull(df_nsp), "None")
        policy_types = df_nsp.loc[
            (~df_nsp["PolicyTypes"].str.contains("ingress", case=False))
            | (~df_nsp["PolicyTypes"].str.contains("egress", case=False)),
            ["PolicyName", "Namespace", "PolicyTypes"],
        ]

        security_check_against(
            policy_types,
            log.warning,
            "Both policyTypes Ingress and Egress should be enforced by individual Networkpolicy. Please apply both policyTypes on below networkpolicies",
        )

        networkpolicies_drift_detection(log)


# --------------------------------------------------------------------------------
# Performing PeerAuthentication checks
# --------------------------------------------------------------------------------
def peerauthentication_security_checks(namespaces, log, kubeconfig):
    for namespace in namespaces.items:
        if "istio-system" in namespace.metadata.name:
            peerauthentication_json = nonesafe_loads(
                run_shell_cmd("kubectl get peerauthentication -A -o=json --kubeconfig={}".format(kubeconfig))
            )
            header = ["PeerAuthenticationName", "Namespace", "Selector", "mtlsMode", "portLevelMtls"]
            filename = "./output/mTLS_files/peerauthentication.csv"
            peerauth_data = []

            if peerauthentication_json == None:
                log.info("No Istio Mutual TLS implementation")
            elif peerauthentication_json["items"] == []:
                log.warning("Cluster should run in Strict mTLS mode. Currently it is running in Permissive mode")
            else:
                for peerauth in peerauthentication_json["items"]:
                    peerAuthenticationName = peerauth["metadata"]["name"]
                    namespace_name = peerauth["metadata"]["namespace"]
                    if "spec" in peerauth:
                        peerauthSpec = peerauth["spec"]
                        selector = peerauthSpec["selector"] if "selector" in peerauthSpec else "None"
                        mtlsMode = peerauthSpec["mtls"] if "mtls" in peerauthSpec else "None"
                        portLevelMtls = peerauthSpec["portLevelMtls"] if "portLevelMtls" in peerauthSpec else "None"
                    else:
                        selector = "None"
                        mtlsMode = "None"
                        portLevelMtls = "None"

                    values = {
                        "PeerAuthenticationName": peerAuthenticationName,
                        "Namespace": namespace_name,
                        "Selector": selector,
                        "mtlsMode": mtlsMode,
                        "portLevelMtls": portLevelMtls,
                    }

                    peerauth_data.append(values)

                csv_write_dict(filename, "w", header, peerauth_data)

                df_peerauth = pd.read_csv("./output/mTLS_files/peerauthentication.csv", sep=";", engine="python")
                log.info(df_peerauth)

                mTLS = df_peerauth.loc[
                    (~df_peerauth["mtlsMode"].str.contains("STRICT", case=False)),
                    ["PeerAuthenticationName", "Namespace", "mtlsMode"],
                ]

                security_check_against(
                    mTLS,
                    log.warning,
                    "Strict mTLS should be enforced for enabling Zero-Trust in the cluster. Please apply Strict mode on below peerauthentications",
                )


# -----------------------------------------------------------
# Main functionality
# -----------------------------------------------------------
def main():
    args = __get_cli()
    kubeconfig = args["kubeConfigPath"]
    clusterIP = args["clusterIP"]
    apiServer = args["apiServerPodname"]
    pods, namespaces = k8s_utils(kubeconfig)

    checks = {}
    log = log_formatter("main_result.log")
    if check_admissioncontroller(pods, checks, apiServer) != {}:
        log.info("Checking enabled authorization modes and admission controllers")
        if "RBAC" not in checks["--authorization-mode"]:
            log.critical("RBAC authorization mode should be enforced on the cluster")
        if "Node" not in checks["--authorization-mode"]:
            log.critical("Node authorization mode should be enforced on the cluster")
        if "AlwaysPullImages" not in checks["--enable-admission-plugins"]:
            log.warning("AlwaysPullImages admission controller should be enforced on the cluster")
        if "PodSecurityPolicy" not in checks["--enable-admission-plugins"]:
            log.warning("PodSecurityPolicy admission controller should be enforced on the cluster")
        else:
            log.info("Fetching Pod Security Policies...")
            list_psp(log, kubeconfig)
    else:
        log.error("Please provide valid kube-apiserver pod name")

    log.info("Now, Fetching Pods information...")
    # pods_config_json(pods,log, kubeconfig)
    pd.options.display.max_rows = 999
    pods_info(pods)
    pods_security_checks(log)

    """ Running network security checks"""
    nsp_security_checks(namespaces, pods, log, kubeconfig)
    peerauthentication_security_checks(namespaces, log, kubeconfig)

    if args["windows"]:
        sudo = ""
        log.info("Running nmap on cluster IP")
        nmap(clusterIP, sudo)
    else:
        sudo = "sudo"
        log.info("Running nmap on cluster IP")
        nmap(clusterIP, sudo)
        log.info("Running iptables command on cluster IP")
        iptables()
    log.info("Completed the static analysis scan. Please check output folder for the scan result")


if __name__ == "__main__":
    main()
