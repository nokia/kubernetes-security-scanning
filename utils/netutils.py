#
# Copyright (C) 2021 Nokia
# Licensed under the GNU General Public License v2.0 only
# SPDX-License-Identifier: GPL-2.0-only
#

import json
import pathlib
from utils.fileutils import csv_write, json_write, rename_file
from utils.runshell import run_shell_cmd
from utils.driftDetector import compare_files

# -----------------------------------------------------------
# Netutils Functions
# -----------------------------------------------------------
def nmap(clusterIP, sudo):
    nmap_cmd = "{} nmap -O -T4 -PE --osscan-limit -v -sS -p - {} -oX -".format(sudo, clusterIP)
    nmap_filepath = "./output/nsp_files/nmap.xml"
    run_shell_cmd("{} > {} ".format(nmap_cmd, nmap_filepath))


def iptables():
    iptables_filepath = "./output/nsp_files/iptables_nat.xml"
    iptable_kube_service_filepath = "./output/nsp_files/iptables_nat_kubeservices.txt"
    run_shell_cmd("sudo iptables-save -t nat   | iptables-xml > {}".format(iptables_filepath))
    run_shell_cmd("sudo iptables -t nat -L KUBE-SERVICES -n  | column -t > {}".format(iptable_kube_service_filepath))


# ------------------------------------------------------------------------
# Function to fetch Ingress or Egress rules of NetworkPolicy
# ------------------------------------------------------------------------
def fetch_policy_rules(policy, spec):
    if policy.capitalize() in spec["policyTypes"]:
        policy = spec[policy] if policy in spec else "Deny"
    else:
        policy = "None"
    return policy


# ------------------------------------------------------------------------
# Fetching networkpolicies in json for each namespace
# ------------------------------------------------------------------------
def fetch_networkpolicies(namespaces, log, kubeconfig):
    nsp_podSelector = []
    nsp_dict_json = {}

    """Capturing following values of network policies"""
    header = [
        "PolicyName",
        "Namespace",
        "PodSelector",
        "PolicyTypes",
        "Ingress",
        "Egress",
    ]

    filename = "./output/nsp_files/nsp.csv"
    csv_write(filename, "w", header)

    for namespace in namespaces.items:
        namespace_name = namespace.metadata.name
        fetch_nsp_cmd = "kubectl get networkpolicy -o json -n {} --kubeconfig={}".format(namespace_name, kubeconfig)
        resulted_nsp = json.loads(run_shell_cmd(fetch_nsp_cmd))
        if resulted_nsp["items"] != []:
            log.info("Capturing networkpolicies in {} namespace".format(namespace_name))

            # """Save networkpolicies in json file"""
            # filepath = "./output/nsp_files/nsp_in_{}.json".format(namespace_name)
            # run_shell_cmd("{} > {}".format(fetch_nsp_cmd, filepath))

            for nsp in resulted_nsp["items"]:
                nsp_spec = nsp["spec"]
                policyName = nsp["metadata"]["name"]
                podSelector = nsp_spec["podSelector"]
                policyTypes = nsp_spec["policyTypes"]

                """Append PodSelector labels of networkpolicy in the nsp_podSelector list"""
                nsp_podSelector.append(
                    [podSelector["matchLabels"] if "matchLabels" in podSelector else None, namespace_name]
                )
                ingress = fetch_policy_rules("ingress", nsp_spec)
                egress = fetch_policy_rules("egress", nsp_spec)

                data = [
                    policyName,
                    namespace_name,
                    podSelector,
                    policyTypes,
                    ingress,
                    egress,
                ]
                csv_write(filename, "a", data)

                nsp_dict = {
                    policyName: {
                        "PolicyName": policyName,
                        "Namespace": namespace_name,
                        "PodSelector": podSelector,
                        "PolicyTypes": policyTypes,
                        "Ingress": ingress,
                        "Egress": egress,
                    },
                }
                nsp_dict_json.update(nsp_dict)

    """Creating a backup of all_nsps.json file """
    nsp_json_filepath = pathlib.Path("./output/nsp_files/all_nsps.json")
    nsp_json_bak_file = pathlib.Path("./output/nsp_files/all_nsps_bak.json")
    rename_file(nsp_json_filepath, nsp_json_bak_file)

    """Fetching all networkpolicies in json"""
    json_write(nsp_json_filepath, "w", nsp_dict_json)

    nsp_podSelector.remove(None) if None in nsp_podSelector else nsp_podSelector
    return nsp_podSelector


# ------------------------------------------------------------------------
# Detects configurations drift between previous and current networkpolicies
# ------------------------------------------------------------------------
def networkpolicies_drift_detection(log):
    backup_file = pathlib.Path("./output/nsp_files/all_nsps_bak.json")
    current_file = pathlib.Path("./output/nsp_files/all_nsps.json")
    if backup_file.exists() and current_file.exists():
        drift = compare_files(current_file, backup_file)
        if not drift.startswith("{}"):
            log.info("Detecting configurations drift in networkpolicies between previous and current run of the tool")
            log.warning(drift)
    else:
        pass


# ------------------------------------------------------------------------
# Check for pods which have no NetworkPolicies implementation
# ------------------------------------------------------------------------
def check_pods_without_nsp(pods, nsp_pods_labels, log):
    pods_with_labels = []
    pods_with_nsp = []
    all_pods = []
    pods_without_nsp = []

    """Creating a list of pods name with their labels"""
    for pod in pods.items:
        if (
            "kube-system" not in pod.metadata.namespace
            and "calico-system" not in pod.metadata.namespace
            and "istio-system" not in pod.metadata.namespace
            and "tigera-operator" not in pod.metadata.namespace
        ):
            pods_with_labels.append([pod.metadata.name, pod.metadata.labels, pod.metadata.namespace])

    """Comparing pods labels in all_pods list with nsp_pods_labels to find out pods which do not have nsp implemented"""
    for pod in pods_with_labels:
        pod_name = pod[0]
        pod_label = pod[1]
        pod_namespace = pod[2]
        if pod_label != None and nsp_pods_labels != None:
            for nsp_pod in nsp_pods_labels:
                nsp_label = nsp_pod[0]
                nsp_namespace = nsp_pod[1]
                if nsp_label != None and nsp_label.items() <= pod_label.items() and nsp_namespace == pod_namespace:
                    pods_with_nsp.append([pod_name, pod_namespace])
        all_pods.append([pod_name, pod_namespace])

    for pod in all_pods:
        if pod not in pods_with_nsp:
            log.warning("{} pod running in {} namespace doesnot have a network policy".format(pod[0], pod[1]))
