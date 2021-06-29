#
# Copyright (C) 2021 Nokia
# Licensed under the GNU General Public License v2.0 only
# SPDX-License-Identifier: GPL-2.0-only
#

import yaml
from kubernetes import client
from kubernetes.client import Configuration
from kubernetes.config import kube_config


class K8s(object):
    def __init__(self, configuration_yaml):
        self.configuration_yaml = configuration_yaml
        self._configuration_yaml = None

    @property
    def config(self):
        with open(self.configuration_yaml, "r") as f:
            if self._configuration_yaml is None:
                self._configuration_yaml = yaml.safe_load(f)
        return self._configuration_yaml

    @property
    def client(self):
        k8_loader = kube_config.KubeConfigLoader(self.config)
        call_config = type.__call__(Configuration)
        k8_loader.load_and_set(call_config)
        Configuration.set_default(call_config)
        return client.CoreV1Api()


# Instantiate your kubernetes class and pass in config
# kube_one = K8s(configuration_yaml="~/.kube/config1")
# pods=kube_one.client.list_pod_for_all_namespaces(watch=False)


def k8s_utils(kubeconfig_path):
    v1 = K8s(configuration_yaml=kubeconfig_path)
    pods = v1.client.list_pod_for_all_namespaces(watch=False)
    namespaces = v1.client.list_namespace(watch=False)
    return pods, namespaces
