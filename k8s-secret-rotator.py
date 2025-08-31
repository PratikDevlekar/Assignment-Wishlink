#!/usr/bin/env python3
import os
import subprocess
import sys
import json
import tempfile
import base64
import hashlib

# helper function : helps me run cmds on bin/bash
def run(cmd,input=None):
    result = subprocess.run(
        cmd, shell=True,
        capture_output=True, text=True,
        input=input
    )
    if result.returncode != 0:
        print(f"Command failed: {cmd}\n{result.stderr.strip()}")
        sys.exit(1)
    return result.stdout.strip()


# Setting up input [ENV] required field
SECRET_NAME = os.environ.get("SECRET_NAME")
NAMESPACE = os.environ.get("NAMESPACE", "default")
NEW_SECRET_VALUE = os.environ.get("NEW_SECRET_VALUE")  
SECRET_KEY = os.environ.get("SECRET_KEY")
file_path_default = True

# For Testing Purpose 
# SECRET_NAME = "my-secret"
# NAMESPACE = "test-space"
# NEW_SECRET_VALUE = "Testing-new-password"
# SECRET_KEY = "password"

# Taking input [STDIN] required field
if not SECRET_NAME:
    print("Enter secret name (press Ctrl+D to finish):")
    SECRET_NAME = sys.stdin.read().strip()

if not NEW_SECRET_VALUE:
    print("Enter new secret value (press Ctrl+D to finish):")
    NEW_SECRET_VALUE = sys.stdin.read().strip()

if not NAMESPACE:
    print("Enter Namespace (press Ctrl+D to finish):")
    NAMESPACE = sys.stdin.read().strip()

if not SECRET_KEY:
    print("Enter secret key (press Ctrl+D to finish):")
    SECRET_KEY = sys.stdin.read().strip()

if not SECRET_NAME:
    print("ERROR: SECRET_NAME environment variable is required")
    sys.exit(1)

if not NEW_SECRET_VALUE:
    print("ERROR: NEW_SECRET_VALUE environment variable is required")
    sys.exit(1)

if not SECRET_KEY:
    print("ERROR: SECRET_KEY environment variable is required")
    sys.exit(1)
FILE_PATH_ON_POD = "/etc/secrets/"+ str(SECRET_KEY)

# Discover workloads of a specific kind (Deployment/StatefulSet) that reference the target secret
# Checks env vars, envFrom, and volume mounts for secret references

def workload(secret_name, namespace, kind, workloads):
    dep_cmd = f"kubectl get {kind.lower()}s -n {namespace} -o json"
    deps = json.loads(run(dep_cmd))
    for dep in deps['items']:
        found = False
        for env in dep['spec']['template']['spec'].get('containers', []):
            env_vars = env.get('env', [])
            # valueFrom check
            for e in env_vars:
                if e.get('valueFrom', {}).get('secretKeyRef', {}).get('name') == secret_name:
                    workloads.append((kind, dep['metadata']['name']))
                    found = True
                    break
            # envFrom check
            for e in env.get('envFrom', []):
                if e.get('secretRef', {}).get('name') == secret_name:
                    workloads.append((kind, dep['metadata']['name']))
                    found = True
                    break
        # Volumes check
        if(found == False):
            for vol in dep['spec']['template']['spec'].get('volumes', []):
                if vol.get('secret', {}).get('secretName') == secret_name:
                    workloads.append((kind, dep['metadata']['name']))
                    break 

def get_workloads(secret_name, namespace):
    workloads = []
    kind = ["Deployment", "StatefulSet"] #Futher can also be extended
    for k in kind:
        workload(secret_name, namespace, k,workloads)
    return list(set(workloads))


# Update the Kubernetes secret with new value 
# Encodes the new value in base64 and applies via kubectl

def patch_secret(secret_name, namespace, new_value, key):
    cmd_get = f"kubectl get secret {secret_name} -n {namespace} -o json"
    secret_json_str = run(cmd_get)
    secret_json = json.loads(secret_json_str)
    data = secret_json.get("data", {})
    data[key] = base64.b64encode(new_value.encode()).decode()  # base64 encode
    secret_json["data"] = data
    cmd_apply = "kubectl apply -f -"
    result = run(cmd_apply, input=json.dumps(secret_json))  # Passing the JSON directly to kubectl

    print(f"Secret '{secret_name}' updated successfully with key '{key}'.")

# Configure rolling update strategy with specified surge and unavailable parameters
# Ensures zero-downtime deployment by allowing controlled pod replacement

def ensure_max_surge(kind, name, namespace, surge="40%", unavailable="0"):
    patch = {
        "spec": {
            "strategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {
                    "maxSurge": surge,
                    "maxUnavailable": unavailable
                }
            }
        }
    }
    cmd_patch = f"kubectl patch {kind.lower()}/{name} -n {namespace} --type merge -p '{json.dumps(patch)}'"
    run(cmd_patch)
    print(f"Updated rollout strategy for {kind}/{name}: maxSurge={surge}, maxUnavailable={unavailable}")


# Restart workload and wait for successful rollout with exponential backoff retry logic
# Triggers rollback on failure and verifies post-rollout secret propagation

def rollout_workload(kind, name, namespace):
    rollout_cmd = f"kubectl rollout restart {kind.lower()}/{name} -n {namespace}"
    run(rollout_cmd)

    retries = 3
    hold = 3
    timeout = pow(2,hold)*60
    while retries > 0:
        try:
            wait_cmd = f"kubectl rollout status {kind.lower()}/{name} -n {namespace} --timeout={timeout}s"
            run(wait_cmd)
            print(f"{kind}/{name} rolled out successfully.")
            verify_post_rollout(kind, name, namespace)
            break
        except Exception as e:
            print(f"Error during rollout: {e}. Retrying...")
            retries -= 1
            hold+=1
            timeout = pow(2,hold)*60
            if file_path_default == False:
                print("Enter the path to the secret file, default not working: " + FILE_PATH_ON_POD)
                FILE_PATH_ON_POD = sys.stdin.read().strip()
            if retries == 0:
                print(f"Rollout failed for {kind}/{name}. Triggering rollback...")
                rollback_workload(kind, name, namespace)
                raise Exception(f"Rollout failed for {kind}/{name} after multiple attempts.")
            

# Rollback workload to previous revision in case of deployment failure
# Uses kubectl rollout undo to restore previous working state

def rollback_workload(kind, name, namespace):
    print(f"Rolling back {kind}/{name}...")
    rollback_cmd = f"kubectl rollout undo {kind.lower()}/{name} -n {namespace}"
    run(rollback_cmd)
    print(f"Rollback completed for {kind}/{name}.")

# Get list of pod names for a given workload using label selectors
# Extracts matchLabels from workload spec and queries pods with those labels

def get_pod_names(kind, name, namespace):
    cmd = f"kubectl get {kind.lower()}/{name} -n {namespace} -o json"
    data = json.loads(run(cmd))
    
    # Extract the label selector
    selector = data['spec']['selector']['matchLabels']
    # Build label selector string: key1=value1,key2=value2
    selector_str = ",".join([f"{k}={v}" for k,v in selector.items()])
    pod_cmd = f"kubectl get pods -n {namespace} -l {selector_str} -o json"
    pods_json = json.loads(run(pod_cmd))
    return [pod['metadata']['name'] for pod in pods_json.get('items', [])]

# Extract container names from workload specification
# Returns list of container names defined in the pod template

def get_containers(kind, name, namespace):
    cmd = f"kubectl get {kind.lower()}/{name} -n {namespace} -o json"
    data = json.loads(run(cmd))
    return [c['name'] for c in data['spec']['template']['spec'].get('containers', [])]

# Verify that the new secret value has been propagated to running pods
# Checks both environment variables and mounted files using hash comparison

def verify_post_rollout(kind, name, namespace):
    pods = get_pod_names(kind, name, namespace)
    containers = get_containers(kind, name, namespace)
    secret_hash = hashlib.sha256(NEW_SECRET_VALUE.encode()).hexdigest()
    # Fetch the deployment once
    dep_cmd = f"kubectl get {kind.lower()}/{name} -n {namespace} -o json"
    dep_json = json.loads(run(dep_cmd))
    containers_spec = dep_json['spec']['template']['spec']['containers']

    # Picked the First pod, to check changed secret [Sure can be check for all pod: if cluster is small]
    pod_name = pods[0]
    container_name = containers[0]

    container_spec = next((c for c in containers_spec if c['name'] == container_name), None)
    if container_spec:
        found = False
        # Check env vars
        for env_var in container_spec.get('env', []):
            env_name = env_var['name']
            cmd_env = f"kubectl exec {pod_name} -n {namespace} -c {container_name} -- printenv {env_name}"
            try:
                output = run(cmd_env)
                pod_hash = hashlib.sha256(output.encode()).hexdigest()
                if pod_hash == secret_hash:
                    found = True
                    break  # verified, no need to check other env vars
            except Exception:
                pass

        # Check mounted file only if env check failed
        if not found:
            file_path = FILE_PATH_ON_POD
            cmd_file = f"kubectl exec {pod_name} -n {namespace} -c {container_name} -- cat {file_path}"
            try:
                output = run(cmd_file)
                file_path_default = False
                pod_hash = hashlib.sha256(output.encode()).hexdigest()
                if pod_hash != secret_hash:
                    raise Exception(f"Secret mismatch in pod {pod_name}, container {container_name}")
            except Exception:
                # file might not exist, skip
                pass

# -----------------------------
# Main Execution
# -----------------------------
try:
    workloads = get_workloads(SECRET_NAME, NAMESPACE)
    if not workloads:
        print("No workloads reference this secret.")
    else:
        patch_secret(SECRET_NAME, NAMESPACE, NEW_SECRET_VALUE, SECRET_KEY)
        for kind, name in workloads:
            ensure_max_surge(kind, name, NAMESPACE, surge="40%", unavailable="0%")
            rollout_workload(kind, name, NAMESPACE)

    print("All done! Secret rotated and workloads updated safely.")

except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
