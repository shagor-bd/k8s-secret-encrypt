### Encrypting Confidential Data at Rest in Kubernetes

Data encryption at rest ensures sensitive data is protected from unauthorized access if the storage medium is compromised. Kubernetes provides a mechanism to encrypt secrets stored in etcd. Here's a brief explanation and an example:

---

### Without Encryption
By default, secrets in Kubernetes are stored in plain text in the etcd database. If etcd is compromised, the secrets can be directly read.

#### Example:  
1. **Create a Secret**:
   ```bash
   kubectl create secret generic my-secret --from-literal=key1=supersecret
   ```

2. **Retrieve the Secret**:
   ```bash
   ETCDCTL_API=3 etcdctl \
       --endpoints=https://127.0.0.1:2379 \
       --cacert=/etc/kubernetes/pki/etcd/ca.crt \
       --cert=/etc/kubernetes/pki/etcd/server.crt \
       --key=/etc/kubernetes/pki/etcd/server.key \
       get /registry/secrets/default/my-secret | hexdump -C
   ```
   - **Result**: The output will show the secret data in plain text.
   ```
   00000000  2f 72 65 67 69 73 74 72  79 2f 73 65 63 72 65 74  |/registry/secret|
   00000010  73 2f 64 65 66 61 75 6c  74 2f 6d 79 2d 73 65 63  |s/default/my-sec|
   00000020  72 65 74 0a 6b 38 73 00  0a 0c 0a 02 76 31 12 06  |ret.k8s.....v1..|
   00000030  53 65 63 72 65 74 12 d0  01 0a b0 01 0a 09 6d 79  |Secret........my|
   00000040  2d 73 65 63 72 65 74 12  00 1a 07 64 65 66 61 75  |-secret....defau|
   00000050  6c 74 22 00 2a 24 38 30  38 31 34 32 38 64 2d 32  |lt".*$8081428d-2|
   00000060  36 63 63 2d 34 33 37 31  2d 38 39 66 30 2d 31 38  |6cc-4371-89f0-18|
   00000070  62 32 64 64 64 61 31 30  32 39 32 00 38 00 42 08  |b2ddda10292.8.B.|
   00000080  08 85 90 b3 bb 06 10 00  8a 01 61 0a 0e 6b 75 62  |..........a..kub|
   00000090  65 63 74 6c 2d 63 72 65  61 74 65 12 06 55 70 64  |ectl-create..Upd|
   000000a0  61 74 65 1a 02 76 31 22  08 08 85 90 b3 bb 06 10  |ate..v1"........|
   000000b0  00 32 08 46 69 65 6c 64  73 56 31 3a 2d 0a 2b 7b  |.2.FieldsV1:-.+{|
   000000c0  22 66 3a 64 61 74 61 22  3a 7b 22 2e 22 3a 7b 7d  |"f:data":{".":{}|
   000000d0  2c 22 66 3a 6b 65 79 31  22 3a 7b 7d 7d 2c 22 66  |,"f:key1":{}},"f|
   000000e0  3a 74 79 70 65 22 3a 7b  7d 7d 42 00 12 13 0a 04  |:type":{}}B.....|
   000000f0  6b 65 79 31 12 0b 73 75  70 65 72 73 65 63 72 65  |key1..supersecre|   # We can see the secrect data
   00000100  74 1a 06 4f 70 61 71 75  65 1a 00 22 00 0a        |t..Opaque.."..|
   0000010e
   ```


---

### With Encryption
Enabling encryption ensures that the secrets are encrypted before being written to the etcd database.

#### Steps:
1. **Update the Encryption Configuration File**:
   Create or update the encryption configuration file (e.g., `/etc/kubernetes/encryption-config.yaml`):

   Generate a 32-byte random key and base64 encode it. You can use this command:
   ```bash
   head -c 32 /dev/urandom | base64
   ```
   Output:
   ```
   SY8v+Z/xQpXLV2ifLJRBQdyIbjz8tHuis5ivoZG9+uo=
   ```
   ```yaml
   apiVersion: apiserver.config.k8s.io/v1
   kind: EncryptionConfiguration
   resources:
   - resources:
     - secrets
     providers:
     - aescbc:
         keys:
         - name: key1
           secret: <base64-encoded-32-byte-key>   # SY8v+Z/xQpXLV2ifLJRBQdyIbjz8tHuis5ivoZG9+uo=    -- repleace with this
     - identity: {}
   ```

2. **Update the API Server Configuration**:
   Modify the `kube-apiserver` manifest (e.g., `/etc/kubernetes/manifests/kube-apiserver.yaml`) to include the encryption configuration:
   ```yaml
   #
   # This is a fragment of a manifest for a static Pod.
   # Check whether this is correct for your cluster and for your API server.
   #
   apiVersion: v1
   kind: Pod
   metadata:
   annotations:
      kubeadm.kubernetes.io/kube-apiserver.advertise-address.endpoint: 10.20.30.40:443
   creationTimestamp: null
   labels:
      app.kubernetes.io/component: kube-apiserver
      tier: control-plane
   name: kube-apiserver
   namespace: kube-system
   spec:
   containers:
   - command:
      - kube-apiserver
      ...
      - --encryption-provider-config=/etc/kubernetes/enc/enc.yaml  # add this line
      volumeMounts:
      ...
      - name: enc                           # add this line
         mountPath: /etc/kubernetes/enc      # add this line
         readOnly: true                      # add this line
      ...
   volumes:
   ...
   - name: enc                             # add this line
      hostPath:                             # add this line
         path: /etc/kubernetes/enc           # add this line
         type: DirectoryOrCreate             # add this line
   ...
   ```

3. **Restart the API Server**:
   Restart the API server to apply the changes.

4. **Create new secret and Verify encryption**
```bash
kubectl create secret generic my-secret-1 --from-literal=key1=supersecret2
#secret/my-secret-1 created

controlplane /etc/kubernetes/manifests ➜  ETCDCTL_API=3 etcdctl    --cacert=/etc/kubernetes/pki/etcd/ca.crt      --cert=/etc/kubernetes/pki/etcd/server.crt    --key=/etc/kubernetes/pki/etcd/server.key     get /registry/secrets/default/my-secret-1 | hexdump -C
```
Output:
```
00000000  2f 72 65 67 69 73 74 72  79 2f 73 65 63 72 65 74  |/registry/secret|
00000010  73 2f 64 65 66 61 75 6c  74 2f 6d 79 2d 73 65 63  |s/default/my-sec|
00000020  72 65 74 2d 31 0a 6b 38  73 3a 65 6e 63 3a 61 65  |ret-1.k8s:enc:ae|
00000030  73 63 62 63 3a 76 31 3a  6b 65 79 31 3a 47 32 45  |scbc:v1:key1:G2E|
00000040  9b 1e 74 d2 e6 34 e8 67  a0 20 30 0f 57 60 56 e7  |..t..4.g. 0.W`V.|
00000050  7c 02 4e 67 5f 34 07 db  dc 24 d0 b8 49 a7 83 77  ||.Ng_4...$..I..w|
00000060  95 de fc e9 e6 98 98 05  81 c1 58 10 ed 56 01 bb  |..........X..V..|
00000070  32 1d 73 fa f6 f7 9d f0  83 78 21 53 ca 65 d6 10  |2.s......x!S.e..|
00000080  9d a8 4e ea cd 4c 26 7a  8e 71 62 12 de 96 d3 f5  |..N..L&z.qb.....|
00000090  ef 50 4e 12 a0 36 33 30  8a 3a 93 ce 34 b0 39 e9  |.PN..630.:..4.9.|
000000a0  83 15 e0 d5 48 6d 03 10  2b eb 69 61 48 3c 2f 43  |....Hm..+.iaH</C|
000000b0  f5 a0 00 ee 39 54 90 49  f4 49 c1 68 13 29 1e 4f  |....9T.I.I.h.).O|
000000c0  20 62 9a de 9a d0 22 36  11 9b 62 c1 e5 95 31 1d  | b...."6..b...1.|
000000d0  28 5f 13 74 f2 23 94 4c  cd 00 dd 0d 9e 78 12 28  |(_.t.#.L.....x.(|
000000e0  7a 0d eb 5c 2c d2 e4 d7  02 07 1b 9f a0 78 19 8f  |z..\,........x..|
000000f0  92 dd 12 78 dd 35 87 04  80 98 34 41 91 97 e5 08  |...x.5....4A....|
00000100  44 3e ed 93 78 7b 77 39  47 6f a2 60 dd 07 0d f9  |D>..x{w9Go.`....|
00000110  f2 f2 de d0 a5 07 84 e6  52 6b b9 da b8 ec 3b ae  |........Rk....;.|
00000120  5d c9 df a2 19 32 83 48  73 9a d8 2b f5 b3 4e 1e  |]....2.Hs..+..N.|   # Secret now encrypted
00000130  32 b5 d3 9e c3 9b f9 ab  06 f7 7f a6 cf 0a        |2.............|
0000013e
```
- **Result**: The secret data will appear encrypted.


5. **Re-encrypt Existing Secrets**:
   After complete the encryption procedure all the previous secrets are still unencrypted. Now manually trigger the re-encryption of existing secrets across all the namespace:
   ```bash
   kubectl get secrets --all-namespaces -o json | kubectl replace -f -
   ```



### Summary
- **Without Encryption**: Secrets are stored in plain text.
- **With Encryption**: Secrets are encrypted using the specified key, improving security. Always ensure proper key management practices to prevent unauthorized access.
- [Referance](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
