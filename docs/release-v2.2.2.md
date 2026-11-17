# v2.2.2 — agente do virtualizador detectado sozinho

> **Rascunho. Publique a release (tag `v2.2.2`) depois do merge e do teste nas VMs.** Contém tudo da v2.2.1; veja o [CHANGELOG](../CHANGELOG.md).

## Novo

O baseline detecta o virtualizador (`systemd-detect-virt`), sem perguntar, e instala/liga o agente certo **só se faltar**:

| Virtualizador | Pacote |
|---|---|
| `kvm`/`qemu` (Proxmox) | `qemu-guest-agent` (unidade static: só `start`; sobe no boot pelo udev) |
| `vmware` (ESXi) | `open-vm-tools` |
| `microsoft` (Hyper-V) | `linux-cloud-tools-virtual` (`hv-kvp-daemon`, `hv-vss-daemon`) |
| `none` / outro | nada, só informa |

No Proxmox, se a VM não tem o canal virtio, o agente não sobe: o baseline avisa para marcar **Options › QEMU Guest Agent** e **desligar/ligar** a VM. O `baseline-verify` ganhou o item "agente do virtualizador" (OK, ou AVISO com o comando; nunca FALHA).

Sem mudança de chaves do `baseline.env`.

## Checklist do teste nas VMs

1. **dns1 (Proxmox)**, antes de marcar o Qemu Agent na VM: rodar o baseline → deve instalar o `qemu-guest-agent` e AVISAR do canal. Marcar o agente, desligar/ligar a VM, `sudo baseline-verify` → OK; o Summary do Proxmox passa a mostrar o IP.
2. **dns2 (ESXi)**: o baseline instala `open-vm-tools`; `sudo baseline-verify` → OK e o vSphere mostra "VMware Tools: em execução".
3. Rodar o baseline de novo: nada é reinstalado ("já instalado").

## Verificação (SHA-256)

```
c8e98cebb3649e9054d2e17ebe77a37b4131917491b811342371b4fbc8d8fce9  baseline.sh
0521cacc9548798913d8d7871720b86d7c8bffd2c07a22147fbb7764a17ebc4a  baseline-verify.sh
```

```bash
cd /tmp
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.2/baseline.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.2/baseline-verify.sh
curl -fsSLO https://raw.githubusercontent.com/glaucier/server-baseline/v2.2.2/SHA256SUMS
sha256sum -c SHA256SUMS
```

Mudanças em relação à v2.2.1: https://github.com/glaucier/server-baseline/compare/v2.2.1...v2.2.2
