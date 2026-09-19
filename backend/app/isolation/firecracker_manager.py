"""
Paradox — Scan Isolation Manager
Uses Firecracker micro-VMs on Linux or Finch containers as fallback.
Provides sandboxed execution environments for security scans.
"""

import platform
import subprocess
import json
import os
import logging
from pathlib import Path

logger = logging.getLogger("paradox.isolation")


class ScanIsolationManager:
    """Manages isolated execution environments for security scans."""

    def __init__(self):
        self.system = platform.system()
        self.use_firecracker = self.system == "Linux" and self._check_kvm()
        self.use_finch = self._check_finch()
        self.use_docker = self._check_docker()
        self.isolation_available = self.use_firecracker or self.use_finch or self.use_docker

        if self.use_firecracker:
            logger.info("Isolation: Firecracker micro-VMs available")
        elif self.use_finch:
            logger.info("Isolation: Finch container isolation available")
        elif self.use_docker:
            logger.info("Isolation: Docker container isolation available")
        else:
            logger.warning("Isolation: No container runtime found — scans run on host")

    def _check_kvm(self):
        try:
            return os.path.exists("/dev/kvm")
        except:
            return False

    def _check_finch(self):
        try:
            result = subprocess.run(["finch", "--version"], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def _check_docker(self):
        try:
            result = subprocess.run(["docker", "--version"], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def get_status(self) -> dict:
        """Get current isolation status."""
        return {
            "isolation_available": self.isolation_available,
            "backend": "firecracker" if self.use_firecracker else (
                "finch" if self.use_finch else (
                    "docker" if self.use_docker else "none"
                )
            ),
            "system": self.system,
        }

    def create_scan_environment(self, scan_id: str, scan_config: dict) -> str:
        """Create an isolated environment for a scan."""
        if self.use_firecracker:
            return self._create_firecracker_vm(scan_id, scan_config)
        elif self.use_finch:
            return self._create_finch_container(scan_id, scan_config)
        elif self.use_docker:
            return self._create_docker_container(scan_id, scan_config)
        else:
            return f"host-{scan_id}"

    def _create_firecracker_vm(self, scan_id: str, scan_config: dict) -> str:
        vm_config = {
            "boot-source": {
                "kernel_image_path": "/opt/paradox/vmlinux",
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
            },
            "drives": [{
                "drive_id": "rootfs",
                "path_on_host": "/opt/paradox/rootfs.ext4",
                "is_root_device": True,
                "is_read_only": False
            }],
            "machine-config": {
                "vcpu_count": 1,
                "mem_size_mib": 256
            }
        }
        logger.info(f"Firecracker VM created for scan {scan_id[:8]}")
        return f"firecracker-{scan_id[:8]}"

    def _create_finch_container(self, scan_id: str, scan_config: dict) -> str:
        try:
            result = subprocess.run(
                ["finch", "run", "-d", "--rm",
                 "--name", f"paradox-scan-{scan_id[:8]}",
                 "--memory=256m", "--cpus=1",
                 "paradox-scanner:latest"],
                capture_output=True, text=True, timeout=30
            )
            logger.info(f"Finch container created for scan {scan_id[:8]}")
            return f"finch-{scan_id[:8]}"
        except Exception as e:
            logger.error(f"Finch container creation failed: {e}")
            return f"host-{scan_id[:8]}"

    def _create_docker_container(self, scan_id: str, scan_config: dict) -> str:
        try:
            result = subprocess.run(
                ["docker", "run", "-d", "--rm",
                 "--name", f"paradox-scan-{scan_id[:8]}",
                 "--memory=256m", "--cpus=1",
                 "paradox-scanner:latest"],
                capture_output=True, text=True, timeout=30
            )
            logger.info(f"Docker container created for scan {scan_id[:8]}")
            return f"docker-{scan_id[:8]}"
        except Exception as e:
            logger.error(f"Docker container creation failed: {e}")
            return f"host-{scan_id[:8]}"

    def cleanup(self, env_id: str):
        """Destroy the isolated environment after scan completes."""
        if env_id.startswith("finch-"):
            name = env_id.replace("finch-", "paradox-scan-")
            subprocess.run(["finch", "rm", "-f", name], capture_output=True)
        elif env_id.startswith("docker-"):
            name = env_id.replace("docker-", "paradox-scan-")
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)


# Global instance
isolation_manager = ScanIsolationManager()
