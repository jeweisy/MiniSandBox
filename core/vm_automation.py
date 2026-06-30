import os
import subprocess


class VMAutomation:
    def __init__(self):
        self.vmrun_path = os.environ.get("MINISANDBOX_VMRUN_PATH",
                                         r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")
        self.vmx_path = os.environ.get("MINISANDBOX_VMX_PATH",
                                       r"C:\Users\user\Documents\Virtual Machines\Windows 11 x64 SANDBOX\Windows 11 x64 SANDBOX.vmx")

        self.vm_password = os.environ.get("MINISANDBOX_VM_PASS")
        self.guest_user = os.environ.get("MINISANDBOX_GUEST_USER")
        self.guest_pass = os.environ.get("MINISANDBOX_GUEST_PASS")

        self.snapshot_name = os.environ.get("MINISANDBOX_SNAPSHOT", "Clean_Lab")
        self._validate_security_context()

    def _validate_security_context(self):
        required_vars = {"MINISANDBOX_VM_PASS": self.vm_password, "MINISANDBOX_GUEST_USER": self.guest_user,
                         "MINISANDBOX_GUEST_PASS": self.guest_pass}
        missing = [k for k, v in required_vars.items() if not v]
        if missing:
            raise PermissionError(f"[!] CRITICAL SECURITY VIOLATION: Missing variables: {', '.join(missing)}.")

    def revert_to_clean_snapshot(self):
        command = [self.vmrun_path, "-T", "ws", "-vp", self.vm_password, "revertToSnapshot", self.vmx_path,
                   self.snapshot_name]
        return self._execute_secure_command(command)

    def start_vm(self):
        command = [self.vmrun_path, "-T", "ws", "-vp", self.vm_password, "start", self.vmx_path, "nogui"]
        return self._execute_secure_command(command)

    def copy_file_to_guest(self, host_path, guest_path):
        if not os.path.exists(host_path): return False
        command = [self.vmrun_path, "-T", "ws", "-vp", self.vm_password, "-gu", self.guest_user, "-gp", self.guest_pass,
                   "CopyFileFromHostToGuest", self.vmx_path, host_path, guest_path]
        return self._execute_secure_command(command)

    def pull_file_from_guest(self, guest_path, host_path):
        command = [self.vmrun_path, "-T", "ws", "-vp", self.vm_password, "-gu", self.guest_user, "-gp", self.guest_pass,
                   "CopyFileFromGuestToHost", self.vmx_path, guest_path, host_path]
        return self._execute_secure_command(command)

    def execute_program_in_guest(self, guest_program_path, args=""):
        command = [self.vmrun_path, "-T", "ws", "-vp", self.vm_password, "-gu", self.guest_user, "-gp", self.guest_pass,
                   "runProgramInGuest", self.vmx_path, "-noWait", guest_program_path]
        if args:
            command.append(args)
        return self._execute_secure_command(command)

    def stop_vm(self):
        command = [self.vmrun_path, "-T", "ws", "-vp", self.vm_password, "stop", self.vmx_path, "hard"]
        return self._execute_secure_command(command)

    def _execute_secure_command(self, command):
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode != 0:
                if "CopyFileFromHostToGuest" in command:
                    print(f"\n[DEBUG_ERROR] VMware Tools Output: {result.stderr.strip()}")
                return False
            return True
        except Exception as e:
            print(f"\n[DEBUG_ERROR] Exception: {str(e)}")
            return False