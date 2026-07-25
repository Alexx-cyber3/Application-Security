import shutil
import subprocess
import logging
import os

# Add local bin directory to PATH so bundled syft and cosign binaries can be discovered
_file_path = globals().get("__file__")
if _file_path:
    _current_dir = os.path.dirname(os.path.abspath(_file_path))
    _bin_dir = os.path.join(_current_dir, "bin")
    if os.path.exists(_bin_dir):
        _paths = os.environ.get("PATH", "").split(os.pathsep)
        if _bin_dir not in _paths:
            os.environ["PATH"] = _bin_dir + os.pathsep + os.environ.get("PATH", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

class ToolManager:
    @staticmethod
    def is_tool_available(name: str) -> bool:
        """Check if a tool is in the system PATH."""
        return shutil.which(name) is not None

    @classmethod
    def check_tools(cls) -> dict:
        """Check the status of syft and cosign."""
        syft_avail = cls.is_tool_available("syft")
        cosign_avail = cls.is_tool_available("cosign")
        
        return {
            "syft": {
                "available": syft_avail,
                "path": shutil.which("syft") or "Not found",
                "version": cls.get_tool_version("syft") if syft_avail else None
            },
            "cosign": {
                "available": cosign_avail,
                "path": shutil.which("cosign") or "Not found",
                "version": cls.get_tool_version("cosign") if cosign_avail else None
            }
        }

    @classmethod
    def get_tool_version(cls, name: str) -> str:
        """Retrieve the version of a tool."""
        try:
            cmd = [name, "--version"] if name == "syft" else [name, "version"]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
        except Exception as e:
            logger.error(f"Error fetching version for {name}: {e}")
        return "Unknown"

    @classmethod
    def install_tool(cls, name: str) -> tuple[bool, str]:
        """Attempt to install a tool via winget."""
        if cls.is_tool_available(name):
            return True, f"{name} is already installed."

        winget_id = "anchore.syft" if name == "syft" else "Sigstore.Cosign"
        
        logger.info(f"Attempting to install {name} ({winget_id}) via winget...")
        try:
            # We use --silent and accept agreements to allow automated script installations
            cmd = [
                "winget", "install", 
                winget_id, 
                "--accept-source-agreements", 
                "--accept-package-agreements", 
                "--silent"
            ]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
            
            # Recheck if now available since winget changes might take a moment or require command refresh
            if result.returncode == 0 or cls.is_tool_available(name):
                logger.info(f"Successfully installed {name}.")
                return True, f"Successfully installed {name} via winget."
            else:
                err_msg = result.stderr.strip() or result.stdout.strip()
                logger.warning(f"Failed to install {name} via winget: {err_msg}")
                return False, f"Installation command failed with code {result.returncode}. Output: {err_msg}"
        except subprocess.TimeoutExpired:
            logger.error(f"Installation of {name} timed out.")
            return False, f"Installation of {name} timed out."
        except Exception as e:
            logger.error(f"Exception trying to install {name}: {e}")
            return False, f"Failed to install: {str(e)}"

if __name__ == "__main__":
    print("Checking tools status:")
    status = ToolManager.check_tools()
    print(status)
