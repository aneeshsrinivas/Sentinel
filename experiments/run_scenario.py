import argparse
import subprocess
import os
import sys

def main():
    parser = argparse.ArgumentParser(description="SENTINEL Attack Orchestrator")
    parser.add_argument("--scenario", choices=["http_flood", "slowloris", "conn_flood", "lowrate", "burst"], 
                        help="Attack scenario to run")
    parser.add_argument("--all", action="store_true", help="Run all scenarios sequentially")
    args = parser.parse_args()

    scenarios = ["http_flood", "slowloris", "conn_flood", "lowrate", "burst"] if args.all else [args.scenario]
    
    if not scenarios[0]:
        parser.print_help()
        sys.exit(1)

    for sc in scenarios:
        script_path = os.path.join(os.path.dirname(__file__), f"attack_{sc}.py")
        print(f"[*] Starting attack scenario: {sc}")
        try:
            subprocess.run([sys.executable, script_path], check=True)
            print(f"[+] Scenario {sc} completed successfully.\n")
        except FileNotFoundError:
            print(f"[-] Script not found: {script_path}\n")
        except Exception as e:
            print(f"[-] Error running scenario {sc}: {e}\n")

if __name__ == "__main__":
    main()
