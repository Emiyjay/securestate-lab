import json
from pathlib import Path

from securestate.platform_info import identify_platform


def main():
    print("=" * 50)
    print("          SECURESTATE LAB")
    print("  Operating System Security Assessment")
    print("=" * 50)

    environment = identify_platform()

    print("\nSYSTEM INFORMATION")

    for key, value in environment.items():
        print(f"{key.replace('_', ' ').title()}: {value}")

    reports_directory = Path("reports")
    reports_directory.mkdir(exist_ok=True)

    report_path = reports_directory / "environment.json"

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(environment, file, indent=4)

    print("\nEnvironment information saved successfully.")
    print(f"Report location: {report_path.resolve()}")


if __name__ == "__main__":
    main()